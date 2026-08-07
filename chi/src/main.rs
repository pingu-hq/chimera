//! `chi` - the seccomp-notify trampoline for the chimera sandbox.

#![no_std]
#![no_main]

// link the target's bundled musl libc so the crt startup (`__libc_start_main`)
// and any compiler-emitted c helpers (`strlen`, memcpy, ...) resolve. our code
// still makes no libc calls; only rustix and raw syscalls.
#[link(name = "c")]
extern "C" {}

use core::ffi::c_void;

// ---------------------------------------------------------------------------
// raw syscall numbers (x86_64 linux)
// ---------------------------------------------------------------------------
const SYS_PRCTL: usize = 157;
const SYS_SECCOMP: usize = 317;
const SYS_FCNTL: usize = 72;
const SYS_SENDMSG: usize = 46;
const SYS_EXECVE: usize = 59;
const SYS_EXIT_GROUP: usize = 231;

const PR_SET_NO_NEW_PRIVS: usize = 38;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const FD_CLOEXEC: usize = 1;

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

const SECCOMP_SET_MODE_FILTER: usize = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: usize = 1 << 3;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

const BPF_LD_W_ABS: u16 = 0x0020;
const BPF_JMP_JEQ_K: u16 = 0x0015;
const BPF_RET_K: u16 = 0x0006;

const OFF_ARCH: u32 = 4;
const OFF_NR: u32 = 0;

/// audit_arch_x86_64
const AUDIT_ARCH: u32 = 0xc000_003e;

// ---------------------------------------------------------------------------
macro_rules! sc {
    ($nr:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr, $r5:expr) => {{
        let __r: isize;
        core::arch::asm!(
            "syscall",
            inlateout("rax") ($nr as isize) => __r,
            in("rdi") $r0,
            in("rsi") $r1,
            in("rdx") $r2,
            in("r10") $r3,
            in("r8") $r4,
            in("r9") $r5,
            options(nostack)
        );
        __r
    }};
}

#[inline(never)]
unsafe fn sc1(nr: usize, a0: usize) -> isize {
    sc!(nr, a0, 0usize, 0usize, 0usize, 0usize, 0usize)
}
#[inline(never)]
unsafe fn sc2(nr: usize, a0: usize, a1: usize) -> isize {
    sc!(nr, a0, a1, 0usize, 0usize, 0usize, 0usize)
}
#[inline(never)]
unsafe fn sc3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    sc!(nr, a0, a1, a2, 0usize, 0usize, 0usize)
}
#[inline(never)]
unsafe fn sc4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    sc!(nr, a0, a1, a2, a3, 0usize, 0usize)
}

// ---------------------------------------------------------------------------
// logging via rustix is defined further down (just before `run_chi`).

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    logit("\nchi: panic\n");
    unsafe { sc1(SYS_EXIT_GROUP, 101) };
    unreachable!()
}

// ---------------------------------------------------------------------------
// seccomp classic-bpf.
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// build the filter into `prog`; returns the number of instructions used.
fn build_filter(nrs: &[usize], audit_arch: u32, prog: &mut [SockFilter]) -> usize {
    let mut n = 0;
    prog[n] = bpf_stmt(BPF_LD_W_ABS, OFF_ARCH);
    n += 1;
    prog[n] = bpf_jump(BPF_JMP_JEQ_K, audit_arch, 1, 0);
    n += 1;
    prog[n] = bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS);
    n += 1;
    prog[n] = bpf_stmt(BPF_LD_W_ABS, OFF_NR);
    n += 1;
    for nr in nrs {
        prog[n] = bpf_jump(BPF_JMP_JEQ_K, *nr as u32, 0, 1);
        n += 1;
        prog[n] = bpf_stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF);
        n += 1;
    }
    prog[n] = bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW);
    n += 1;
    n
}

#[repr(C)]
struct SockFprog {
    len: u16,
    _pad: u16,
    filter: *mut SockFilter,
}

/// install the filter with a new listener; returns the listener fd (>= 0) or
/// a negative errno.
#[inline(never)]
unsafe fn install(prog: &[SockFilter]) -> isize {
    let r = sc4(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0);
    if r != 0 {
        logit("chi: prctl PR_SET_NO_NEW_PRIVS failed\n");
        return r;
    }
    let mut fprog = SockFprog {
        len: prog.len() as u16,
        _pad: 0,
        filter: prog.as_ptr() as *mut SockFilter,
    };
    sc3(
        SYS_SECCOMP,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        (&mut fprog as *mut SockFprog) as usize,
    )
}

// ---------------------------------------------------------------------------
// scm_rights sendmsg of the listener fd over the ctrl socket.
// ---------------------------------------------------------------------------
#[repr(C)]
struct Iov {
    base: *mut c_void,
    len: usize,
}

#[repr(C)]
struct MsgHdr {
    name: *mut c_void,
    namelen: u32,
    pad: u32,
    iov: *mut Iov,
    iovlen: usize,
    control: *mut c_void,
    controllen: usize,
    flags: i32,
}

fn send_fd_msg(sock: usize, fd: Option<usize>) -> isize {
    let byte: u8 = if fd.is_some() { b'F' } else { b'E' };
    let mut buf = [byte];
    let mut iov = Iov {
        base: buf.as_mut_ptr() as *mut c_void,
        len: 1,
    };
    let mut msg = MsgHdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        pad: 0,
        iov: &mut iov,
        iovlen: 1,
        control: core::ptr::null_mut(),
        controllen: 0,
        flags: 0,
    };

    if let Some(fd) = fd {
        let mut control = [0u8; 32];
        let controlp = control.as_mut_ptr();
        unsafe {
            core::ptr::write_volatile(controlp as *mut usize, 20usize); // cmsg_len
            core::ptr::write_volatile(controlp.add(8) as *mut i32, SOL_SOCKET as i32);
            core::ptr::write_volatile(controlp.add(12) as *mut i32, SCM_RIGHTS as i32);
            core::ptr::write_volatile(controlp.add(16) as *mut usize, fd);
        }
        msg.control = controlp as *mut c_void;
        msg.controllen = 28; // cmsg_space(sizeof(int)) on x86_64
    }
    let r = unsafe { sc3(SYS_SENDMSG, sock, (&msg as *const MsgHdr) as usize, 0) };
    r
}

// ---------------------------------------------------------------------------
// argv / env helpers.
// ---------------------------------------------------------------------------
fn c_bytes(p: *const u8) -> usize {
    let mut i = 0;
    while unsafe { *p.add(i) } != 0 {
        i += 1;
    }
    i
}

fn key_len(s: *const u8) -> usize {
    c_bytes_before(s, b'=')
}

fn c_bytes_before(p: *const u8, stop: u8) -> usize {
    let mut i = 0;
    loop {
        let c = unsafe { *p.add(i) };
        if c == 0 || c == stop {
            return i;
        }
        i += 1;
    }
}

fn eq_bytes(p: *const u8, n: usize, want: &[u8]) -> bool {
    if n != want.len() {
        return false;
    }
    for (i, c) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != *c {
            return false;
        }
    }
    true
}

fn has_pref(p: *const u8, n: usize, pre: &[u8]) -> bool {
    if n < pre.len() {
        return false;
    }
    for (i, c) in pre.iter().enumerate() {
        if unsafe { *p.add(i) } != *c {
            return false;
        }
    }
    true
}

fn skip_env(p: *const u8, klen: usize) -> bool {
    has_pref(p, klen, b"CHIMERA_")
        || has_pref(p, klen, b"LD_")
        || eq_bytes(p, klen, b"PATH")
        || eq_bytes(p, klen, b"HOME")
}

fn getenvp(envp: *const *const u8, key: &[u8]) -> Option<*const u8> {
    let mut ep = envp;
    loop {
        let p = unsafe { *ep };
        if p.is_null() {
            return None;
        }
        let klen = key_len(p);
        if eq_bytes(p, klen, key) {
            return Some(unsafe { p.add(klen + 1) });
        }
        ep = unsafe { ep.add(1) };
    }
}

fn parse_u64(p: *const u8) -> Option<usize> {
    let mut val: usize = 0;
    let mut i = 0;
    loop {
        let c = unsafe { *p.add(i) };
        if c == 0 {
            break;
        }
        if !(c >= b'0' && c <= b'9') {
            return None;
        }
        val = val * 10 + (c - b'0') as usize;
        i += 1;
    }
    Some(val)
}

fn parse_nrs(v: *const u8, out: &mut [usize]) -> usize {
    let mut count = 0usize;
    let mut cur: usize = 0;
    let mut have = false;
    let mut i = 0;
    loop {
        let c = unsafe { *v.add(i) };
        if c == 0 {
            break;
        }
        if c == b',' {
            if have && count < out.len() {
                out[count] = cur;
                count += 1;
            }
            cur = 0;
            have = false;
        } else if c >= b'0' && c <= b'9' {
            cur = cur * 10 + (c - b'0') as usize;
            have = true;
        }
        i += 1;
    }
    if have && count < out.len() {
        out[count] = cur;
        count += 1;
    }
    count
}

/// build the rootfs-anchored exec path into `buf`; returns byte length
/// (excluding nul) or 0 if it would not fit. caller nul-terminates.
fn build_exec_path(rootfs: *const u8, command: *const u8, buf: &mut [u8]) -> usize {
    let rlen = c_bytes(rootfs);
    let clen = c_bytes(command);
    let abs = unsafe { *command } == b'/';

    let mut rtrim = rlen;
    while rtrim > 1 && unsafe { *rootfs.add(rtrim - 1) } == b'/' {
        rtrim -= 1;
    }

    let mut n = 0;
    let mut i = 0;
    while i < rtrim {
        if n >= buf.len() {
            return 0;
        }
        buf[n] = unsafe { *rootfs.add(i) };
        n += 1;
        i += 1;
    }
    if !abs {
        if n >= buf.len() {
            return 0;
        }
        buf[n] = b'/';
        n += 1;
    }
    i = 0;
    while i < clen {
        if n >= buf.len() {
            return 0;
        }
        buf[n] = unsafe { *command.add(i) };
        n += 1;
        i += 1;
    }
    n
}

fn set_cloexec(fd: usize) {
    unsafe {
        let flags = sc2(SYS_FCNTL, fd, F_GETFD);
        if flags >= 0 {
            sc3(SYS_FCNTL, fd, F_SETFD, (flags as usize) | FD_CLOEXEC);
        }
    }
}

// ---------------------------------------------------------------------------
// rustix-backed generic syscalls (chdir / write / close).
// ---------------------------------------------------------------------------
use rustix::fd::RawFd;

fn run_chi(argc: isize, argv: *const *const u8, envp: *const *const u8) -> i32 {
    if argc < 3 {
        logit("chi: usage: chi <rootfs> <command> [args...]\n");
        return 2;
    }
    let argp = argv as *const *const u8;
    let rootfs = unsafe { *argp.add(1) };
    let command = unsafe { *argp.add(2) };

    let ctrl_fd = match getenvp(envp, b"CHIMERA_CTRL_FD") {
        Some(v) => match parse_u64(v) {
            Some(fd) => fd,
            None => return err2("chi: invalid CHIMERA_CTRL_FD\n"),
        },
        None => return err2("chi: CHIMERA_CTRL_FD not set\n"),
    };

    let mut nrs: [usize; 256] = [0; 256];
    let mut nrs_len = 0;
    if let Some(v) = getenvp(envp, b"CHIMERA_SYSCALLS") {
        nrs_len = parse_nrs(v, &mut nrs);
    }

    // chdir into the rootfs before installing seccomp.
    let root_cstr = unsafe { core::ffi::CStr::from_ptr(rootfs as *const core::ffi::c_char) };
    match rustix::process::chdir(root_cstr) {
        Ok(()) => {}
        Err(_) => return err2("chi: chdir failed\n"),
    }

    let mut prog: [SockFilter; 512] = [SockFilter { code: 0, jt: 0, jf: 0, k: 0 }; 512];
    let nprog = build_filter(&nrs[..nrs_len], AUDIT_ARCH, &mut prog);
    let fd = unsafe { install(&prog[..nprog]) };

    if fd >= 0 {
        let lfd = fd as usize;
        if send_fd_msg(ctrl_fd, Some(lfd)) < 0 {
            logit("chi: failed to send listener fd\n");
        }
        set_cloexec(lfd);
        unsafe { rustix::io::close(lfd as RawFd) };
    } else {
        let _ = send_fd_msg(ctrl_fd, None);
    }

    set_cloexec(ctrl_fd);
    unsafe { rustix::io::close(ctrl_fd as RawFd) };

    // exec_path and filtered envp, both in no-heap stack arrays.
    let mut path = [0u8; 4096];
    let len = build_exec_path(rootfs, command, &mut path);
    if len == 0 {
        return err2("chi: exec path too long\n");
    }
    path[len] = 0;

    let mut new_envp: [*const u8; 128] = [core::ptr::null(); 128];
    let mut n = 0usize;
    let mut ep = envp;
    loop {
        let p = unsafe { *ep };
        if p.is_null() {
            break;
        }
        let klen = key_len(p);
        if !skip_env(p, klen) {
            if n + 2 < new_envp.len() {
                new_envp[n] = p;
                n += 1;
            }
        }
        ep = unsafe { ep.add(1) };
    }
    const PATH_K: &[u8] = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
    const HOME_K: &[u8] = b"HOME=/root\0";
    new_envp[n] = PATH_K.as_ptr();
    n += 1;
    new_envp[n] = HOME_K.as_ptr();
    n += 1;
    new_envp[n] = core::ptr::null();

    let guest_argv = unsafe { argp.add(2) as *const *const u8 };

    unsafe {
        sc3(
            SYS_EXECVE,
            path.as_ptr() as usize,
            guest_argv as usize,
            new_envp.as_ptr() as usize,
        );
    }
    logit("chi: exec failed\n");
    127
}

fn err2(s: &str) -> i32 {
    logit(s);
    2
}

fn logit(s: &str) {
    let _ = unsafe { rustix::io::write(rustix::fd::BorrowedFd::borrow_raw(2), s.as_bytes()) };
}

// ---------------------------------------------------------------------------
// entry point: crt calls `main(argc, argv, envp)`.
// ---------------------------------------------------------------------------
#[export_name = "main"]
unsafe extern "C" fn main(argc: isize, argv: *const *const u8, envp: *const *const u8) -> i32 {
    run_chi(argc, argv, envp)
}