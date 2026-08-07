use std::os::unix::io::RawFd;

pub const SECCOMP_SET_MODE_FILTER: libc::c_int = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;

const BPF_LD_W_ABS: u16 = 0x0020;
const BPF_JMP_JEQ_K: u16 = 0x0015;
const BPF_RET_K: u16 = 0x0006;

const OFF_ARCH: u32 = 4;
const OFF_NR: u32 = 0;

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// build a classic-bpf seccomp filter that traps the given syscall
/// numbers with user_notif and allows everything else.
pub fn build_filter(syscall_nrs: &[i32], audit_arch: u32) -> Vec<libc::sock_filter> {
    let mut prog = Vec::new();

    prog.push(bpf_stmt(BPF_LD_W_ABS, OFF_ARCH));
    prog.push(bpf_jump(BPF_JMP_JEQ_K, audit_arch, 1, 0));
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    prog.push(bpf_stmt(BPF_LD_W_ABS, OFF_NR));
    for nr in syscall_nrs {
        prog.push(bpf_jump(BPF_JMP_JEQ_K, *nr as u32, 0, 1));
        prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF));
    }
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    prog
}

/// install the filter with a new listener. on success returns the
/// listener fd; on failure returns err(errno).
pub fn install(prog: &[libc::sock_filter]) -> Result<RawFd, i32> {
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if r != 0 {
        return Err(errno());
    }

    let mut fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &mut fprog as *mut libc::sock_fprog,
        ) as RawFd
    };

    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotifAddFd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// `libc::ioctl` is `c_int` on musl but `c_ulong` on glibc, so the request
/// constants must use that type rather than a hardcoded width: the `_ioc`
/// encoding is 32 bits, so it truncates safely to either.
const fn iowr(t: u8, nr: u8, size: usize) -> libc::Ioctl {
    ((3u64 << 30) | ((size as u64) << 16) | ((t as u64) << 8) | (nr as u64)) as libc::Ioctl
}

const NOTIF_RECV: libc::Ioctl = iowr(0x21, 0, std::mem::size_of::<SeccompNotif>());
const NOTIF_SEND: libc::Ioctl = iowr(0x21, 1, std::mem::size_of::<SeccompNotifResp>());
const NOTIF_ADDFD: libc::Ioctl = iowr(0x21, 3, std::mem::size_of::<SeccompNotifAddFd>());

pub fn notif_recv(fd: RawFd, n: &mut SeccompNotif) -> Result<(), i32> {
    let r = unsafe {
        libc::ioctl(
            fd,
            NOTIF_RECV,
            n as *mut SeccompNotif as usize as libc::c_ulong,
        )
    };
    if r < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn notif_send(fd: RawFd, r: &SeccompNotifResp) -> Result<(), i32> {
    let res = unsafe {
        libc::ioctl(
            fd,
            NOTIF_SEND,
            r as *const SeccompNotifResp as usize as libc::c_ulong,
        )
    };
    if res < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// install a supervisor fd into the tracee (seccomp_ioctl_notif_addfd).
/// on success returns the new fd number in the tracee.
pub fn notif_addfd(fd: RawFd, n: &SeccompNotifAddFd) -> Result<i32, i32> {
    let res = unsafe {
        libc::ioctl(
            fd,
            NOTIF_ADDFD,
            n as *const SeccompNotifAddFd as usize as libc::c_ulong,
        )
    };
    if res < 0 {
        Err(errno())
    } else {
        Ok(res)
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}
