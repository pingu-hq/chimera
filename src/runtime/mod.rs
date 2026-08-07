pub mod exec;
pub mod mem;
pub mod notify;
pub mod regex;
pub mod seccomp;

use crate::embroider::chmp::Policy;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;

/// environment variables that leak host state into the sandbox and must not
const HOST_ONLY_ENV: &[&str] = &[
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_DEBUG",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "LD_HWCAP_MASK",
    "LD_ASSUME_KERNEL",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "LD_USE_LOAD_BIAS",
    "LD_DYNAMIC_WEAK",
    "PYTHONHOME",
    "PYTHONPATH",
    "PERL5LIB",
    "GEM_HOME",
    "GEM_PATH",
    "RUBYLIB",
    "NODE_PATH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
    "SSH_AUTH_SOCK",
    // the pwd var is a shell hint pointing at the host project dir; the guest cwd is
    // tracked by the sandbox (and the chi execs at `/`), so it only misleads.
    "PWD",
];

/// the environment the chi (and, through it, the guest command) sees.
pub fn sanitize_env() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(k, _)| {
            if k.starts_with("LD_") {
                return false;
            }
            !HOST_ONLY_ENV.contains(&k.as_str())
        })
        .collect()
}

pub fn conjure(policy: &Policy, rootfs: &str, command: &str, cmd_args: &[String]) -> Result<i32, String> {
    let rootfs = std::fs::canonicalize(rootfs)
        .map_err(|e| format!("rootfs '{}': {e}", rootfs))?
        .to_string_lossy()
        .into_owned();

    let arch = crate::arch::load_arch_table()?;
    let syscall_args = crate::arch::load_syscall_args()?;

    // a policy with xattr perms enabled requires a rootfs that round-trips
    // `user.*` xattrs; refuse to boot otherwise. the probe distinguishes a
    // rootfs that refuses user.* xattrs from one that could not even be
    // probed (missing dir, permissions, ...).
    let xattr_perms = if policy.meta.xattr {
        match crate::emulation::xattr::probe_xattr_perms(&rootfs) {
            crate::emulation::xattr::ProbeOutcome::Supported => true,
            crate::emulation::xattr::ProbeOutcome::Unsupported(reason) => {
                return Err(format!(
                    "policy enables xattr perms but rootfs '{rootfs}' does not support user.* xattrs: {reason}"
                ));
            }
            crate::emulation::xattr::ProbeOutcome::Error(reason) => {
                return Err(format!(
                    "cannot probe xattr perms on rootfs '{rootfs}': {reason}"
                ));
            }
        }
    } else {
        false
    };

    // reverse lookup so policy syscall names resolve to numbers in o(1).
    let name_to_nr: HashMap<&str, i32> = arch
        .nr_to_name
        .iter()
        .map(|(nr, name)| (name.as_str(), *nr))
        .collect();

    // only trap what the supervisor must see: override bodies, handle bodies,
    let trap_plan = crate::embroider::plan(&policy, &arch);
    let mut nrs: Vec<i32> = Vec::new();
    let mut need_trap = |s: &str| match name_to_nr.get(s) {
        Some(nr) => nrs.push(*nr),
        None => eprintln!(
            "{} warn: syscall '{s}' not in {} table",
            crate::log::tag("chimera"),
            arch.arch_dir
        ),
    };
    for c in &trap_plan.trap {
        need_trap(c);
    }
    nrs.sort_unstable();
    nrs.dedup();
    let bpf_str = nrs
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut fds = [0 as RawFd; 2];
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET,
            0,
            fds.as_mut_ptr(),
        )
    };
    if r < 0 {
        return Err(format!("socketpair failed: {}", std::io::Error::last_os_error()));
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let chi = locate_chi(exe.as_path())
        .ok_or_else(|| format!("chi binary not found for {}", exe.display()))?;

    unsafe { libc::fflush(std::ptr::null_mut()) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        // child -> chi binary
        unsafe { libc::close(fds[0]) };

        let mut argv = vec![
            chi.to_string_lossy().into_owned(),
            rootfs.to_string(),
            command.to_string(),
        ];
        argv.extend(cmd_args.iter().cloned());

        unsafe {
            std::env::set_var("CHIMERA_CTRL_FD", fds[1].to_string());
            std::env::set_var("CHIMERA_SYSCALLS", &bpf_str);
        }

        let argv_c: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_str()).expect("NUL in argv"))
            .collect();
        let mut ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());

        let envs: Vec<CString> = sanitize_env()
            .iter()
            .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
            .collect();
        let mut envp: Vec<*const libc::c_char> = envs.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());

        let path = CString::new(chi.to_str().unwrap_or("chi")).expect("NUL in path");
        unsafe { libc::execve(path.as_ptr(), ptrs.as_ptr(), envp.as_ptr()) };

        eprintln!(
            "{} failed to exec chi: {}",
            crate::log::tag("chimera"),
            std::io::Error::last_os_error()
        );
        unsafe { libc::_exit(127) };
    }

    // parent
    unsafe { libc::close(fds[1]) };

    match recv_listener_or_error(fds[0]) {
        Ok(listener) => {
            println!("{} supervising pid {pid}", crate::log::tag("chimera"));
            let code = notify::supervise(policy, &rootfs, &arch, &syscall_args, listener, pid, xattr_perms);
            unsafe { libc::close(listener) };
            Ok(code)
        }
        Err(msg) => {
            eprintln!("{} warn: {msg}", crate::log::tag("chimera"));
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            if libc::WIFEXITED(status) {
                Ok(libc::WEXITSTATUS(status))
            } else {
                Ok(1)
            }
        }
    }
}

const CMSG_SPACE: usize = 32;

fn recv_listener_or_error(sock: RawFd) -> Result<RawFd, String> {
    let mut buf = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut control = [0u8; CMSG_SPACE];
    // `msghdr` layout and field widths differ between glibc (size_t fields)
    // and musl (socklen_t + private padding), so zero-init and assign.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;
    msg.msg_flags = 0;

    let r = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if r < 0 {
        return Err(format!("recvmsg failed: {}", std::io::Error::last_os_error()));
    }

    if buf[0] == b'E' {
        return Err("seccomp user notification unavailable; running without sandboxing".to_string());
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err("no control message received".to_string());
    }
    let cmsg = unsafe { &*cmsg };
    if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
        return Err("unexpected control message".to_string());
    }

    let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::c_int;
    Ok(unsafe { *data })
}

/// pitch the path of the `chi` helper binary. `chi` is a separate `no_std`
/// crate (`chi/`); we accept either a copy sitting next to the `chimera`
/// binary, an explicit `chimera_chi`, or the crate's own build output.
fn locate_chi(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("CHIMERA_CHI") {
        candidates.push(std::path::PathBuf::from(p));
    }
    if let Some(dir) = exe.parent() {
        candidates.push(dir.join("chi"));
    }
    candidates.push(manifest.join("chi/target/x86_64-unknown-linux-musl/release/chi"));
    candidates.push(manifest.join("chi/target/release/chi"));
    candidates.into_iter().find(|p| p.exists())
}
