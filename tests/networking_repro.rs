//! networking confinement regression tests.

use chimera::emulation::networking;
use chimera::emulation::paths;
use chimera::emulation::state::SandboxState;
use chimera::emulation::EmuReply;
use chimera::runtime::mem;
use chimera::runtime::seccomp::{SeccompData, SeccompNotif};
use std::collections::HashMap;
use std::os::unix::io::RawFd;

/// child → parent report: the socket fd plus pointers to a sockaddr buffer and
/// a socklen_t, both living in the child's own memory.
#[repr(C)]
struct Report {
    fd: libc::c_int,
    sa: u64,
    sa_len: libc::socklen_t,
    slen: u64,
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "chimera-net-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    dir
}

fn raw(map: &[(&str, u64)]) -> HashMap<String, u64> {
    map.iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect()
}

fn notif() -> SeccompNotif {
    SeccompNotif {
        id: 0,
        pid: 0,
        flags: 0,
        data: SeccompData {
            nr: 0,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        },
    }
}

/// fork a child that sets up its socket and sockaddr buffer, then writes a
/// [`report`] through the pipe and pauses until the parent reaps it.
fn with_child<F: FnOnce() -> Report>(setup: F) -> (libc::pid_t, Report) {
    let mut pipes = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipes[0]) };
        let report = setup();
        let written = unsafe {
            libc::write(
                pipes[1],
                &report as *const Report as *const libc::c_void,
                std::mem::size_of::<Report>(),
            )
        };
        assert_eq!(written as usize, std::mem::size_of::<Report>());
        unsafe { libc::pause() };
        std::process::exit(0);
    }
    unsafe { libc::close(pipes[1]) };
    let mut report = Report {
        fd: 0,
        sa: 0,
        sa_len: 0,
        slen: 0,
    };
    let got = unsafe {
        libc::read(
            pipes[0],
            &mut report as *mut Report as *mut libc::c_void,
            std::mem::size_of::<Report>(),
        )
    };
    assert_eq!(got as usize, std::mem::size_of::<Report>());
    unsafe { libc::close(pipes[0]) };
    (pid, report)
}

fn reap(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
}

fn is_socket_at(path: &std::path::Path) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe { libc::lstat(c.as_ptr(), &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK }
}

#[test]
fn bind_resolves_inside_the_rootfs() {
    let root = scratch("bind");
    let root_s = root.to_str().unwrap().to_string();
    let (pid, r) = with_child(|| {
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(s >= 0, "socket failed");
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path = b"/tmp/x.sock";
        for (i, b) in path.iter().enumerate() {
            sa.sun_path[i] = *b as libc::c_char;
        }
        let mut slen: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        Report {
            fd: s,
            sa: &sa as *const libc::sockaddr_un as u64,
            sa_len: std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            slen: &mut slen as *mut libc::socklen_t as u64,
        }
    });

    let mut state = SandboxState::new();
    let mut ctx = paths::PathCtx::new(&root_s, &[]);
    let reply = networking::dispatch(
        pid,
        "bind",
        &HashMap::new(),
        &raw(&[("fd", r.fd as u64), ("buffer", r.sa), ("address_length", r.sa_len as u64)]),
        &notif(),
        -1,
        &mut ctx,
        &mut state,
        false,
    );
    assert_eq!(reply, Some(EmuReply::Value(0)), "emulated bind must succeed");

    // the guest path `/tmp/x.sock` must appear inside the rootfs...
    assert!(is_socket_at(&root.join("tmp/x.sock")));
    // ...and must not leak onto the host.
    assert!(!std::path::Path::new("/tmp/x.sock").exists());
    reap(pid);
}

#[test]
fn getname_maps_the_host_path_back_to_guest() {
    let root = scratch("getname");
    let root_s = root.to_str().unwrap().to_string();
    let host_path = root.join("tmp/y.sock");
    let (pid, r) = with_child(|| {
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(s >= 0, "socket failed");
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path = host_path.to_str().unwrap().as_bytes();
        for (i, b) in path.iter().enumerate() {
            sa.sun_path[i] = *b as libc::c_char;
        }
        assert_eq!(
            unsafe {
                libc::bind(
                    s,
                    &sa as *const libc::sockaddr_un as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            },
            0,
            "child bind to host path failed"
        );
        let mut slen: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        Report {
            fd: s,
            sa: &sa as *const libc::sockaddr_un as u64,
            sa_len: std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            slen: &mut slen as *mut libc::socklen_t as u64,
        }
    });

    let mut state = SandboxState::new();
    let mut ctx = paths::PathCtx::new(&root_s, &[]);
    let reply = networking::dispatch(
        pid,
        "getsockname",
        &HashMap::new(),
        &raw(&[("fd", r.fd as u64), ("buffer", r.sa), ("address_length", r.slen)]),
        &notif(),
        -1,
        &mut ctx,
        &mut state,
        false,
    );
    assert_eq!(reply, Some(EmuReply::Value(0)), "emulated getsockname must succeed");

    // the buffer now holds the guest view of the socket path.
    let got = mem::read_bytes(pid, r.sa, r.sa_len as usize).unwrap();
    let got = &got[2..]; // skip the af_unix family
    let end = got.iter().position(|&b| b == 0).unwrap_or(got.len());
    let path = std::str::from_utf8(&got[..end]).unwrap();
    assert_eq!(path, "/tmp/y.sock");
    reap(pid);
}
