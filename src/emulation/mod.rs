//! emulation of policy-modified syscalls.

pub mod capabilities;
pub mod directories;
pub mod fd;
pub mod filesystem;
pub mod identity;
pub mod memory;
pub mod metadata;
pub mod networking;
pub mod paths;
pub mod processes;
pub mod procinfo;
pub mod random;
pub mod signals;
pub mod state;
pub mod statfs;
pub mod statx;
pub mod sysidentity;
pub mod time;
pub mod xattr;

use crate::emulation::state::SandboxState;
use crate::runtime::seccomp::SeccompNotif;
use std::collections::HashMap;
use std::os::unix::io::RawFd;

/// what to reply to the tracee after emulating a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmuReply {
    /// success: return `val` from the syscall.
    Value(i64),
    /// failure: report the given (positive) errno.
    Errno(i32),
    /// the emulation rewrote the tracee's syscall arguments in place; run the
    /// syscall with the original numeric args (e.g. execve after path rewrite).
    Continue,
}

/// the set of syscalls [`dispatch`] emulates. keep in sync with the match arms
/// below: it lets the supervisor fast-path out of trapped syscalls that have
/// no policy body and no emulation without building any argument maps.
pub fn is_emulated(name: &str) -> bool {
    matches!(
        name,
        // path-taking filesystem syscalls always run through the emulator.
        "open" | "openat" | "openat2"
            | "stat" | "newfstatat" | "lstat" | "statx"
            | "access" | "faccessat" | "faccessat2"
            | "readlink" | "readlinkat"
            | "statfs" | "statfs64" | "fstatfs" | "fstatfs64"
            | "chdir" | "fchdir" | "getcwd" | "mkdir" | "mkdirat" | "mknod" | "mknodat"
            | "rmdir" | "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2"
            | "link" | "linkat" | "symlink" | "symlinkat"
            | "getdents" | "getdents64" | "lseek"
            | "close"
            | "chmod" | "fchmod" | "fchmodat" | "fchmodat2" | "chown" | "lchown" | "fchown"
            | "fchownat" | "truncate" | "ftruncate" | "utimensat" | "utime" | "utimes"
            | "futimesat"
            | "execve"
            | "getxattr" | "lgetxattr" | "fgetxattr" | "setxattr" | "lsetxattr" | "fsetxattr"
            | "removexattr" | "lremovexattr" | "fremovexattr" | "listxattr" | "llistxattr"
            | "flistxattr"
            | "uname"
            | "getuid" | "geteuid" | "getgid" | "getegid" | "getresuid" | "getresgid" | "setuid"
            | "seteuid" | "setgid" | "setegid" | "setreuid" | "setregid" | "setresuid"
            | "setresgid" | "setgroups" | "getgroups"
            | "capget" | "capset"
            | "socket" | "socketpair" | "bind" | "listen" | "accept" | "accept4"
            | "connect" | "getsockname" | "getpeername" | "setsockopt" | "getsockopt"
    )
}

/// route a trapped syscall to its emulation.
pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    notif: &SeccompNotif,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    modified: bool,
    listener: RawFd,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    // ensure this pid has a processstate (inherits from parent on first sight).
    let _ = state.proc(pid);

    match name {
        // path-taking filesystem syscalls always run through the emulator:
        // continuing with a guest-absolute path would resolve against the *host*
        // root (the tracee's cwd is pinned at the rootfs, which only helps
        // relative paths). `map_host` is idempotent for already-mapped paths.
        "open" | "openat" | "openat2" => {
            filesystem::open(pid, name, args, raw, notif, listener, ctx, state)
        }
        "stat" | "newfstatat" | "lstat" => filesystem::stat(pid, name, args, raw, ctx, state),
        "statx" => filesystem::statx(pid, args, raw, ctx, state),
        "access" | "faccessat" | "faccessat2" => {
            filesystem::access(pid, name, args, raw, ctx, state)
        }
        "readlink" | "readlinkat" => filesystem::readlink(pid, name, args, raw, ctx, state),
        "statfs" | "statfs64" | "fstatfs" | "fstatfs64" => {
            statfs::dispatch(pid, name, args, raw, ctx, state)
        }
        "chdir" | "fchdir" | "getcwd" | "mkdir" | "mkdirat" | "mknod" | "mknodat"
        | "rmdir" | "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2"
        | "link" | "linkat" | "symlink" | "symlinkat" | "getdents" | "getdents64" | "lseek"
        | "close" => {
            directories::dispatch(pid, name, args, raw, ctx, state)
        }
        "chmod" | "fchmod" | "fchmodat" | "fchmodat2" | "chown" | "lchown" | "fchown"
        | "fchownat" | "truncate" | "ftruncate" | "utimensat" | "utime" | "utimes"
        | "futimesat" => metadata::dispatch(pid, name, args, raw, ctx, state),
        "execve" => processes::execve(pid, args, raw, ctx, state),
        "getxattr" | "lgetxattr" | "fgetxattr" | "setxattr" | "lsetxattr" | "fsetxattr"
        | "removexattr" | "lremovexattr" | "fremovexattr" | "listxattr" | "llistxattr"
        | "flistxattr" => xattr::dispatch(pid, name, args, raw, ctx, state),
        "uname" => sysidentity::uname(notif, raw, pid),
        "getuid" | "geteuid" | "getgid" | "getegid" | "getresuid" | "getresgid" | "setuid"
        | "seteuid" | "setgid" | "setegid" | "setreuid" | "setregid" | "setresuid"
        | "setresgid" | "setgroups" | "getgroups" => {
            identity::dispatch(pid, name, &notif.data.args, state)
        }
        "capget" | "capset" => capabilities::dispatch(pid, name, &raw, state),
        "socket" | "socketpair" | "bind" | "listen" | "accept" | "accept4"
        | "connect" | "getsockname" | "getpeername" | "setsockopt" | "getsockopt" => {
            networking::dispatch(pid, name, args, raw, notif, listener, ctx, state, modified)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// every emulated syscall must have a name -> arg-names entry in
    #[test]
    fn every_emulated_syscall_has_an_arg_table_entry() {
        let table = crate::arch::load_syscall_args().expect("syscalls.chmd");
        for name in [
            "open", "openat", "openat2", "stat", "newfstatat", "lstat", "statx", "access",
            "faccessat", "faccessat2", "readlink", "readlinkat", "statfs", "statfs64", "fstatfs",
            "fstatfs64", "chdir", "fchdir", "getcwd", "mkdir", "mkdirat", "mknod", "mknodat",
            "rmdir", "unlink", "unlinkat", "rename", "renameat", "renameat2", "link", "linkat",
            "symlink", "symlinkat", "getdents", "getdents64", "lseek", "close", "chmod", "fchmod",
            "fchmodat",
            "fchmodat2", "chown", "lchown", "fchown", "fchownat", "truncate", "ftruncate",
            "utimensat", "utime", "utimes", "futimesat", "execve", "getxattr", "lgetxattr",
            "setxattr", "lsetxattr", "removexattr", "lremovexattr", "listxattr", "llistxattr",
            "uname", "getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid", "setuid",
            "seteuid", "setgid", "setegid", "setreuid", "setregid", "setresuid", "setresgid",
            "setgroups", "getgroups",
        ] {
            assert!(is_emulated(name), "{name} must be emulated");
            assert!(
                table.contains_key(name),
                "{name} is emulated but has no arg-table entry"
            );
        }
    }
}
