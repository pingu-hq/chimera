
use crate::emulation::paths;
use crate::emulation::state::SandboxState;
use crate::emulation::{metadata, statx, xattr, EmuReply};
use crate::runtime::mem;
use crate::runtime::seccomp::{self, SeccompNotif, SeccompNotifAddFd};
use std::collections::HashMap;
use std::os::unix::io::RawFd;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}

/// the kernel's `struct open_how` (openat2's argument): flags, mode, resolve.
#[repr(C)]
#[derive(Clone, Copy)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn overlay_stat(path: &str, st: &mut libc::stat, xattr_perms: bool) {
    if !xattr_perms {
        return;
    }
    if let Some(meta) = xattr::read_meta(path) {
        xattr::apply_meta_to_stat(st, &meta);
    } else {
        // no meta yet (pre-setup leftover, or a host-created file): don't leak
        // the host uid/gid into the sandbox - present as root-owned with the
        // real permission bits.
        st.st_uid = 0;
        st.st_gid = 0;
    }
}

fn overlay_statx(path: &str, st: &mut statx::Statx, xattr_perms: bool) {
    if !xattr_perms {
        return;
    }
    if let Some(meta) = xattr::read_meta(path) {
        xattr::apply_meta_to_statx(st, &meta);
    } else {
        st.stx_uid = 0;
        st.stx_gid = 0;
    }
}

fn parse_u64(v: Option<&String>) -> Option<u64> {
    v.and_then(|s| s.parse::<u64>().ok())
}

/// map openat2's `struct open_how.resolve` flags onto the *mapped* host path.
fn translate_resolve(resolve: u64) -> u64 {
    const RESOLVE_NO_MAGICLINKS: u64 = 0x0002;
    const RESOLVE_NO_SYMLINKS: u64 = 0x0004;
    resolve & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)
}

/// resolve an open/stat/access path, honoring dirfd for `*at` variants.
///
/// always prefers the raw guest path from the tracee (policy `map_path` of a
/// relative `*at` name against cwd is wrong when dirfd ≠ at_fdcwd).
fn resolve_fs(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    cwd: &str,
) -> Option<String> {
    let dirfd = match name {
        "openat" | "openat2" | "newfstatat" | "statx" | "faccessat" | "faccessat2"
        | "readlinkat" => paths::dirfd_of(raw, "dirfd"),
        _ => libc::AT_FDCWD,
    };
    let path = paths::guest_path_arg(pid, args, raw, "path")?;
    ctx.resolve_at(pid, dirfd, &path, cwd)
}

/// open/openat: run as the supervisor and inject the fd via addfd.
pub fn open(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    notif: &SeccompNotif,
    listener: RawFd,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    // openat2 passes `struct open_how { u64 flags; u64 mode; u64 resolve; }`
    // at `how` (len `length`). decode it and reuse the openat path.
    let (host, flags, mode, resolve) = if name == "openat2" {
        let how_ptr = raw.get("how").copied()?;
        let length = raw.get("length").copied().unwrap_or(0) as usize;
        let size = length.min(24);
        if size < 24 {
            return Some(EmuReply::Errno(libc::EINVAL));
        }
        let bytes = mem::read_bytes(pid, how_ptr, size)?;
        let flags = u64::from_ne_bytes(bytes[0..8].try_into().ok()?) as libc::c_int;
        let mode = u64::from_ne_bytes(bytes[8..16].try_into().ok()?) as libc::mode_t;
        let resolve = u64::from_ne_bytes(bytes[16..24].try_into().unwrap_or([0; 8]));
        if state.debug {
            eprintln!(
                "{} openat2: flags={flags:#x} mode={mode:#o} resolve={resolve:#x}",
                crate::log::tag("debug-fs")
            );
        }
        (
            resolve_fs(pid, "openat2", args, raw, ctx, &cwd)?,
            flags,
            mode,
            translate_resolve(resolve),
        )
    } else {
        let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int;
        let mode = parse_u64(args.get("mode")).unwrap_or(0) as libc::mode_t;
        (
            resolve_fs(pid, name, args, raw, ctx, &cwd)?,
            flags,
            mode,
            0,
        )
    };
    let path = paths::cstr(&host)?;
    if state.debug {
        eprintln!(
            "{} open({name}): host={host:?} flags={flags:#x} mode={mode:#o}",
            crate::log::tag("debug-fs")
        );
    }

    let create = flags & libc::O_CREAT != 0;
    let existed = if create {
        std::fs::symlink_metadata(&host).is_ok()
    } else {
        false
    };

    // virtual access check before opening an existing path.
    if state.xattr_perms && (!create || existed) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(libc::AT_FDCWD, path.as_ptr(), &mut st, 0) } < 0 {
            return Some(EmuReply::Errno(errno()));
        }
        overlay_stat(&host, &mut st, true);
        let mut need = 0;
        let accmode = flags & libc::O_ACCMODE;
        if accmode == libc::O_RDONLY || accmode == libc::O_RDWR {
            need |= libc::R_OK;
        }
        if accmode == libc::O_WRONLY || accmode == libc::O_RDWR || flags & libc::O_TRUNC != 0 {
            need |= libc::W_OK;
        }
        if need != 0
            && !xattr::virt_access(
                st.st_mode as u32,
                st.st_uid,
                st.st_gid,
                state.proc(pid),
                need,
                (st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
            )
        {
            return Some(EmuReply::Errno(libc::EACCES));
        }
    }

    let fd = if name == "openat2" {
        // preserve the resolve_* semantics: flattening to open(2) would drop
        // symlink-escape / xdev protection the guest asked for. rebuild the
        // struct and issue the real syscall against the mapped host path.
        let how = OpenHow {
            flags: flags as u64,
            mode: mode as u64,
            resolve,
        };
        let size = std::mem::size_of::<OpenHow>();
        let r = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how as *const OpenHow as *const libc::c_void,
                size,
            )
        };
        if r < 0 {
            return Some(EmuReply::Errno(errno()));
        }
        r as libc::c_int
    } else {
        unsafe { libc::open(path.as_ptr(), flags, mode) }
    };
    if fd < 0 {
        return Some(EmuReply::Errno(errno()));
    }

    // stamp only files this call created; pre-existing ones keep their meta.
    if create && state.xattr_perms && !existed {
        let umask = metadata::tracee_umask(pid);
        let ident = state.proc(pid).ident;
        xattr::stamp(&host, &ident, mode as u32 & !umask);
    }

    let addfd = SeccompNotifAddFd {
        id: notif.id,
        flags: 0,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    let result = match seccomp::notif_addfd(listener, &addfd) {
        Ok(newfd) => EmuReply::Value(newfd as i64),
        Err(e) => EmuReply::Errno(e),
    };
    unsafe { libc::close(fd) };
    Some(result)
}

/// stat/newfstatat/lstat: run as the supervisor and copy struct stat out.
pub fn stat(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_fs(pid, name, args, raw, ctx, &cwd)?;
    let path = paths::cstr(&host)?;
    let buf = *raw.get("stat")?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = match name {
        "lstat" => libc::AT_SYMLINK_NOFOLLOW,
        "newfstatat" => parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int,
        _ => 0,
    };
    if unsafe { libc::fstatat(libc::AT_FDCWD, path.as_ptr(), &mut st, flags) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    overlay_stat(&host, &mut st, state.xattr_perms);

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&st as *const libc::stat) as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };
    if mem::write_bytes(pid, buf, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}

/// statx: run as the supervisor and copy struct statx into the tracee.
pub fn statx(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_fs(pid, "statx", args, raw, ctx, &cwd)?;
    let path = paths::cstr(&host)?;
    let buf = *raw.get("stat")?;
    let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int;
    let mask = parse_u64(args.get("mask")).unwrap_or(0) as libc::c_uint;

    let mut st: statx::Statx = unsafe { std::mem::zeroed() };
    if unsafe { statx::statx(libc::AT_FDCWD, path.as_ptr(), flags, mask, &mut st) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    overlay_statx(&host, &mut st, state.xattr_perms);

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&st as *const statx::Statx) as *const u8,
            std::mem::size_of::<statx::Statx>(),
        )
    };
    if mem::write_bytes(pid, buf, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}

/// access/faccessat/faccessat2.
pub fn access(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_fs(pid, name, args, raw, ctx, &cwd)?;
    let path = paths::cstr(&host)?;
    let mode = parse_u64(args.get("mode")).unwrap_or(0) as libc::c_int;

    if state.xattr_perms && mode != libc::F_OK {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int
            & libc::AT_SYMLINK_NOFOLLOW;
        if unsafe { libc::fstatat(libc::AT_FDCWD, path.as_ptr(), &mut st, flags) } < 0 {
            return Some(EmuReply::Errno(errno()));
        }
        overlay_stat(&host, &mut st, true);
        let ok = xattr::virt_access(
            st.st_mode as u32,
            st.st_uid,
            st.st_gid,
            state.proc(pid),
            mode,
            (st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
        );
        return Some(if ok {
            EmuReply::Value(0)
        } else {
            EmuReply::Errno(libc::EACCES)
        });
    }

    let r = match name {
        "access" => unsafe { libc::access(path.as_ptr(), mode) },
        "faccessat" | "faccessat2" => {
            let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int;
            unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), mode, flags) }
        }
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

/// readlink/readlinkat.
pub fn readlink(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let guest = paths::guest_path_arg(pid, args, raw, "path")?;
    let host = resolve_fs(pid, name, args, raw, ctx, &cwd)?;
    let path = paths::cstr(&host)?;
    let buf = *raw.get("buffer")?;
    let bufsiz = raw.get("bufsiz").copied().unwrap_or(0) as usize;

    let mut data = vec![0u8; bufsiz];
    let n = unsafe {
        libc::readlink(
            path.as_ptr(),
            data.as_mut_ptr() as *mut libc::c_char,
            bufsiz,
        )
    };
    if n < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    let n = n as usize;
    let target = String::from_utf8_lossy(&data[..n]).into_owned();
    let clean = clean_readlink_target(pid, &guest, &target, ctx, state);
    let bytes = clean.as_bytes();
    if mem::write_bytes(pid, buf, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(bytes.len() as i64))
}

/// rewrite a `readlink` result so it points into the guest namespace.
fn clean_readlink_target(
    pid: libc::pid_t,
    guest: &str,
    target: &str,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> String {
    let exe = state.proc(pid).exe.clone();
    let cwd = state.proc(pid).cwd.clone();

    // `/proc/self` was resolved to `/proc/<pid>` for the actual read; classify
    // the well-known symlinks and answer from sandbox state.
    let guest = paths::translate_proc(pid, guest);
    if let Some(rest) = guest.strip_prefix("/proc/") {
        let pid_part = rest.split('/').next().unwrap_or("");
        if pid_part.parse::<u32>().is_ok() {
            if rest.ends_with("/exe") {
                if !exe.is_empty() {
                    return exe;
                }
            } else if rest.ends_with("/cwd") {
                return cwd;
            } else if rest.ends_with("/root") {
                return "/".to_string();
            }
        }
    }

    // everything else maps back through the rootfs/bind table; an unmapped
    // host target (e.g. a device node) is reported as-is.
    ctx.host_to_guest(target).unwrap_or_else(|| target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_flags_keep_symlink_checks_strip_confinement() {
        // kept: no_symlinks | no_magiclinks
        assert_eq!(translate_resolve(0x0004), 0x0004);
        assert_eq!(translate_resolve(0x0002), 0x0002);
        assert_eq!(translate_resolve(0x0006), 0x0006);
        // confinement flags are stripped (mapping layer provides them)
        assert_eq!(translate_resolve(0x0010), 0); // the in_root flag
        assert_eq!(translate_resolve(0x0008), 0); // the beneath flag
        assert_eq!(translate_resolve(0x0040), 0); // the no_xdev flag
        // everything together keeps only no_symlinks | no_magiclinks
        assert_eq!(translate_resolve(0x0010 | 0x0008 | 0x0040 | 0x0004 | 0x0002), 0x0006);
        assert_eq!(translate_resolve(0), 0);
    }
}
