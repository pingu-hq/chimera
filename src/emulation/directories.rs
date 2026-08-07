
use crate::emulation::paths::{self, resolve_guest};
use crate::emulation::state::SandboxState;
use crate::emulation::{metadata, xattr, EmuReply};
use crate::runtime::mem;
use std::collections::HashMap;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}

fn parse_u64(v: Option<&String>) -> Option<u64> {
    v.and_then(|s| s.parse::<u64>().ok())
}

pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    match name {
        "chdir" => chdir(pid, args, ctx, state),
        "fchdir" => fchdir(pid, raw, ctx, state),
        "getcwd" => getcwd(pid, raw, state),
        "mkdir" | "mkdirat" => mkdir(pid, name, args, raw, ctx, state),
        "mknod" | "mknodat" => mknod(pid, name, args, raw, ctx, state),
        "rmdir" => rmdir(pid, args, ctx, state),
        "unlink" | "unlinkat" => unlink(pid, name, args, raw, ctx, state),
        "rename" | "renameat" | "renameat2" => {
            rename(pid, name, args, raw, ctx, state)
        }
        "link" | "linkat" => link(pid, name, args, raw, ctx, state),
        "symlink" | "symlinkat" => symlink(pid, name, args, raw, ctx, state),
        "getdents" | "getdents64" => getdents(pid, name, raw, ctx, state),
        "lseek" => lseek(pid, raw, state),
        "close" => {
            // forget any tracked directory stream so a reused fd number starts
            // a fresh stream.
            if let Some(&fd) = raw.get("fd") {
                state.clear_dir_stream(pid, fd as i32);
            }
            Some(EmuReply::Continue)
        }
        _ => None,
    }
}

/// lseek: update the tracked position of a directory stream the getdents
/// emulation serves. for any other fd the real kernel lseek is correct (the
/// guest's fd offset and file description are untouched by the emulation), so
/// pass it through untouched.
fn lseek(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let fd = raw.get("fd").copied()? as i32;
    let Some((dev, ino, cur)) = state.dir_stream(pid, fd) else {
        return Some(EmuReply::Continue);
    };
    let offset = raw.get("offset").copied()? as i64;
    let whence = raw.get("whence").copied()? as i32;
    let new = match whence {
        libc::SEEK_SET => offset,
        libc::SEEK_CUR => cur + offset,
        // directory streams have no byte length; seek_end is meaningless here
        // (linux returns einval for directories).
        _ => return Some(EmuReply::Errno(libc::EINVAL)),
    };
    if new < 0 {
        return Some(EmuReply::Errno(libc::EINVAL));
    }
    state.set_dir_stream(pid, fd, dev, ino, new);
    Some(EmuReply::Value(new))
}

/// getdents/getdents64: read directory entries from a tracee fd.
fn getdents(
    pid: libc::pid_t,
    name: &str,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let fd = raw.get("fd").copied()? as i32;
    let buf = raw.get("dirp").copied()?;
    let count = raw.get("count").copied().unwrap_or(0) as usize;
    if count == 0 {
        return Some(EmuReply::Value(0));
    }

    let link = format!("/proc/{pid}/fd/{fd}");
    let c = paths::cstr(&link)?;
    let dup_fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if dup_fd < 0 {
        return Some(EmuReply::Errno(errno()));
    }

    let mut dents = vec![0u8; count];

    // identity of the underlying file so a reused fd number pointing at a
    // different directory resets the tracked stream position.
    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let (dev, ino) = if unsafe { libc::fstat(dup_fd, &mut fst) } == 0 {
        (fst.st_dev as u64, fst.st_ino as u64)
    } else {
        (0, 0)
    };
    let off = match state.dir_stream(pid, fd) {
        Some((d, i, o)) if d == dev && i == ino => o,
        _ => 0,
    };
    let _ = unsafe { libc::lseek(dup_fd, off, libc::SEEK_SET) };

    let nr = if name == "getdents64" {
        libc::SYS_getdents64
    } else {
        libc::SYS_getdents
    };
    let n = unsafe {
        libc::syscall(
            nr,
            dup_fd,
            dents.as_mut_ptr() as *mut libc::c_void,
            count,
        )
    };
    let e = errno();
    unsafe { libc::close(dup_fd) };
    if n < 0 {
        return Some(EmuReply::Errno(e));
    }
    let n = n as usize;
    // the real stream consumed `n` bytes (the guest's fd offset never moves
    // because the syscall was intercepted), so advance the tracked position
    // even when scratch_filter later trims the returned buffer.
    state.set_dir_stream(pid, fd, dev, ino, off + n as i64);

    // hide chimera's own scratch artifacts from listings. the exec shim writes
    // `t-*`/`s-*` binaries into scratch dirs (`chi`, `t`, and `chimera*`
    // subdirs under /tmp and /var/tmp); a guest `ls /` should not see them.
    let dir_host = std::fs::read_link(&link)
        .ok()
        .map(|p| p.display().to_string());
    let n = scratch_filter(name == "getdents64", n, &mut dents, dir_host.as_deref(), ctx.rootfs());
    if mem::write_bytes(pid, buf, &dents[..n]).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(n as i64))
}

/// filter chimera scratch entries out of a raw getdents buffer, returning the
/// new length. `dir_host` is the host path of the directory being listed
/// (`none` if it could not be resolved - then only the globally-unique scratch
/// names are filtered).
fn scratch_filter(
    is64: bool,
    n: usize,
    buf: &mut [u8],
    dir_host: Option<&str>,
    rootfs: &str,
) -> usize {
    let root = rootfs.trim_end_matches('/');
    // true when the listed directory is one of chimera's scratch containers:
    // `chi`, `t`, or any `chimera`/`chimera-*` subdir.
    let in_scratch = match dir_host {
        Some(h) => {
            h == format!("{root}/chi")
                || h == format!("{root}/t")
                || h.split('/').any(|c| c == "chimera" || c.starts_with("chimera-"))
        }
        None => false,
    };
    let at_root = dir_host == Some(root);

    // d_reclen sits at byte 16; d_name at 19 (getdents64) or 18 (getdents).
    let name_off = if is64 { 19 } else { 18 };
    let mut out = 0usize;
    let mut off = 0usize;
    while off < n {
        if off + 16 > n {
            break;
        }
        let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
        if reclen == 0 || off + reclen > n {
            break;
        }
        let name_end = buf[off + name_off..off + reclen]
            .iter()
            .position(|&b| b == 0)
            .map(|i| off + name_off + i)
            .unwrap_or(off + reclen);
        let name = String::from_utf8_lossy(&buf[off + name_off..name_end]);
        let drop = if name == "chimera" || name.starts_with("chimera-") {
            true
        } else if at_root && (name == "chi" || name == "t") {
            true
        } else if in_scratch && (name.starts_with("t-") || name.starts_with("s-")) {
            true
        } else {
            false
        };
        if !drop {
            if out != off {
                buf.copy_within(off..off + reclen, out);
            }
            out += reclen;
        }
        off += reclen;
    }
    out
}

fn resolve_path(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    key: &str,
    dirfd_key: &str,
    ctx: &mut paths::PathCtx,
    cwd: &str,
) -> Option<String> {
    let dirfd = match name {
        "mkdirat" | "mknodat" | "unlinkat" | "symlinkat" => paths::dirfd_of(raw, dirfd_key),
        "renameat" | "renameat2" | "linkat" => paths::dirfd_of(raw, dirfd_key),
        _ => libc::AT_FDCWD,
    };
    let path = if dirfd != libc::AT_FDCWD {
        paths::guest_path_arg(pid, args, raw, key)?
    } else {
        args.get(key)?.clone()
    };
    ctx.resolve_at(pid, dirfd, &path, cwd)
}

fn mkdir(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_path(pid, name, args, raw, "path", "dirfd", ctx, &cwd)?;
    let cpath = paths::cstr(&host)?;
    let mode = parse_u64(args.get("mode")).unwrap_or(0o777) as libc::mode_t;

    let r = unsafe { libc::mkdir(cpath.as_ptr(), mode) };
    if r < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    if state.xattr_perms {
        let umask = metadata::tracee_umask(pid);
        let ident = state.proc(pid).ident;
        xattr::stamp(&host, &ident, mode & !umask);
    }
    Some(EmuReply::Value(0))
}

/// mknod/mknodat: create a fifo, socket, or device node. the path resolves
/// against the *virtual* cwd (the kernel cwd is pinned at the rootfs), then
/// runs as the supervisor on the mapped host path.
fn mknod(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    if state.debug {
        eprintln!("{} mknod: name={name} cwd={cwd} args={args:?}", crate::log::tag("debug-mknod"));
    }
    let host = resolve_path(pid, name, args, raw, "path", "dirfd", ctx, &cwd)?;
    let cpath = paths::cstr(&host)?;
    let mode = parse_u64(args.get("mode")).unwrap_or(0) as libc::mode_t;
    let dev = parse_u64(args.get("dev")).unwrap_or(0) as libc::dev_t;
    if state.debug {
        eprintln!("{} mknod: host={} mode={:o} dev={}", crate::log::tag("debug-mknod"), host, mode, dev);
    }
    let r = unsafe { libc::mknodat(libc::AT_FDCWD, cpath.as_ptr(), mode, dev) };
    if r < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    if state.xattr_perms {
        let umask = metadata::tracee_umask(pid);
        let ident = state.proc(pid).ident;
        xattr::stamp(&host, &ident, mode & !umask);
    }
    Some(EmuReply::Value(0))
}

fn rmdir(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = ctx.map_host(pid, args.get("path")?, &cwd);
    let cpath = paths::cstr(&host)?;
    let r = unsafe { libc::rmdir(cpath.as_ptr()) };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn unlink(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_path(pid, name, args, raw, "path", "dirfd", ctx, &cwd)?;
    let cpath = paths::cstr(&host)?;
    let r = match name {
        "unlink" => unsafe { libc::unlink(cpath.as_ptr()) },
        "unlinkat" => {
            let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_int;
            unsafe { libc::unlinkat(libc::AT_FDCWD, cpath.as_ptr(), flags) }
        }
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn rename(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let old_host = resolve_path(
        pid, name, args, raw, "oldpath", "olddirfd", ctx, &cwd,
    )?;
    let new_host = resolve_path(
        pid, name, args, raw, "newpath", "newdirfd", ctx, &cwd,
    )?;
    let old_c = paths::cstr(&old_host)?;
    let new_c = paths::cstr(&new_host)?;
    let r = match name {
        "rename" => unsafe { libc::rename(old_c.as_ptr(), new_c.as_ptr()) },
        "renameat" => unsafe {
            libc::renameat(
                libc::AT_FDCWD,
                old_c.as_ptr(),
                libc::AT_FDCWD,
                new_c.as_ptr(),
            )
        },
        "renameat2" => {
            // rename through sys_renameat2 directly: musl's libc.a has no
            // `renameat2` wrapper (unlike glibc), so calling libc::renameat2
            // would fail static linking.
            let flags = parse_u64(args.get("flags")).unwrap_or(0) as libc::c_uint;
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    old_c.as_ptr(),
                    libc::AT_FDCWD,
                    new_c.as_ptr(),
                    flags,
                ) as libc::c_int
            }
        }
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn link(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let old_host = resolve_path(
        pid, name, args, raw, "oldpath", "olddirfd", ctx, &cwd,
    )?;
    let new_host = resolve_path(
        pid, name, args, raw, "newpath", "newdirfd", ctx, &cwd,
    )?;
    let old_c = paths::cstr(&old_host)?;
    let new_c = paths::cstr(&new_host)?;
    let r = match name {
        "link" => unsafe { libc::link(old_c.as_ptr(), new_c.as_ptr()) },
        "linkat" => unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                old_c.as_ptr(),
                libc::AT_FDCWD,
                new_c.as_ptr(),
                0,
            )
        },
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn symlink(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let target = args.get("target")?;
    // the kernel resolves an *absolute* symlink target against the host root
    let stored = if target.starts_with('/') {
        ctx.map_host(pid, target, &cwd)
    } else {
        target.clone()
    };
    let target_c = paths::cstr(&stored)?;
    let link_host = resolve_path(
        pid, name, args, raw, "linkpath", "newdirfd", ctx, &cwd,
    )?;
    let link_c = paths::cstr(&link_host)?;
    let r = unsafe { libc::symlink(target_c.as_ptr(), link_c.as_ptr()) };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

pub fn chdir(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let path = args.get("path")?;
    let cwd = state.proc(pid).cwd.clone();
    let guest = if let Some(g) = path.strip_prefix(ctx.rootfs()) {
        let g = g.trim_start_matches('/');
        if g.is_empty() {
            "/".to_string()
        } else {
            format!("/{g}")
        }
    } else {
        paths::translate_proc(pid, &resolve_guest(&cwd, path))
    };
    let host = paths::cstr(&ctx.guest_to_host(&guest))?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(libc::AT_FDCWD, host.as_ptr(), &mut st, 0) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Some(EmuReply::Errno(libc::ENOTDIR));
    }
    state.proc_mut(pid).cwd = guest;
    Some(EmuReply::Value(0))
}

pub fn fchdir(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let fd = raw.get("fd").copied()? as i32;
    let host = match paths::fd_host_path(pid, fd) {
        Some(h) => h,
        None => return Some(EmuReply::Errno(libc::EBADF)),
    };

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let host_c = match paths::cstr(&host) {
        Some(c) => c,
        None => return Some(EmuReply::Errno(libc::ENAMETOOLONG)),
    };
    if unsafe { libc::stat(host_c.as_ptr(), &mut st) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Some(EmuReply::Errno(libc::ENOTDIR));
    }
    match ctx.host_to_guest(&host) {
        Some(guest) => {
            state.proc_mut(pid).cwd = guest;
            Some(EmuReply::Value(0))
        }
        None => Some(EmuReply::Errno(libc::EACCES)),
    }
}

pub fn getcwd(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let buf = raw.get("buffer").copied()?;
    let size = raw.get("length").copied().unwrap_or(0) as usize;
    let cwd = state.proc(pid).cwd.clone();
    let bytes = cwd.as_bytes();
    if bytes.len() + 1 > size {
        return Some(EmuReply::Errno(libc::ERANGE));
    }
    let mut out = bytes.to_vec();
    out.push(0);
    if mem::write_bytes(pid, buf, &out).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(bytes.len() as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// build a linux_dirent64 buffer (d_ino, d_off, d_reclen, d_type, name).
    fn dents64(names: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let name_off = buf.len() + 19;
            let reclen = (name_off + name.len() + 1 + 7) & !7;
            let reclen_u16 = (reclen - buf.len()) as u16;
            buf.extend_from_slice(&(100 + i as u64).to_ne_bytes()); // d_ino
            buf.extend_from_slice(&(200 + i as u64).to_ne_bytes()); // d_off
            buf.extend_from_slice(&reclen_u16.to_ne_bytes()); // d_reclen
            buf.push(4); // d_type dt_dir
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            while buf.len() < reclen {
                buf.push(0);
            }
        }
        buf
    }

    #[test]
    fn filters_scratch_from_root_listing() {
        let buf = dents64(&[".", "..", "chi", "t", "tmp", "chimera-2be40f33", "t-foo", "usr"]);
        let n = buf.len();
        let mut got = buf.clone();
        let n2 = scratch_filter(true, n, &mut got, Some("/srv/rootfs"), "/srv/rootfs");
        // chi, t, chimera-* dropped; t-foo kept (root dir is not a scratch container)
        let kept: Vec<String> = parse_names(&got[..n2]);
        assert_eq!(kept, vec![".", "..", "tmp", "t-foo", "usr"]);
    }

    #[test]
    fn filters_shims_inside_scratch_dir() {
        let buf = dents64(&[".", "..", "t-3o6b8mturs4y", "s-script", "libexpat1.deb", "chimera"]);
        let n = buf.len();
        let mut got = buf.clone();
        let n2 = scratch_filter(
            true,
            n,
            &mut got,
            Some("/srv/rootfs/chi/chimera-2be40f33"),
            "/srv/rootfs",
        );
        let kept: Vec<String> = parse_names(&got[..n2]);
        assert_eq!(kept, vec![".", "..", "libexpat1.deb"]);
    }

    #[test]
    fn keeps_regular_entries_elsewhere() {
        let buf = dents64(&[".", "..", "t-foo", "bin", "s-bar"]);
        let n = buf.len();
        let mut got = buf.clone();
        let n2 = scratch_filter(true, n, &mut got, Some("/srv/rootfs/tmp"), "/srv/rootfs");
        // /tmp is not a chimera scratch container; t-foo/s-bar are user files
        let kept: Vec<String> = parse_names(&got[..n2]);
        assert_eq!(kept, vec![".", "..", "t-foo", "bin", "s-bar"]);
    }

    fn parse_names(buf: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut off = 0;
        while off + 16 <= buf.len() {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > buf.len() {
                break;
            }
            let end = buf[off + 19..off + reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|i| off + 19 + i)
                .unwrap_or(off + reclen);
            out.push(String::from_utf8_lossy(&buf[off + 19..end]).into_owned());
            off += reclen;
        }
        out
    }

    fn raw(map: &[(&str, u64)]) -> HashMap<String, u64> {
        map.iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect()
    }

    #[test]
    fn lseek_updates_tracked_dir_stream_and_passes_others_through() {
        let mut state = SandboxState::new();
        let fd = 3;

        // untracked fd: not a stream the getdents emulation serves, so the real
        // kernel lseek is correct -> continue.
        assert_eq!(
            lseek(1, &raw(&[("fd", fd as u64), ("offset", 0), ("whence", 0)]), &mut state),
            Some(EmuReply::Continue)
        );

        // track the fd as a dir stream at offset 512.
        state.set_dir_stream(1, fd, 0xAA, 0xBB, 512);

        // with seek_set, offset is absolute
        assert_eq!(
            lseek(1, &raw(&[("fd", fd as u64), ("offset", 64), ("whence", 0)]), &mut state),
            Some(EmuReply::Value(64))
        );
        assert_eq!(state.dir_stream(1, fd), Some((0xAA, 0xBB, 64)));
        // with seek_cur, offset is relative to the current position
        assert_eq!(
            lseek(1, &raw(&[("fd", fd as u64), ("offset", -40i64 as u64), ("whence", 1)]), &mut state),
            Some(EmuReply::Value(24))
        );
        assert_eq!(state.dir_stream(1, fd), Some((0xAA, 0xBB, 24)));
        // dirs have no size, so seek_end is meaningless
        assert_eq!(
            lseek(1, &raw(&[("fd", fd as u64), ("offset", 0), ("whence", 2)]), &mut state),
            Some(EmuReply::Errno(libc::EINVAL))
        );
        // negative result -> einval
        assert_eq!(
            lseek(1, &raw(&[("fd", fd as u64), ("offset", -100i64 as u64), ("whence", 0)]), &mut state),
            Some(EmuReply::Errno(libc::EINVAL))
        );
    }

    #[test]
    fn getdents_offset_resets_on_reused_fd_number() {
        let mut state = SandboxState::new();
        // stream on fd 5 for /a; then fd 5 is reused for /b (different ino).
        state.set_dir_stream(1, 5, 1, 100, 4096);
        assert_eq!(state.dir_stream(1, 5), Some((1, 100, 4096)));
        // a getdents for a different inode starts a fresh stream at 0.
        let off = match state.dir_stream(1, 5) {
            Some((d, i, o)) if d == 1 && i == 200 => o,
            _ => 0,
        };
        assert_eq!(off, 0);
        // close forgets the stream entirely.
        state.clear_dir_stream(1, 5);
        assert_eq!(state.dir_stream(1, 5), None);
    }
}
