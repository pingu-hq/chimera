//! extended attribute helpers for `user.chimera.meta`, plus the boot probe.

use crate::emulation::paths;
use crate::emulation::state::{
    Identity, MetaPerms, ProcessState, SandboxState, XATTR_META, XATTR_META_VERSION,
};
use crate::emulation::EmuReply;
use crate::runtime::mem;
use std::collections::HashMap;
use std::ffi::CString;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}

/// attribute used by the bootup capability probe.
pub const XATTR_PROBE: &str = "user.chimera.probe";

/// read the `user.chimera.meta` payload from `path` (following symlinks, like
/// `stat`). returns `none` when absent or unparsable.
pub fn read_meta(path: &str) -> Option<MetaPerms> {
    get_meta(path, false)
}

/// read meta without following a trailing symlink (`lstat`/`lchown` semantics).
pub fn read_meta_nofollow(path: &str) -> Option<MetaPerms> {
    get_meta(path, true)
}

fn get_meta(path: &str, nofollow: bool) -> Option<MetaPerms> {
    let cpath = CString::new(path).ok()?;
    let cname = CString::new(XATTR_META).ok()?;
    // meta payloads are short; the fixed 128-byte buffer always fits.
    let mut buf = [0u8; 128];
    let n = unsafe {
        if nofollow {
            libc::lgetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        } else {
            libc::getxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        }
    };
    if n <= 0 {
        return None;
    }
    MetaPerms::from_xattr(&buf[..n as usize])
}

/// write a `user.chimera.meta` payload to `path` (following symlinks).
pub fn write_meta(path: &str, perms: &MetaPerms) -> bool {
    set_meta(path, perms, false)
}

/// write meta without following a trailing symlink.
pub fn write_meta_nofollow(path: &str, perms: &MetaPerms) -> bool {
    set_meta(path, perms, true)
}

fn set_meta(path: &str, perms: &MetaPerms, nofollow: bool) -> bool {
    let cpath = CString::new(path).ok();
    let cname = CString::new(XATTR_META).ok();
    let (Some(cpath), Some(cname)) = (cpath, cname) else {
        return false;
    };
    let data = perms.to_xattr();

    // dpkg/apt create files and directories with mode 0 (mkfifoat(0),
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    let opened_writable = unsafe {
        libc::fstatat(libc::AT_FDCWD, cpath.as_ptr(), &mut st, flags) == 0
            && !nofollow
            && (st.st_mode & libc::S_IWUSR) == 0
            && libc::chmod(cpath.as_ptr(), st.st_mode | libc::S_IWUSR) == 0
    };

    let r = unsafe {
        if nofollow {
            libc::lsetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
            )
        } else {
            libc::setxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
            )
        }
    };

    if opened_writable {
        unsafe { libc::chmod(cpath.as_ptr(), st.st_mode) };
    }
    r == 0
}

/// stamp `path` with the current sandbox identity and `mode`.
pub fn stamp(path: &str, ident: &Identity, mode: u32) -> bool {
    write_meta(
        path,
        &MetaPerms {
            version: XATTR_META_VERSION,
            uid: ident.euid,
            gid: ident.egid,
            mode: mode & 0o7777,
        },
    )
}

/// overlay a `user.chimera.meta` override onto a raw `libc::stat`.
pub fn apply_meta_to_stat(st: &mut libc::stat, meta: &MetaPerms) {
    st.st_uid = meta.uid;
    st.st_gid = meta.gid;
    st.st_mode = (st.st_mode & !0o7777) | (meta.mode & 0o7777);
}

/// same as [`apply_meta_to_stat`] for `struct statx`.
pub fn apply_meta_to_statx(st: &mut crate::emulation::statx::Statx, meta: &MetaPerms) {
    st.stx_uid = meta.uid;
    st.stx_gid = meta.gid;
    st.stx_mode = (st.stx_mode & !0o7777u16) | (meta.mode as u16 & 0o7777);
}

/// virtual permission check against the process identity.
///
/// `perm` is a bitset of `r_ok`/`w_ok`/`x_ok`. root (`euid == 0`) bypasses
/// everything except execute-on-non-dir, which still needs any `x` bit.
pub fn virt_access(
    mode: u32,
    st_uid: u32,
    st_gid: u32,
    proc: &ProcessState,
    perm: libc::c_int,
    is_dir: bool,
) -> bool {
    if proc.ident.euid == 0 {
        return match perm {
            libc::X_OK => is_dir || (mode & 0o111) != 0,
            _ => true,
        };
    }
    let perm = perm as u32;
    let bits = if proc.ident.euid == st_uid {
        (mode >> 6) & 0o7
    } else if proc.ident.egid == st_gid || proc.groups.contains(&st_gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    bits & perm == perm
}

/// may this process change the mode of a file owned by `meta`?
pub fn can_chmod(proc: &ProcessState, meta: &MetaPerms) -> bool {
    proc.ident.euid == 0 || proc.ident.euid == meta.uid
}

/// may this process apply the given ownership change?
pub fn can_chown(
    proc: &ProcessState,
    meta: &MetaPerms,
    new_uid: Option<u32>,
    new_gid: Option<u32>,
) -> bool {
    let uid_change = new_uid.filter(|&u| u != u32::MAX && u != meta.uid);
    let gid_change = new_gid.filter(|&g| g != u32::MAX && g != meta.gid);

    if proc.ident.euid == 0 {
        return true;
    }
    if uid_change.is_some() {
        return false;
    }
    if proc.ident.euid != meta.uid {
        return false;
    }
    match gid_change {
        None => true,
        Some(g) => g == proc.ident.egid || proc.groups.contains(&g),
    }
}

/// route a trapped path-based xattr syscall.
pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let name_arg = args.get("name").cloned();
    let cname = name_arg.as_deref().and_then(|s| CString::new(s).ok());

    // the `user.chimera.*` namespace is the sandbox's own bookkeeping: the
    // guest must neither read nor write it. reading answers enodata (as if the
    // attribute were absent), listing filters it out, and writing/removing it
    // is refused outright.
    let reserved = name_arg
        .as_deref()
        .is_some_and(|n| n.starts_with("user.chimera."));

    let host = match name {
        // fd-based variants resolve the fd through `/proc/<pid>/fd`.
        "fgetxattr" | "fsetxattr" | "flistxattr" | "fremovexattr" => {
            let fd = args.get("fd").and_then(|s| s.parse::<i32>().ok())?;
            paths::cstr(&paths::fd_host_path(pid, fd)?)?
        }
        _ => paths::cstr(&ctx.map_host(pid, args.get("path")?, &cwd))?,
    };

    let r = match name {
        "setxattr" | "lsetxattr" | "fsetxattr" => {
            if reserved {
                return Some(EmuReply::Errno(libc::EPERM));
            }
            let value_ptr = raw.get("value").copied()?;
            let length = raw.get("length").copied().unwrap_or(0) as usize;
            let flags = raw.get("flags").copied().unwrap_or(0) as libc::c_int;
            let value = mem::read_bytes(pid, value_ptr, length)?;
            let cname = cname.as_ref()?;
            match name {
                "lsetxattr" => unsafe {
                    libc::lsetxattr(
                        host.as_ptr(),
                        cname.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags,
                    )
                },
                "fsetxattr" => unsafe {
                    let fd = args.get("fd").and_then(|s| s.parse::<i32>().ok())?;
                    libc::fsetxattr(
                        fd,
                        cname.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags,
                    )
                },
                _ => unsafe {
                    libc::setxattr(
                        host.as_ptr(),
                        cname.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags,
                    )
                },
            }
        }
        "getxattr" | "lgetxattr" | "fgetxattr" => {
            if reserved {
                return Some(EmuReply::Errno(libc::ENODATA));
            }
            let out_ptr = raw.get("value").copied()?;
            let length = raw.get("length").copied().unwrap_or(0) as usize;
            let cname = cname.as_ref()?;
            let mut buf = vec![0u8; length];
            let n = unsafe {
                match name {
                    "lgetxattr" => libc::lgetxattr(
                        host.as_ptr(),
                        cname.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        length,
                    ),
                    "fgetxattr" => {
                        let fd = args.get("fd").and_then(|s| s.parse::<i32>().ok())?;
                        libc::fgetxattr(
                            fd,
                            cname.as_ptr(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            length,
                        )
                    }
                    _ => libc::getxattr(
                        host.as_ptr(),
                        cname.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        length,
                    ),
                }
            };
            if n < 0 {
                return Some(EmuReply::Errno(errno()));
            }
            let n = n as usize;
            if mem::write_bytes(pid, out_ptr, &buf[..n]).is_none() {
                return Some(EmuReply::Errno(libc::EFAULT));
            }
            return Some(EmuReply::Value(n as i64));
        }
        "listxattr" | "llistxattr" | "flistxattr" => {
            let out_ptr = raw.get("list").copied()?;
            let length = raw.get("length").copied().unwrap_or(0) as usize;
            let mut buf = vec![0u8; length];
            let n = unsafe {
                match name {
                    "llistxattr" => libc::llistxattr(
                        host.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_char,
                        length,
                    ),
                    "flistxattr" => {
                        let fd = args.get("fd").and_then(|s| s.parse::<i32>().ok())?;
                        libc::flistxattr(
                            fd,
                            buf.as_mut_ptr() as *mut libc::c_char,
                            length,
                        )
                    }
                    _ => libc::listxattr(
                        host.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_char,
                        length,
                    ),
                }
            };
            if n < 0 {
                return Some(EmuReply::Errno(errno()));
            }
            let n = n as usize;
            // filter the `user.chimera.*` names out of the nul-separated list
            // (a truncated buffer reports the size a full list would need).
            let list = &buf[..n];
            let mut kept: Vec<u8> = Vec::with_capacity(list.len());
            for attr in list.split(|&b| b == 0).filter(|s| !s.is_empty()) {
                if !attr.starts_with(b"user.chimera.") {
                    kept.extend_from_slice(attr);
                    kept.push(0);
                }
            }
            let (written, ret) = if kept.len() > list.len() {
                // the guest asked for fewer bytes than the (filtered) list
                // needs; report the needed size like the kernel does.
                (list.len(), kept.len())
            } else {
                let n = kept.len();
                (n, n)
            };
            if mem::write_bytes(pid, out_ptr, &kept[..written]).is_none() {
                return Some(EmuReply::Errno(libc::EFAULT));
            }
            return Some(EmuReply::Value(ret as i64));
        }
        "removexattr" | "lremovexattr" | "fremovexattr" => {
            if reserved {
                return Some(EmuReply::Errno(libc::EPERM));
            }
            let cname = cname.as_ref()?;
            match name {
                "lremovexattr" => unsafe {
                    libc::lremovexattr(host.as_ptr(), cname.as_ptr())
                },
                "fremovexattr" => unsafe {
                    let fd = args.get("fd").and_then(|s| s.parse::<i32>().ok())?;
                    libc::fremovexattr(fd, cname.as_ptr())
                },
                _ => unsafe { libc::removexattr(host.as_ptr(), cname.as_ptr()) },
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

/// result of probing a rootfs for `user.*` xattr support.
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// user.* xattrs round-trip on the rootfs.
    Supported,
    /// the rootfs accepts files but refuses user.* xattrs (`reason` is the
    /// fsetxattr failure, e.g. enotsup on a filesystem without user xattrs).
    Unsupported(String),
    /// the probe could not even create its file (missing rootfs, not a
    /// directory, permission denied, ...) - `reason` carries the path error.
    Error(String),
}

/// probe whether the rootfs filesystem round-trips `user.*` xattrs.
pub fn probe_xattr_perms(rootfs: &str) -> ProbeOutcome {
    let root = rootfs.trim_end_matches('/');
    let mut dirs = Vec::with_capacity(4);
    dirs.push(root.to_string());
    for sub in ["tmp", "var/tmp", "t"] {
        dirs.push(format!("{root}/{sub}"));
    }

    let mut last_err = String::new();
    for dir in &dirs {
        match probe_dir_xattr(dir) {
            Ok(outcome) => return outcome,
            Err(e) => last_err = e,
        }
    }
    ProbeOutcome::Error(format!(
        "cannot create probe file under '{root}' (tried {} locations): {last_err}",
        dirs.len()
    ))
}

/// probe `user.*` xattr round-trip in `dir`. `err` means the directory does
/// not even accept a new file (missing, permissions, ...) - try another
/// location. `ok` carries the final answer once a file could be created.
fn probe_dir_xattr(dir: &str) -> Result<ProbeOutcome, String> {
    let path = format!(
        "{}/.chimera.probe.{}",
        dir.trim_end_matches('/'),
        std::process::id()
    );
    let cpath = CString::new(path)
        .map_err(|_| "probe path contains a NUL byte".to_string())?;

    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot create probe file '{}': {}",
            String::from_utf8_lossy(cpath.as_bytes()),
            std::io::Error::last_os_error()
        ));
    }

    let cname = CString::new(XATTR_PROBE)
        .map_err(|_| {
            unsafe { libc::close(fd) };
            unsafe { libc::unlink(cpath.as_ptr()) };
            "xattr name contains a NUL byte".to_string()
        })?;

    let value = b"1";
    let set_err = unsafe {
        let r = libc::fsetxattr(
            fd,
            cname.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        );
        if r == 0 {
            None
        } else {
            Some(std::io::Error::last_os_error())
        }
    };
    if let Some(e) = set_err {
        unsafe { libc::close(fd) };
        unsafe { libc::unlink(cpath.as_ptr()) };
        return Ok(ProbeOutcome::Unsupported(format!(
            "fsetxattr user.* on '{}' failed: {e}",
            String::from_utf8_lossy(cpath.as_bytes())
        )));
    }

    let mut buf = [0u8; 8];
    let n = unsafe {
        libc::fgetxattr(
            fd,
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    let ok = n == value.len() as isize && buf[..n as usize] == *value;
    if ok {
        unsafe { libc::fremovexattr(fd, cname.as_ptr()) };
    }
    unsafe { libc::close(fd) };
    unsafe { libc::unlink(cpath.as_ptr()) };
    if ok {
        Ok(ProbeOutcome::Supported)
    } else {
        Ok(ProbeOutcome::Unsupported(
            "fsetxattr succeeded but fgetxattr did not round-trip".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_round_trips_on_supporting_fs() {
        let dir = std::env::temp_dir().join(format!("chimera-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            probe_xattr_perms(dir.to_str().unwrap()),
            ProbeOutcome::Supported
        );
        let leftover = dir.join(format!(".chimera.probe.{}", std::process::id()));
        assert!(!leftover.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn probe_error_when_rootfs_missing() {
        assert!(matches!(
            probe_xattr_perms("/nonexistent-chimera-probe"),
            ProbeOutcome::Error(_)
        ));
    }

    #[test]
    fn probe_falls_back_to_writable_subdir_on_readonly_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("chimera-ro-{}", std::process::id()));
        let root = dir.join("rootfs");
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            probe_xattr_perms(root.to_str().unwrap()),
            ProbeOutcome::Supported
        );
        // nothing left behind in either location
        let leftover = root.join(format!(".chimera.probe.{}", std::process::id()));
        assert!(!leftover.exists());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn can_chown_respects_minus_one() {
        let mut proc = ProcessState::root();
        proc.ident.setuid(1000);
        let meta = MetaPerms {
            version: 1,
            uid: 1000,
            gid: 1000,
            mode: 0o644,
        };
        assert!(can_chown(&proc, &meta, Some(u32::MAX), Some(1000)));
        assert!(!can_chown(&proc, &meta, Some(0), Some(u32::MAX)));
        assert!(!can_chown(&proc, &meta, Some(u32::MAX), Some(42)));
        proc.groups.push(42);
        assert!(can_chown(&proc, &meta, Some(u32::MAX), Some(42)));
    }
}
