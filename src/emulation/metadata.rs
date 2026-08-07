
use crate::emulation::paths;
use crate::emulation::state::{MetaPerms, SandboxState, XATTR_META_VERSION};
use crate::emulation::{xattr, EmuReply};
use crate::runtime::mem;
use std::collections::HashMap;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}

/// route a trapped metadata syscall.
pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    match name {
        "chmod" | "fchmodat" | "fchmodat2" => {
            if state.debug {
                eprintln!("{} dispatch {name}: args={args:?}", crate::log::tag("debug-meta"));
            }
            chmod(pid, name, args, raw, ctx, state)
        }
        "chown" | "lchown" | "fchownat" => {
            chown(pid, name, args, raw, ctx, state)
        }
        "truncate" => truncate(pid, args, ctx, state),
        "utime" | "utimes" | "utimensat" | "futimesat" => {
            utimens(pid, name, args, raw, ctx, state)
        }
        "fchmod" | "fchown" | "ftruncate" => fd_meta(pid, name, args, state),
        _ => None,
    }
}

/// read the tracee's current umask so o_creat/mkdir stamping matches the kernel.
pub fn tracee_umask(pid: libc::pid_t) -> u32 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Umask:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        })
        .unwrap_or(0)
}

/// existing meta for `path`, or a fallback built from the real inode.
fn meta_or_host(path: &str, nofollow: bool) -> Option<MetaPerms> {
    if nofollow {
        if let Some(m) = xattr::read_meta_nofollow(path) {
            return Some(m);
        }
    } else if let Some(m) = xattr::read_meta(path) {
        return Some(m);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let cpath = paths::cstr(path)?;
    let flags = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    if unsafe { libc::fstatat(libc::AT_FDCWD, cpath.as_ptr(), &mut st, flags) } < 0 {
        return None;
    }
    Some(MetaPerms {
        version: XATTR_META_VERSION,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode & 0o7777,
    })
}

/// true for inode types that refuse `user.*` xattrs (fifos, sockets, device
/// nodes). the virtual-perms model can't store meta on them, so chmod/chown
/// fall back to the real host operation.
fn is_xattr_special(path: &str) -> bool {
    let Some(cpath) = paths::cstr(path) else {
        return false;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(libc::AT_FDCWD, cpath.as_ptr(), &mut st, 0) } < 0 {
        return false;
    }
    matches!(
        st.st_mode & libc::S_IFMT,
        libc::S_IFIFO | libc::S_IFSOCK | libc::S_IFCHR | libc::S_IFBLK
    )
}

fn parse_u32(v: Option<&String>) -> Option<u32> {
    v.and_then(|s| s.parse::<u32>().ok())
}

fn resolve_meta_path(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    cwd: &str,
) -> Option<String> {
    let dirfd = match name {
        "fchmodat" | "fchmodat2" | "fchownat" | "utimensat" | "futimesat" => {
            paths::dirfd_of(raw, "dirfd")
        }
        _ => libc::AT_FDCWD,
    };
    // for non-at_fdcwd, re-read the guest path so we don't use a
    // cwd-mapped relative path from the policy.
    let path = if dirfd != libc::AT_FDCWD {
        paths::guest_path_arg(pid, args, raw, "path")?
    } else {
        args.get("path")?.clone()
    };
    ctx.resolve_at(pid, dirfd, &path, cwd)
}

fn chmod(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_meta_path(pid, name, args, raw, ctx, &cwd)?;
    let mode = parse_u32(args.get("mode"))? as libc::mode_t;
    if state.debug {
        eprintln!("{} {name}: cwd={cwd} host={host} mode={mode:o}", crate::log::tag("debug-meta"));
    }

    // fchmodat2 (glibc's fchmodat with flags) honors at_symlink_nofollow. the
    // kernel cannot change a symlink's mode, so report enotsup like the real
    // syscall - gnu tar treats that as success for symlinks.
    let nofollow = name == "fchmodat2"
        && raw.get("flags").copied().unwrap_or(0) as i32 & libc::AT_SYMLINK_NOFOLLOW != 0;
    if nofollow {
        let cpath = paths::cstr(&host)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(cpath.as_ptr(), &mut st) } < 0 {
            return Some(EmuReply::Errno(errno()));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Some(EmuReply::Errno(libc::ENOTSUP));
        }
    }

    if state.xattr_perms {
        if is_xattr_special(&host) {
            let cpath = paths::cstr(&host)?;
            return Some(if unsafe { libc::chmod(cpath.as_ptr(), mode) } < 0 {
                EmuReply::Errno(errno())
            } else {
                EmuReply::Value(0)
            });
        }
        let mut meta = meta_or_host(&host, false)?;
        if !xattr::can_chmod(state.proc(pid), &meta) {
            return Some(EmuReply::Errno(libc::EPERM));
        }
        meta.mode = mode & 0o7777;
        let ok = xattr::write_meta(&host, &meta);
        if ok {
            // mirror the mode onto the real host inode as well: the sandbox
            let cpath = paths::cstr(&host)?;
            unsafe { libc::chmod(cpath.as_ptr(), mode) };
        }
        return Some(if ok {
            EmuReply::Value(0)
        } else {
            EmuReply::Errno(errno())
        });
    }

    let cpath = paths::cstr(&host)?;
    let r = match name {
        "chmod" => unsafe { libc::chmod(cpath.as_ptr(), mode) },
        // legacy fchmodat ignores flags; glibc leaves r10 garbage.
        "fchmodat" | "fchmodat2" => unsafe {
            libc::fchmodat(libc::AT_FDCWD, cpath.as_ptr(), mode, 0)
        },
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn chown(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_meta_path(pid, name, args, raw, ctx, &cwd)?;
    let owner = parse_u32(args.get("owner"));
    let group = parse_u32(args.get("group"));
    let nofollow = name == "lchown"
        || (name == "fchownat"
            && raw.get("flags").copied().unwrap_or(0) as i32 & libc::AT_SYMLINK_NOFOLLOW != 0);

    if state.xattr_perms {
        if !nofollow && is_xattr_special(&host) {
            let cpath = paths::cstr(&host)?;
            let o = owner.unwrap_or(u32::MAX);
            let g = group.unwrap_or(u32::MAX);
            return Some(if unsafe { libc::chown(cpath.as_ptr(), o, g) } < 0 {
                EmuReply::Errno(errno())
            } else {
                EmuReply::Value(0)
            });
        }
        let mut meta = meta_or_host(&host, nofollow)?;
        if !xattr::can_chown(state.proc(pid), &meta, owner, group) {
            return Some(EmuReply::Errno(libc::EPERM));
        }
        if let Some(o) = owner {
            if o != u32::MAX {
                meta.uid = o;
            }
        }
        if let Some(g) = group {
            if g != u32::MAX {
                meta.gid = g;
            }
        }
        let ok = if nofollow {
            xattr::write_meta_nofollow(&host, &meta)
        } else {
            xattr::write_meta(&host, &meta)
        };
        // kernel forbids user.* xattrs on symlinks; treat that as success for
        // cosmetic chown of a symlink (ownership is not stored).
        if !ok && nofollow {
            return Some(EmuReply::Value(0));
        }
        return Some(if ok {
            EmuReply::Value(0)
        } else {
            EmuReply::Errno(errno())
        });
    }

    let cpath = paths::cstr(&host)?;
    let owner = owner.unwrap_or(u32::MAX);
    let group = group.unwrap_or(u32::MAX);
    let r = match name {
        "chown" => unsafe { libc::chown(cpath.as_ptr(), owner, group) },
        "lchown" => unsafe { libc::lchown(cpath.as_ptr(), owner, group) },
        "fchownat" => {
            let flags = raw.get("flags").copied().unwrap_or(0) as libc::c_int;
            unsafe { libc::fchownat(libc::AT_FDCWD, cpath.as_ptr(), owner, group, flags) }
        }
        _ => return None,
    };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

fn fd_meta(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    if state.debug {
        eprintln!("{} {name}: args={args:?}", crate::log::tag("debug-meta"));
    }
    if name == "ftruncate" {
        return None;
    }
    let fd = args.get("fd")?.parse::<i32>().ok()?;
    let host = match paths::fd_host_path(pid, fd) {
        Some(h) => h,
        None => {
            if state.debug {
                eprintln!("{} {name}: fd_host_path({fd}) failed", crate::log::tag("debug-meta"));
            }
            return None;
        }
    };
    if state.debug {
        eprintln!("{} {name}: fd={fd} host={host}", crate::log::tag("debug-meta"));
    }

    match name {
        "fchmod" => {
            let mode = parse_u32(args.get("mode"))? as libc::mode_t;
            if !state.xattr_perms {
                let cpath = paths::cstr(&host)?;
                let r = unsafe { libc::chmod(cpath.as_ptr(), mode) };
                if state.debug {
                    eprintln!("{} {name}: chmod({host}, {mode:o}) -> {r} errno={}", crate::log::tag("debug-meta"), errno());
                }
                return Some(if r < 0 {
                    EmuReply::Errno(errno())
                } else {
                    EmuReply::Value(0)
                });
            }
            let mut meta = meta_or_host(&host, false)?;
            if !xattr::can_chmod(state.proc(pid), &meta) {
                return Some(EmuReply::Errno(libc::EPERM));
            }
            meta.mode = mode & 0o7777;
            let ok = xattr::write_meta(&host, &meta);
            if ok {
                // mirror the real mode like the path-based chmod: files are
                // created mode-000 and later opened by the supervisor, whose
                // permission checks use the real inode mode.
                let cpath = paths::cstr(&host)?;
                unsafe { libc::chmod(cpath.as_ptr(), mode) };
            }
            Some(if ok {
                EmuReply::Value(0)
            } else {
                EmuReply::Errno(errno())
            })
        }
        "fchown" => {
            let owner = parse_u32(args.get("owner"));
            let group = parse_u32(args.get("group"));
            if !state.xattr_perms {
                let cpath = paths::cstr(&host)?;
                let r = unsafe {
                    libc::chown(
                        cpath.as_ptr(),
                        owner.unwrap_or(u32::MAX),
                        group.unwrap_or(u32::MAX),
                    )
                };
                return Some(if r < 0 {
                    EmuReply::Errno(errno())
                } else {
                    EmuReply::Value(0)
                });
            }
            let mut meta = meta_or_host(&host, false)?;
            if !xattr::can_chown(state.proc(pid), &meta, owner, group) {
                return Some(EmuReply::Errno(libc::EPERM));
            }
            if let Some(o) = owner {
                if o != u32::MAX {
                    meta.uid = o;
                }
            }
            if let Some(g) = group {
                if g != u32::MAX {
                    meta.gid = g;
                }
            }
            Some(if xattr::write_meta(&host, &meta) {
                EmuReply::Value(0)
            } else {
                EmuReply::Errno(errno())
            })
        }
        _ => None,
    }
}

fn truncate(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let path = args.get("path")?;
    let host = paths::cstr(&ctx.map_host(pid, path, &cwd))?;
    let length = args.get("length").and_then(|v| v.parse::<i64>().ok())?;
    let r = unsafe { libc::truncate(host.as_ptr(), length as libc::off_t) };
    Some(if r < 0 {
        EmuReply::Errno(errno())
    } else {
        EmuReply::Value(0)
    })
}

/// utime/utimes/utimensat: map the path, then copy the times struct out of
/// the *tracee's* address space before calling libc. passing the raw pointer
/// straight to the supervisor would read supervisor memory (efault / bad address).
fn utimens(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = resolve_meta_path(pid, name, args, raw, ctx, &cwd)?;
    let cpath = paths::cstr(&host)?;

    let r = match name {
        "utime" => {
            let times_ptr = raw.get("times").copied().unwrap_or(0);
            if times_ptr == 0 {
                unsafe { libc::utime(cpath.as_ptr(), std::ptr::null()) }
            } else {
                let bytes = mem::read_bytes(pid, times_ptr, std::mem::size_of::<libc::utimbuf>())?;
                let mut buf = libc::utimbuf {
                    actime: 0,
                    modtime: 0,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        &mut buf as *mut _ as *mut u8,
                        bytes.len(),
                    );
                }
                unsafe { libc::utime(cpath.as_ptr(), &buf) }
            }
        }
        "utimes" | "futimesat" => {
            let times_ptr = raw.get("times").copied().unwrap_or(0);
            if times_ptr == 0 {
                if name == "futimesat" {
                    unsafe {
                        libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), std::ptr::null(), 0)
                    }
                } else {
                    unsafe { libc::utimes(cpath.as_ptr(), std::ptr::null()) }
                }
            } else {
                let bytes =
                    mem::read_bytes(pid, times_ptr, std::mem::size_of::<[libc::timeval; 2]>())?;
                let mut tv = [libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }; 2];
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        tv.as_mut_ptr() as *mut u8,
                        bytes.len(),
                    );
                }
                if name == "futimesat" {
                    // convert timeval → timespec for utimensat.
                    let ts = [
                        libc::timespec {
                            tv_sec: tv[0].tv_sec,
                            tv_nsec: (tv[0].tv_usec as i64) * 1000,
                        },
                        libc::timespec {
                            tv_sec: tv[1].tv_sec,
                            tv_nsec: (tv[1].tv_usec as i64) * 1000,
                        },
                    ];
                    unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), ts.as_ptr(), 0) }
                } else {
                    unsafe { libc::utimes(cpath.as_ptr(), tv.as_ptr()) }
                }
            }
        }
        "utimensat" => {
            let times_ptr = raw.get("times").copied().unwrap_or(0);
            let flags = raw.get("flags").copied().unwrap_or(0) as libc::c_int;
            if times_ptr == 0 {
                unsafe {
                    libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), std::ptr::null(), flags)
                }
            } else {
                let bytes =
                    mem::read_bytes(pid, times_ptr, std::mem::size_of::<[libc::timespec; 2]>())?;
                let mut ts = [libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }; 2];
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        ts.as_mut_ptr() as *mut u8,
                        bytes.len(),
                    );
                }
                unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), ts.as_ptr(), flags) }
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
