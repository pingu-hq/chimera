
use crate::emulation::paths;
use crate::emulation::state::SandboxState;
use crate::emulation::EmuReply;
use crate::runtime::mem;
use crate::runtime::seccomp::{self, SeccompNotif, SeccompNotifAddFd};
use std::collections::HashMap;
use std::os::unix::io::RawFd;

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(-1)
}

pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    notif: &SeccompNotif,
    listener: RawFd,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
    modified: bool,
) -> Option<EmuReply> {
    match name {
        "socket" if modified => socket(pid, raw, notif, listener),
        "socketpair" if modified => socketpair(pid, raw, notif, listener),
        "listen" if modified => listen(pid, raw),
        "setsockopt" if modified => setsockopt(pid, raw),
        "getsockopt" if modified => getsockopt(pid, raw),
        "bind" => bind_or_connect("bind", pid, args, raw, ctx, state),
        "connect" => bind_or_connect("connect", pid, args, raw, ctx, state),
        "accept" | "accept4" => accept(pid, name, raw, notif, listener, ctx),
        "getsockname" | "getpeername" => {
            getname(pid, name, raw, ctx)
        }
        _ => None,
    }
}

// ==============================
// path mapping (af_unix)

/// map the unix socket path inside a guest sockaddr onto the sandbox, if it is
fn map_sockaddr(
    pid: libc::pid_t,
    bytes: &[u8],
    ctx: &mut paths::PathCtx,
    cwd: &str,
) -> Option<Vec<u8>> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_UNIX as u16 {
        return None;
    }
    let body = &bytes[2..];
    if body.is_empty() || body[0] == 0 {
        return None;
    }
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let p = String::from_utf8_lossy(&body[..end]);
    if !p.starts_with('/') {
        return None;
    }
    let mapped = ctx.map_host(pid, &p, cwd);
    if mapped == p {
        return None;
    }
    if mapped.len() > 107 {
        return None; // sockaddr_un.sun_path is 108 bytes
    }
    let mut out = bytes[..2].to_vec();
    out.extend_from_slice(mapped.as_bytes());
    out.push(0);
    Some(out)
}

/// reverse of [`map_sockaddr`] for result buffers: turn a host af_unix path
/// back into the guest view. returns the rebuilt sockaddr, or `none` when the
/// result needs no rewriting.
fn unmap_sockaddr(bytes: &[u8], ctx: &mut paths::PathCtx) -> Option<Vec<u8>> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != libc::AF_UNIX as u16 {
        return None;
    }
    let body = &bytes[2..];
    if body.is_empty() || body[0] == 0 {
        return None;
    }
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let p = String::from_utf8_lossy(&body[..end]);
    let guest = match ctx.host_to_guest(&p) {
        Some(g) => g,
        None => return None,
    };
    if guest == p {
        return None;
    }
    let mut out = bytes[..2].to_vec();
    out.extend_from_slice(guest.as_bytes());
    out.push(0);
    Some(out)
}

/// duplicate a tracee's socket fd into the supervisor via `pidfd_getfd`.
/// the supervisor has none of the tracee's fds, so running a socket syscall
/// against its own fd number would hit the wrong descriptor. `/proc/<pid>/fd`
/// magic links don't work for sockets (enxio), but `pidfd_getfd` does.
fn dup_tracee_fd(pid: libc::pid_t, fd: libc::c_int) -> Option<RawFd> {
    let pf = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pf < 0 {
        return None;
    }
    let dup = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pf, fd, 0) };
    unsafe { libc::close(pf as RawFd) };
    if dup < 0 {
        return None;
    }
    unsafe { libc::fcntl(dup as libc::c_int, libc::F_SETFD, libc::FD_CLOEXEC) };
    Some(dup as RawFd)
}

fn read_socklen(pid: libc::pid_t, addr: u64) -> Option<libc::socklen_t> {
    let b = mem::read_bytes(pid, addr, 4)?;
    Some(libc::socklen_t::from_ne_bytes(b.try_into().ok()?))
}

fn write_socklen(pid: libc::pid_t, addr: u64, v: libc::socklen_t) -> Option<()> {
    mem::write_bytes(pid, addr, &v.to_ne_bytes())
}

fn write_sockaddr(pid: libc::pid_t, addr: u64, bytes: &[u8]) -> Option<()> {
    mem::write_bytes(pid, addr, bytes)
}

// ==============================
// syscall handlers

fn socket(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    notif: &SeccompNotif,
    listener: RawFd,
) -> Option<EmuReply> {
    let domain = *raw.get("domain")? as libc::c_int;
    let ty = *raw.get("type")? as libc::c_int;
    let protocol = *raw.get("protocol")? as libc::c_int;
    let fd = unsafe { libc::socket(domain, ty, protocol) };
    if fd < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    Some(inject_fd(pid, fd, notif, listener))
}

fn socketpair(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    notif: &SeccompNotif,
    listener: RawFd,
) -> Option<EmuReply> {
    let domain = *raw.get("domain")? as libc::c_int;
    let ty = *raw.get("type")? as libc::c_int;
    let protocol = *raw.get("protocol")? as libc::c_int;
    let mut sv = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(domain, ty, protocol, sv.as_mut_ptr()) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    let sv_ptr = *raw.get("sv")?;
    let bytes = unsafe {
        std::slice::from_raw_parts(sv.as_ptr() as *const u8, 8)
    };
    if mem::write_bytes(pid, sv_ptr, bytes).is_none() {
        unsafe { libc::close(sv[0]); libc::close(sv[1]); }
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    let a = inject_fd(pid, sv[0], notif, listener);
    let b = inject_fd(pid, sv[1], notif, listener);
    let EmuReply::Value(af) = a else {
        return Some(a);
    };
    let EmuReply::Value(bf) = b else {
        return Some(b);
    };
    // rewrite both fds into the tracee's sv array (addfd chose the numbers).
    let arr = [af as u32, bf as u32];
    let bytes = unsafe { std::slice::from_raw_parts(arr.as_ptr() as *const u8, 8) };
    if mem::write_bytes(pid, sv_ptr, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}

fn inject_fd(
    _pid: libc::pid_t,
    fd: RawFd,
    notif: &SeccompNotif,
    listener: RawFd,
) -> EmuReply {
    let addfd = SeccompNotifAddFd {
        id: notif.id,
        flags: 0,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: 0,
    };
    match seccomp::notif_addfd(listener, &addfd) {
        Ok(newfd) => {
            unsafe { libc::close(fd) };
            EmuReply::Value(newfd as i64)
        }
        Err(e) => {
            unsafe { libc::close(fd) };
            EmuReply::Errno(e)
        }
    }
}

fn listen(pid: libc::pid_t, raw: &HashMap<String, u64>) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let dup = dup_tracee_fd(pid, fd)?;
    let backlog = *raw.get("backlog")? as libc::c_int;
    let r = unsafe { libc::listen(dup, backlog) };
    let e = errno();
    unsafe { libc::close(dup) };
    Some(if r < 0 {
        EmuReply::Errno(e)
    } else {
        EmuReply::Value(0)
    })
}

fn setsockopt(pid: libc::pid_t, raw: &HashMap<String, u64>) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let dup = dup_tracee_fd(pid, fd)?;
    let level = *raw.get("level")? as libc::c_int;
    let optname = *raw.get("optname")? as libc::c_int;
    let optval = *raw.get("optval")?;
    let optlen = *raw.get("optlen")? as libc::socklen_t;
    let buf = mem::read_bytes(pid, optval, optlen as usize)?;
    let r = unsafe { libc::setsockopt(dup, level, optname, buf.as_ptr() as *const libc::c_void, optlen) };
    let e = errno();
    unsafe { libc::close(dup) };
    Some(if r < 0 {
        EmuReply::Errno(e)
    } else {
        EmuReply::Value(0)
    })
}

fn getsockopt(pid: libc::pid_t, raw: &HashMap<String, u64>) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let dup = dup_tracee_fd(pid, fd)?;
    let level = *raw.get("level")? as libc::c_int;
    let optname = *raw.get("optname")? as libc::c_int;
    let optval = *raw.get("optval")?;
    let optlen_ptr = *raw.get("optlen")?;
    let mut optlen = read_socklen(pid, optlen_ptr)?;
    let mut buf = vec![0u8; optlen as usize];
    let r = unsafe {
        libc::getsockopt(
            dup,
            level,
            optname,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut optlen as *mut libc::socklen_t,
        )
    };
    let e = errno();
    unsafe { libc::close(dup) };
    if r < 0 {
        return Some(EmuReply::Errno(e));
    }
    buf.truncate(optlen as usize);
    if mem::write_bytes(pid, optval, &buf).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    write_socklen(pid, optlen_ptr, optlen);
    Some(EmuReply::Value(0))
}

/// bind/connect: run against the sandbox-mapped unix socket path when the
/// guest path changes under the rootfs/bind map; otherwise continue.
fn bind_or_connect(
    name: &str,
    pid: libc::pid_t,
    _args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let addr = *raw.get("buffer")?;
    let len = *raw.get("address_length")? as libc::socklen_t;
    if len == 0 {
        return None;
    }
    let bytes = mem::read_bytes(pid, addr, len as usize)?;
    let cwd = state.proc(pid).cwd.clone();
    let Some(mapped) = map_sockaddr(pid, &bytes, ctx, &cwd) else {
        return None;
    };
    // the mapped bytes are binary (family + path), so build a real
    // sockaddr_un instead of treating them as a c string.
    let path = &mapped[2..mapped.len() - 1];
    let path = std::str::from_utf8(path).ok()?;
    let plen = path.len();
    let sun_path = std::mem::size_of::<libc::sockaddr_un>() - 2;
    if plen >= sun_path {
        return Some(EmuReply::Errno(libc::ENAMETOOLONG));
    }
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, b) in path.bytes().enumerate() {
        sa.sun_path[i] = b as libc::c_char;
    }
    let socklen = (2 + plen + 1) as libc::socklen_t;
    let dup = dup_tracee_fd(pid, fd)?;
    let r = unsafe {
        if name == "bind" {
            libc::bind(dup, &sa as *const libc::sockaddr_un as *const libc::sockaddr, socklen)
        } else {
            libc::connect(dup, &sa as *const libc::sockaddr_un as *const libc::sockaddr, socklen)
        }
    };
    let e = errno();
    unsafe { libc::close(dup) };
    Some(if r < 0 {
        EmuReply::Errno(e)
    } else {
        EmuReply::Value(0)
    })
}

/// accept/accept4: run as the supervisor, rewrite the returned af_unix peer
/// address host→guest, and inject the accepted fd via addfd.
fn accept(
    pid: libc::pid_t,
    name: &str,
    raw: &HashMap<String, u64>,
    notif: &SeccompNotif,
    listener: RawFd,
    ctx: &mut paths::PathCtx,
) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let addr_ptr = *raw.get("buffer")?;
    let len_ptr = *raw.get("address_length")?;
    let mut capacity = read_socklen(pid, len_ptr)?;
    if capacity == 0 {
        capacity = 128; // zero capacity: use a buffer big enough for any sockaddr
    }
    let flags = if name == "accept4" {
        raw.get("flags").copied().unwrap_or(0) as libc::c_int
    } else {
        0
    };
    let dup = dup_tracee_fd(pid, fd)?;
    let mut buf = vec![0u8; capacity as usize];
    let mut outlen = capacity;
    let r = unsafe {
        if name == "accept4" {
            libc::accept4(
                dup,
                buf.as_mut_ptr() as *mut libc::sockaddr,
                &mut outlen as *mut libc::socklen_t,
                flags,
            )
        } else {
            libc::accept(
                dup,
                buf.as_mut_ptr() as *mut libc::sockaddr,
                &mut outlen as *mut libc::socklen_t,
            )
        }
    };
    if r < 0 {
        let e = errno();
        unsafe { libc::close(dup) };
        return Some(EmuReply::Errno(e));
    }
    unsafe { libc::close(dup) };
    let newfd = r as RawFd;

    // rewrite the peer address into the tracee's buffer.
    if addr_ptr != 0 {
        buf.truncate(outlen as usize);
        let out = unmap_sockaddr(&buf, ctx).unwrap_or(buf);
        if write_sockaddr(pid, addr_ptr, &out).is_none() {
            unsafe { libc::close(newfd) };
            return Some(EmuReply::Errno(libc::EFAULT));
        }
        write_socklen(pid, len_ptr, out.len() as libc::socklen_t);
    }
    Some(inject_fd(pid, newfd, notif, listener))
}

/// getsockname/getpeername: run as the supervisor, rewrite the returned
/// path (af_unix) host→guest, and write the result into the tracee's buffers.
fn getname(
    pid: libc::pid_t,
    name: &str,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
) -> Option<EmuReply> {
    let fd = *raw.get("fd")? as libc::c_int;
    let addr_ptr = *raw.get("buffer")?;
    let len_ptr = *raw.get("address_length")?;
    let mut capacity = read_socklen(pid, len_ptr)?;
    if capacity == 0 {
        capacity = 128; // zero capacity: use a buffer big enough for any sockaddr
    }
    let dup = dup_tracee_fd(pid, fd)?;
    let mut buf = vec![0u8; capacity as usize];
    let mut outlen = capacity;
    let r = unsafe {
        if name == "getsockname" {
            libc::getsockname(
                dup,
                buf.as_mut_ptr() as *mut libc::sockaddr,
                &mut outlen as *mut libc::socklen_t,
            )
        } else {
            libc::getpeername(
                dup,
                buf.as_mut_ptr() as *mut libc::sockaddr,
                &mut outlen as *mut libc::socklen_t,
            )
        }
    };
    if r < 0 {
        let e = errno();
        unsafe { libc::close(dup) };
        return Some(EmuReply::Errno(e));
    }
    unsafe { libc::close(dup) };
    buf.truncate(outlen as usize);
    let out = unmap_sockaddr(&buf, ctx).unwrap_or(buf);
    if write_sockaddr(pid, addr_ptr, &out).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    write_socklen(pid, len_ptr, out.len() as libc::socklen_t);
    Some(EmuReply::Value(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(path: &str) -> Vec<u8> {
        let mut v = vec![libc::AF_UNIX as u8, 0];
        v.extend_from_slice(path.as_bytes());
        v.push(0);
        v
    }

    #[test]
    fn maps_absolute_unix_path_into_rootfs() {
        let mut ctx = paths::PathCtx::new("/srv/rootfs", &[]);
        let src = unix("/tmp/x.sock");
        let got = map_sockaddr(4242, &src, &mut ctx, "/").expect("must map");
        assert_eq!(&got[2..got.len() - 1], b"/srv/rootfs/tmp/x.sock");
        let back = unmap_sockaddr(&got, &mut ctx).unwrap();
        assert_eq!(&back[2..back.len() - 1], b"/tmp/x.sock");
    }

    #[test]
    fn passes_through_relative_and_abstract_paths() {
        let mut ctx = paths::PathCtx::new("/srv/rootfs", &[]);
        // relative: resolves against the pinned cwd (inside the rootfs)
        assert!(map_sockaddr(1, &unix("rel.sock"), &mut ctx, "/").is_none());
        // abstract: kernel-namespaced, not a path
        let mut abs = unix("/tmp/x");
        abs[2] = 0; // leading nul -> abstract
        assert!(map_sockaddr(1, &abs, &mut ctx, "/").is_none());
        // non-unix families
        let inet = [libc::AF_INET as u8, 0, 0, 0];
        assert!(map_sockaddr(1, &inet, &mut ctx, "/").is_none());
    }

    #[test]
    fn honors_bind_mapping() {
        let binds = vec![("/sock".to_string(), "/host/sock".to_string())];
        let mut ctx = paths::PathCtx::new("/srv/rootfs", &binds);
        let got = map_sockaddr(1, &unix("/sock/x"), &mut ctx, "/")
            .expect("must map via bind");
        assert_eq!(&got[2..got.len() - 1], b"/host/sock/x");
    }
}
