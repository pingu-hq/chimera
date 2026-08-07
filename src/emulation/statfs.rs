//! filesystem information syscalls: statfs, statfs64, fstatfs, fstatfs64.
//!
//! glibc's `statvfs(3)` is implemented on top of the `statfs` syscall, so
//! apt's free-space check needs this path mapped through the rootfs.

use crate::emulation::paths;
use crate::emulation::state::SandboxState;
use crate::emulation::EmuReply;
use crate::runtime::mem;
use std::collections::HashMap;

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
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    match name {
        "statfs" | "statfs64" => statfs(pid, args, raw, ctx, state),
        "fstatfs" | "fstatfs64" => fstatfs(pid, args, raw),
        _ => None,
    }
}

fn statfs(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let cwd = state.proc(pid).cwd.clone();
    let host = ctx.map_host(pid, args.get("path")?, &cwd);
    let cpath = paths::cstr(&host)?;
    let buf_addr = *raw.get("buffer")?;

    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(cpath.as_ptr(), &mut st) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    write_statfs(pid, buf_addr, &st)
}

fn fstatfs(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
) -> Option<EmuReply> {
    let fd = args.get("fd")?.parse::<i32>().ok()?;
    let host = paths::fd_host_path(pid, fd)?;
    let cpath = paths::cstr(&host)?;
    let buf_addr = *raw.get("buffer")?;

    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(cpath.as_ptr(), &mut st) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    write_statfs(pid, buf_addr, &st)
}

fn write_statfs(pid: libc::pid_t, addr: u64, st: &libc::statfs) -> Option<EmuReply> {
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (st as *const libc::statfs) as *const u8,
            std::mem::size_of::<libc::statfs>(),
        )
    };
    if mem::write_bytes(pid, addr, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}
