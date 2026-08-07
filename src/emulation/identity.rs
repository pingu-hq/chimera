//! identity syscalls: get/set uid/gid families and get/setgroups.
//!
//! updates apply to the *calling* process's [`processstate`] only - children
//! that later drop privileges (apt → `_apt`) must not rewrite the shell.

use crate::emulation::state::SandboxState;
use crate::emulation::EmuReply;
use crate::runtime::mem;

pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    args: &[u64; 6],
    state: &mut SandboxState,
) -> Option<EmuReply> {
    if apply(pid, name, args, state) {
        return Some(EmuReply::Value(0));
    }
    match name {
        "getgroups" => getgroups(pid, args, state),
        "setgroups" => setgroups(pid, args, state),
        _ => read(pid, name, args, state),
    }
}

fn setgroups(pid: libc::pid_t, args: &[u64; 6], state: &mut SandboxState) -> Option<EmuReply> {
    let count = args[0] as usize;
    if count == 0 {
        state.proc_mut(pid).groups.clear();
        return Some(EmuReply::Value(0));
    }
    let ptr = args[1];
    if ptr == 0 {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    let bytes = match mem::read_bytes(pid, ptr, count.checked_mul(4)?) {
        Some(b) => b,
        None => return Some(EmuReply::Errno(libc::EFAULT)),
    };
    state.proc_mut(pid).groups = bytes
        .chunks_exact(4)
        .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Some(EmuReply::Value(0))
}

fn getgroups(pid: libc::pid_t, args: &[u64; 6], state: &mut SandboxState) -> Option<EmuReply> {
    let count = args[0] as usize;
    let list = state.proc(pid).groups.clone();
    if count == 0 {
        return Some(EmuReply::Value(list.len() as i64));
    }
    if count < list.len() {
        return Some(EmuReply::Errno(libc::EINVAL));
    }
    let ptr = args[1];
    if ptr == 0 {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    for (i, g) in list.iter().enumerate() {
        if mem::write_bytes(pid, ptr + (i as u64) * 4, &g.to_ne_bytes()).is_none() {
            return Some(EmuReply::Errno(libc::EFAULT));
        }
    }
    Some(EmuReply::Value(list.len() as i64))
}

fn read(pid: libc::pid_t, name: &str, args: &[u64; 6], state: &mut SandboxState) -> Option<EmuReply> {
    let i = state.proc(pid).ident;
    match name {
        "getuid" => Some(EmuReply::Value(i.uid as i64)),
        "geteuid" => Some(EmuReply::Value(i.euid as i64)),
        "getgid" => Some(EmuReply::Value(i.gid as i64)),
        "getegid" => Some(EmuReply::Value(i.egid as i64)),
        "getresuid" => {
            write_u32(pid, args[0], i.uid)?;
            write_u32(pid, args[1], i.euid)?;
            write_u32(pid, args[2], i.suid)?;
            Some(EmuReply::Value(0))
        }
        "getresgid" => {
            write_u32(pid, args[0], i.gid)?;
            write_u32(pid, args[1], i.egid)?;
            write_u32(pid, args[2], i.sgid)?;
            Some(EmuReply::Value(0))
        }
        _ => None,
    }
}

fn apply(pid: libc::pid_t, name: &str, args: &[u64; 6], state: &mut SandboxState) -> bool {
    let id = &mut state.proc_mut(pid).ident;
    match name {
        "setuid" => {
            id.setuid(args[0] as u32);
            true
        }
        "seteuid" => {
            id.seteuid(args[0] as u32);
            true
        }
        "setgid" => {
            id.setgid(args[0] as u32);
            true
        }
        "setegid" => {
            id.setegid(args[0] as u32);
            true
        }
        "setreuid" => {
            let r = args[0] as u32;
            let e = args[1] as u32;
            if r != u32::MAX {
                id.uid = r;
            }
            if e != u32::MAX {
                id.euid = e;
            }
            true
        }
        "setregid" => {
            let r = args[0] as u32;
            let e = args[1] as u32;
            if r != u32::MAX {
                id.gid = r;
            }
            if e != u32::MAX {
                id.egid = e;
            }
            true
        }
        "setresuid" => {
            let (r, e, s) = (args[0] as u32, args[1] as u32, args[2] as u32);
            id.setresuid(
                if r == u32::MAX { id.uid } else { r },
                if e == u32::MAX { id.euid } else { e },
                if s == u32::MAX { id.suid } else { s },
            );
            true
        }
        "setresgid" => {
            let (r, e, s) = (args[0] as u32, args[1] as u32, args[2] as u32);
            id.setresgid(
                if r == u32::MAX { id.gid } else { r },
                if e == u32::MAX { id.egid } else { e },
                if s == u32::MAX { id.sgid } else { s },
            );
            true
        }
        _ => false,
    }
}

fn write_u32(pid: libc::pid_t, addr: u64, v: u32) -> Option<()> {
    if addr == 0 {
        return None;
    }
    mem::write_bytes(pid, addr, &v.to_ne_bytes())
}
