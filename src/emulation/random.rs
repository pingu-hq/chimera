//! random / personality syscalls: getrandom, personality, arch_prctl.

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
    rootfs: &str,
    binds: &[(String, String)],
    state: &mut SandboxState,
) -> Option<EmuReply> {
    match name {
        "getrandom" => getrandom(pid, args, raw),
        _ => None,
    }
}

fn getrandom(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
) -> Option<EmuReply> {
    let buf = *raw.get("buffer")?;
    let length = raw.get("length").copied().unwrap_or(0) as usize;
    let flags = args.get("flags").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    if length == 0 {
        return Some(EmuReply::Value(0));
    }
    let mut out = vec![0u8; length];
    let n = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            out.as_mut_ptr() as *mut libc::c_void,
            length,
            flags,
        )
    };
    if n < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    let n = n as usize;
    if mem::write_bytes(pid, buf, &out[..n]).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(n as i64))
}
