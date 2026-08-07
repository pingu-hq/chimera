
use crate::emulation::state::SandboxState;
use crate::emulation::EmuReply;
use std::collections::HashMap;

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
        "getpid" | "gettid" => Some(EmuReply::Value(pid as i64)),
        "getppid" => getppid(pid),
        _ => None,
    }
}

fn getppid(pid: libc::pid_t) -> Option<EmuReply> {
    // real parent: /proc/<pid>/status ppid, same host pid namespace.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok().map(|p| EmuReply::Value(p));
        }
    }
    Some(EmuReply::Errno(libc::ESRCH))
}
