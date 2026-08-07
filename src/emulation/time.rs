//! time syscalls: clock_gettime, clock_gettime64, gettimeofday, time.

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
        "clock_gettime" | "clock_gettime64" => clock_gettime(pid, args, raw),
        "gettimeofday" => gettimeofday(pid, raw),
        "time" => time(pid, raw),
        "clock_settime" | "clock_settime64" | "settimeofday" => {
            Some(EmuReply::Errno(libc::EPERM))
        }
        _ => None,
    }
}

fn clock_gettime(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
) -> Option<EmuReply> {
    let clock = args.get("clock").and_then(|s| s.parse::<i32>().ok())?;
    let tp = *raw.get("tp")?;
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock, &mut ts) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&ts as *const libc::timespec) as *const u8,
            std::mem::size_of::<libc::timespec>(),
        )
    };
    if mem::write_bytes(pid, tp, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}

fn gettimeofday(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
) -> Option<EmuReply> {
    let tv = *raw.get("tv")?;
    let tz = *raw.get("tz")?;
    let mut t: libc::timeval = unsafe { std::mem::zeroed() };
    if unsafe { libc::gettimeofday(&mut t, std::ptr::null_mut()) } < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&t as *const libc::timeval) as *const u8,
            std::mem::size_of::<libc::timeval>(),
        )
    };
    if mem::write_bytes(pid, tv, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    if tz != 0 {
        // struct timezone { int tz_minuteswest; int tz_dsttime; }: the kernel
        // leaves it unchanged; present it zeroed.
        if mem::write_bytes(pid, tz, &[0u8; 8]).is_none() {
            return Some(EmuReply::Errno(libc::EFAULT));
        }
    }
    Some(EmuReply::Value(0))
}

fn time(pid: libc::pid_t, raw: &HashMap<String, u64>) -> Option<EmuReply> {
    let tloc = *raw.get("tloc")?;
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    if now < 0 {
        return Some(EmuReply::Errno(errno()));
    }
    if tloc != 0 {
        let bytes = now.to_ne_bytes();
        if mem::write_bytes(pid, tloc, &bytes).is_none() {
            return Some(EmuReply::Errno(libc::EFAULT));
        }
    }
    Some(EmuReply::Value(now))
}
