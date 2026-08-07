//! capability syscalls: capget, capset.

use crate::emulation::state::{Caps, SandboxState};
use crate::emulation::EmuReply;
use crate::runtime::mem;
use std::collections::HashMap;

/// the capability-set version glibc and the kernel use today (v3, 64-bit).
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`: version + target pid (0 = self).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// `struct __user_cap_data_struct` (one 32-bit half-word of a capability set).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CapData32 {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn dispatch(
    pid: libc::pid_t,
    name: &str,
    raw: &HashMap<String, u64>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    match name {
        "capget" => capget(pid, raw, state),
        "capset" => capset(pid, raw, state),
        _ => None,
    }
}

fn capget(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let hdrp = *raw.get("hdrp")?;
    let datap = *raw.get("datap")?;
    let mut hdr: CapHeader = read_struct(pid, hdrp)?;
    if hdr.version != LINUX_CAPABILITY_VERSION_3 {
        // mirror the kernel: report the accepted version and fail einval so
        // glibc's capability library retries with the returned version.
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if write_struct(pid, hdrp, &hdr).is_none() {
            return Some(EmuReply::Errno(libc::EFAULT));
        }
        return Some(EmuReply::Errno(libc::EINVAL));
    }
    let target = if hdr.pid != 0 {
        hdr.pid as libc::pid_t
    } else {
        pid
    };
    let c = state.proc(target).caps;
    // the v3 layout: `datap` is two __user_cap_data_struct; element 0 holds the
    // low 32 bits of each set, element 1 the high 32 bits.
    let data = [
        CapData32 {
            effective: c.effective as u32,
            permitted: c.permitted as u32,
            inheritable: c.inheritable as u32,
        },
        CapData32 {
            effective: (c.effective >> 32) as u32,
            permitted: (c.permitted >> 32) as u32,
            inheritable: (c.inheritable >> 32) as u32,
        },
    ];
    if write_struct(pid, datap, &data).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}

fn capset(
    pid: libc::pid_t,
    raw: &HashMap<String, u64>,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let hdrp = *raw.get("hdrp")?;
    let datap = *raw.get("datap")?;
    let mut hdr: CapHeader = read_struct(pid, hdrp)?;
    if hdr.version != LINUX_CAPABILITY_VERSION_3 {
        hdr.version = LINUX_CAPABILITY_VERSION_3;
        if write_struct(pid, hdrp, &hdr).is_none() {
            return Some(EmuReply::Errno(libc::EFAULT));
        }
        return Some(EmuReply::Errno(libc::EINVAL));
    }
    let words: [CapData32; 2] = read_struct(pid, datap)?;
    let caps = Caps {
        effective: combine64(words[0].effective, words[1].effective),
        permitted: combine64(words[0].permitted, words[1].permitted),
        inheritable: combine64(words[0].inheritable, words[1].inheritable),
    };
    let target = if hdr.pid != 0 {
        hdr.pid as libc::pid_t
    } else {
        pid
    };
    state.proc_mut(target).caps = caps;
    Some(EmuReply::Value(0))
}

fn combine64(lo: u32, hi: u32) -> u64 {
    (lo as u64) | ((hi as u64) << 32)
}

fn read_struct<T: Copy + Default>(pid: libc::pid_t, addr: u64) -> Option<T> {
    let bytes = mem::read_bytes(pid, addr, std::mem::size_of::<T>())?;
    if bytes.len() != std::mem::size_of::<T>() {
        return None;
    }
    let mut t = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut t as *mut T as *mut u8,
            bytes.len(),
        );
    }
    Some(t)
}

fn write_struct<T: Copy>(pid: libc::pid_t, addr: u64, t: &T) -> Option<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts((t as *const T) as *const u8, std::mem::size_of::<T>())
    };
    mem::write_bytes(pid, addr, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(map: &[(&str, u64)]) -> HashMap<String, u64> {
        map.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn capget_boots_with_full_set() {
        let mut state = SandboxState::new();
        state.ensure(42);
        assert_eq!(state.proc(42).caps, Caps::root());
        assert_ne!(Caps::root().effective, 0);
        assert_eq!(Caps::root().inheritable, 0);
    }

    #[test]
    fn low_high_word_layout_round_trips() {
        let v: u64 = 0x0123_4567_89ab_cdef;
        assert_eq!(combine64(v as u32, (v >> 32) as u32), v);
        assert_eq!(combine64(0, 0), 0);
        assert_eq!(combine64(0xffff_ffff, 0xffff_ffff), u64::MAX);
    }
}
