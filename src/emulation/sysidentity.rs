
use crate::emulation::EmuReply;
use crate::runtime::mem;
use crate::runtime::seccomp::SeccompNotif;
use std::collections::HashMap;

/// uname: run as the supervisor and copy the utsname into the tracee's
/// buffer. the sandbox reports the host's utsname for now.
pub fn uname(
    _notif: &SeccompNotif,
    raw: &HashMap<String, u64>,
    pid: libc::pid_t,
) -> Option<EmuReply> {
    let buf = *raw.get("buffer")?;

    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } < 0 {
        return Some(EmuReply::Errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-1),
        ));
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&uts as *const libc::utsname) as *const u8,
            std::mem::size_of::<libc::utsname>(),
        )
    };
    if mem::write_bytes(pid, buf, bytes).is_none() {
        return Some(EmuReply::Errno(libc::EFAULT));
    }
    Some(EmuReply::Value(0))
}
