use std::os::unix::io::AsRawFd;

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
}

pub fn parse_maps(pid: libc::pid_t) -> Vec<Region> {
    let Ok(contents) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    let mut regions = Vec::new();
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        let Some(range) = it.next() else { continue };
        let Some((start, end)) = range.split_once('-') else { continue };
        let Some(perms) = it.next() else { continue };
        let start = u64::from_str_radix(start, 16).unwrap_or(0);
        let end = u64::from_str_radix(end, 16).unwrap_or(0);
        regions.push(Region {
            start,
            end,
            readable: perms.starts_with('r'),
            writable: perms.as_bytes().get(1) == Some(&b'w'),
        });
    }
    regions
}

fn vm_read(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> isize {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) }
}

fn vm_write(pid: libc::pid_t, addr: u64, buf: &[u8]) -> isize {
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) }
}

/// fallback reads via `/proc/<pid>/mem` + pread, used when process_vm_readv is
/// unavailable or refused (seccomp/ptrace policy on the host).
fn mem_read_fd(pid: libc::pid_t, addr: u64, buf: &mut [u8]) -> isize {
    let fd = match std::fs::OpenOptions::new()
        .read(true)
        .open(format!("/proc/{pid}/mem"))
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    unsafe {
        libc::pread(
            fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            addr as libc::off_t,
        )
    }
}

/// fallback writes via `/proc/<pid>/mem` + pwrite.
fn mem_write_fd(pid: libc::pid_t, addr: u64, buf: &[u8]) -> isize {
    let fd = match std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/mem"))
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    unsafe {
        libc::pwrite(
            fd.as_raw_fd(),
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            addr as libc::off_t,
        )
    }
}

/// read a nul-terminated c string from the tracee. `max` bounds the read
/// (including the nul). a short read at the end of a mapping returns the bytes
/// copied so far, matching the old region-clamped behaviour.
pub fn read_cstring(pid: libc::pid_t, addr: u64, max: usize) -> Option<String> {
    if addr == 0 || max == 0 {
        return None;
    }
    let mut buf = vec![0u8; max];
    let mut n = vm_read(pid, addr, &mut buf);
    if n <= 0 {
        n = mem_read_fd(pid, addr, &mut buf);
    }
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

pub fn find_region<'a>(regions: &'a [Region], addr: u64) -> Option<&'a Region> {
    regions.iter().find(|r| r.start <= addr && addr < r.end)
}

pub fn read_string(pid: libc::pid_t, addr: u64) -> Option<String> {
    read_cstring(pid, addr, 4096)
}

/// read a null-terminated array of u64 pointers from the tracee's memory
/// (e.g. the execve argv/envp arrays). returns `none` when the terminator is
/// not found within a readable region (or the read fails).
pub fn read_ptrs(pid: libc::pid_t, addr: u64) -> Option<Vec<u64>> {
    if addr == 0 {
        return None;
    }
    let mut out = Vec::new();
    // cap the pointer array length; anything longer is rejected.
    for i in 0..512 {
        let off = addr + i * 8;
        let mut v = [0u8; 8];
        let mut n = vm_read(pid, off, &mut v);
        if n <= 0 {
            n = mem_read_fd(pid, off, &mut v);
        }
        if n != 8 {
            return None;
        }
        let v = u64::from_le_bytes(v);
        out.push(v);
        if v == 0 {
            return Some(out);
        }
    }
    None
}

/// read `len` raw bytes from the tracee's memory at `addr`.
///
/// requires a full read (`n == len`); use [`read_cstring`] when the mapping
/// may end before `len` bytes.
pub fn read_bytes(pid: libc::pid_t, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if len == 0 {
        return Some(buf);
    }
    let mut n = vm_read(pid, addr, &mut buf);
    if n <= 0 {
        n = mem_read_fd(pid, addr, &mut buf);
    }
    if n == len as isize {
        Some(buf)
    } else {
        None
    }
}

/// write bytes into the tracee's memory at `addr` (e.g. syscall output
/// buffers) via process_vm_writev, falling back to `/proc/<pid>/mem`.
pub fn write_bytes(pid: libc::pid_t, addr: u64, buf: &[u8]) -> Option<()> {
    if buf.is_empty() {
        return Some(());
    }
    if vm_write(pid, addr, buf) == buf.len() as isize {
        return Some(());
    }
    if mem_write_fd(pid, addr, buf) == buf.len() as isize {
        Some(())
    } else {
        None
    }
}
