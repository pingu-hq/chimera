//! per-sandbox runtime state shared by all emulation categories.

use std::collections::HashMap;

pub const XATTR_META: &str = "user.chimera.meta";
pub const XATTR_META_VERSION: u64 = 1;

/// identity of a sandbox process, mirroring the kernel's uid/euid/suid model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
}

impl Default for Identity {
    fn default() -> Self {
        Self::root()
    }
}

impl Identity {
    /// chimera boots as root: every id is 0.
    pub fn root() -> Self {
        Self {
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
        }
    }

    pub fn setuid(&mut self, uid: u32) {
        self.suid = self.euid;
        self.uid = uid;
        self.euid = uid;
    }

    pub fn setgid(&mut self, gid: u32) {
        self.sgid = self.egid;
        self.gid = gid;
        self.egid = gid;
    }

    pub fn seteuid(&mut self, euid: u32) {
        self.euid = euid;
    }

    pub fn setegid(&mut self, egid: u32) {
        self.egid = egid;
    }

    pub fn setresuid(&mut self, ruid: u32, euid: u32, suid: u32) {
        self.uid = ruid;
        self.euid = euid;
        self.suid = suid;
    }

    pub fn setresgid(&mut self, rgid: u32, egid: u32, sgid: u32) {
        self.gid = rgid;
        self.egid = egid;
        self.sgid = sgid;
    }
}

/// effective/permitted/inheritable capability sets as 64-bit masks (the v3
/// `capget`/`capset` data layout splits each into two 32-bit words on-disk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

impl Caps {
    /// boot state for the root identity: every capability up to the kernel's
    /// cap_last_cap is permitted and effective; nothing inheritable.
    pub fn root() -> Self {
        const CAP_LAST_CAP: u32 = 40;
        let full = (1u64 << (CAP_LAST_CAP + 1)) - 1;
        Self {
            effective: full,
            permitted: full,
            inheritable: 0,
        }
    }

    pub fn empty() -> Self {
        Self {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }
    }
}

/// per-process mutable sandbox view: identity, groups, virtual cwd.
#[derive(Debug, Clone)]
pub struct ProcessState {
    pub ident: Identity,
    /// supplementary group list recorded by emulated setgroups(2).
    pub groups: Vec<u32>,
    /// capability sets recorded by emulated capset(2); answer capget(2).
    pub caps: Caps,
    /// virtual working directory, guest-absolute (starts with `/`).
    pub cwd: String,
    /// guest path of the most recent emulated execve, so `/proc/self/exe`
    /// (and friends) answer with a guest path instead of the host shim copy.
    pub exe: String,
}

impl ProcessState {
    pub fn root() -> Self {
        Self {
            ident: Identity::root(),
            groups: Vec::new(),
            caps: Caps::root(),
            cwd: "/".to_string(),
            exe: String::new(),
        }
    }
}

impl Default for ProcessState {
    fn default() -> Self {
        Self::root()
    }
}

/// parsed `user.chimera.meta` xattr payload:
/// `{"version":1,"uid":0,"gid":0,"mode":493}` (mode is a raw permission bitset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaPerms {
    pub version: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl MetaPerms {
    /// serialize into the canonical `user.chimera.meta` payload.
    pub fn to_xattr(&self) -> Vec<u8> {
        format!(
            r#"{{"version":{},"uid":{},"gid":{},"mode":{}}}"#,
            self.version, self.uid, self.gid, self.mode
        )
        .into_bytes()
    }

    /// parse a `user.chimera.meta` payload back into [`metaperms`].
    pub fn from_xattr(data: &[u8]) -> Option<Self> {
        let version = json_field(data, "version")?;
        let uid = json_field(data, "uid")? as u32;
        let gid = json_field(data, "gid")? as u32;
        let mode = json_field(data, "mode")? as u32;
        Some(MetaPerms {
            version,
            uid,
            gid,
            mode,
        })
    }
}

/// read the integer value of a `"key":123` field from the fixed-shape payload.
fn json_field(data: &[u8], key: &str) -> Option<u64> {
    let s = std::str::from_utf8(data).ok()?;
    let needle = format!("\"{key}\":");
    let mut rest = s.get(s.find(&needle)? + needle.len()..)?;
    rest = rest.trim_start();
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_perms_round_trip() {
        let p = MetaPerms {
            version: 1,
            uid: 0,
            gid: 0,
            mode: 0o755,
        };
        assert_eq!(p.to_xattr(), br#"{"version":1,"uid":0,"gid":0,"mode":493}"#);
        assert_eq!(MetaPerms::from_xattr(&p.to_xattr()), Some(p));
    }

    #[test]
    fn meta_perms_parses_non_root() {
        let p = MetaPerms::from_xattr(br#"{"version":1,"uid":1000,"gid":1000,"mode":420}"#);
        assert_eq!(
            p,
            Some(MetaPerms {
                version: 1,
                uid: 1000,
                gid: 1000,
                mode: 0o644,
            })
        );
    }

    #[test]
    fn meta_perms_rejects_garbage() {
        assert_eq!(MetaPerms::from_xattr(b"not json"), None);
        assert_eq!(MetaPerms::from_xattr(br#"{"version":1,"uid":"x"}"#), None);
        assert_eq!(MetaPerms::from_xattr(b""), None);
    }

    #[test]
    fn process_inherits_from_parent() {
        let mut s = SandboxState::new();
        s.ensure(1);
        s.proc_mut(1).ident.setuid(42);
        s.proc_mut(1).cwd = "/tmp".into();
        // simulate a child that already inherited (ensure_inherited would do
        // the same via /proc ppid when the child really exists).
        let child = s.proc(1).clone();
        // force-insert via ensure then overwrite
        s.ensure(2);
        *s.proc_mut(2) = child;
        assert_eq!(s.proc(2).ident.uid, 42);
        assert_eq!(s.proc(2).cwd, "/tmp");
        s.proc_mut(2).ident.setuid(7);
        assert_eq!(s.proc(1).ident.uid, 42);
        assert_eq!(s.proc(2).ident.uid, 7);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermAccess {
    Read,
    Write,
    Execute,
}

/// the mutable sandbox state threaded through the supervisor loop.
#[derive(Debug, Clone)]
pub struct SandboxState {
    /// true when the bootup probe confirmed the rootfs round-trips `user.*`
    /// xattrs, i.e. `user.chimera.meta` permission handling is in effect.
    pub xattr_perms: bool,
    /// cached `chimera_debug_exec` flag: emulation reads it per-syscall, so
    /// cache it here instead of walking the environment every notification.
    pub debug: bool,
    /// per-pid identity / cwd / groups. lazily populated: unknown pids inherit
    /// from their `/proc/<pid>/status` ppid when present, else boot as root.
    processes: HashMap<libc::pid_t, ProcessState>,
    /// directory stream positions served by the getdents emulation. the
    dir_offsets: HashMap<(libc::pid_t, i32), (u64, u64, i64)>,
}

impl SandboxState {
    /// current directory-stream identity/offset for a tracee fd, or none when
    /// untracked.
    pub fn dir_stream(&self, pid: libc::pid_t, fd: i32) -> Option<(u64, u64, i64)> {
        self.dir_offsets.get(&(pid, fd)).copied()
    }

    /// record the directory-stream (dev, ino, offset) for a tracee fd.
    pub fn set_dir_stream(&mut self, pid: libc::pid_t, fd: i32, dev: u64, ino: u64, off: i64) {
        self.dir_offsets.insert((pid, fd), (dev, ino, off));
    }

    /// forget a directory-stream (guest closed/replaced the fd).
    pub fn clear_dir_stream(&mut self, pid: libc::pid_t, fd: i32) {
        self.dir_offsets.remove(&(pid, fd));
    }
}

impl SandboxState {
    pub fn new() -> Self {
        Self {
            xattr_perms: false,
            debug: std::env::var("CHIMERA_DEBUG_EXEC").is_ok(),
            processes: HashMap::new(),
            dir_offsets: HashMap::new(),
        }
    }

    /// seed the initial chi process as root at `/`.
    pub fn ensure(&mut self, pid: libc::pid_t) {
        self.processes
            .entry(pid)
            .or_insert_with(ProcessState::root);
    }

    pub fn proc(&mut self, pid: libc::pid_t) -> &ProcessState {
        self.ensure_inherited(pid);
        self.processes.get(&pid).unwrap()
    }

    pub fn proc_mut(&mut self, pid: libc::pid_t) -> &mut ProcessState {
        self.ensure_inherited(pid);
        self.processes.get_mut(&pid).unwrap()
    }

    pub fn remove(&mut self, pid: libc::pid_t) {
        self.processes.remove(&pid);
    }

    fn ensure_inherited(&mut self, pid: libc::pid_t) {
        if self.processes.contains_key(&pid) {
            return;
        }
        let inherited = read_ppid(pid)
            .and_then(|ppid| self.processes.get(&ppid).cloned())
            .unwrap_or_else(ProcessState::root);
        self.processes.insert(pid, inherited);
    }
}

impl Default for SandboxState {
    fn default() -> Self {
        Self::new()
    }
}

fn read_ppid(pid: libc::pid_t) -> Option<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}
