use crate::arch::ArchTable;
use crate::embroider::chmp::{Handle, Override, Policy, Statement};
use crate::emulation::{self, EmuReply};
use crate::runtime::exec::{self, Decision, Outcome};
use crate::runtime::mem;
use crate::runtime::seccomp::{self, SeccompNotif, SeccompNotifResp};
use std::collections::{HashMap, HashSet};
use std::os::unix::io::RawFd;

/// per-supervision lookup tables built once from the policy so the per-syscall
/// path never scans `policy.overrides` / `policy.handles` linearly.
struct PolicyIndex<'a> {
    /// syscall name -> override body
    overrides: HashMap<&'a str, &'a Override>,
    /// group name -> handle body
    handles: HashMap<&'a str, &'a Handle>,
    /// syscall name -> group names it belongs to
    memberships: HashMap<String, Vec<&'a str>>,
}

impl<'a> PolicyIndex<'a> {
    /// `arch` canonicalizes policy syscall names (e.g. `open` -> `openat` on
    /// arm64) so bodies keyed on the legacy x86_64 names match the native
    /// syscall names the supervisor sees in notifications.
    fn build(policy: &'a Policy, arch: &ArchTable) -> Self {
        let mut overrides = HashMap::with_capacity(policy.overrides.len());
        for o in &policy.overrides {
            overrides.insert(arch.canonical_name(&o.name), o);
        }
        let mut handles = HashMap::with_capacity(policy.handles.len());
        for h in &policy.handles {
            handles.insert(h.group.as_str(), h);
        }
        let mut memberships: HashMap<String, Vec<&'a str>> = HashMap::new();
        for g in &policy.groups {
            for s in &g.syscalls {
                let c = arch.canonical_name(s);
                let groups = memberships.entry(c.to_string()).or_default();
                if !groups.contains(&g.name.as_str()) {
                    groups.push(g.name.as_str());
                }
            }
        }
        Self {
            overrides,
            handles,
            memberships,
        }
    }

    /// true when some policy body (an override or a handle on a group this
    /// syscall belongs to) may run for this syscall.
    fn policy_relevant(&self, name: &str) -> bool {
        self.overrides.contains_key(name)
            || self
                .memberships
                .get(name)
                .is_some_and(|gs| gs.iter().any(|g| self.handles.contains_key(*g)))
    }
}

pub fn supervise(
    policy: &Policy,
    rootfs: &str,
    arch: &ArchTable,
    syscall_args: &HashMap<String, Vec<String>>,
    listener: RawFd,
    child: libc::pid_t,
    xattr_perms: bool,
) -> i32 {
    let mut state = emulation::state::SandboxState::new();
    state.xattr_perms = xattr_perms;
    // seed the chi process as root@/; children inherit on first sight.
    state.ensure(child);
    let debug = state.debug;
    let index = PolicyIndex::build(policy, arch);
    // `name` borrows from `arch.nr_to_name` for the whole loop, so warned keys
    // are stable `&str`s (no per-syscall string allocation).
    let mut warned: HashSet<&str> = HashSet::new();
    let mut exe_printed = false;

    // the notif_recv ioctl blocks by default; make it non-blocking so the drain loop can
    // tell "queue empty" (eagain -> back to poll) from "task died" (enoent).
    unsafe {
        let fl = libc::fcntl(listener, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(listener, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }

    let binds: Vec<(String, String)> = policy
        .on_startup
        .iter()
        .filter_map(|s| match s {
            Statement::Bind(src, dst) => Some((src.clone(), dst.clone())),
            _ => None,
        })
        .collect();
    let mut ctx = emulation::paths::PathCtx::new(rootfs, &binds);

    loop {
        // check for child exit once per batch.
        let mut status: i32 = 0;
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == child {
            if libc::WIFEXITED(status) {
                if state.debug {
                    eprintln!(
                        "{} child {child} exited with {} (raw {status})",
                        crate::log::tag("chimera"),
                        libc::WEXITSTATUS(status)
                    );
                }
                return libc::WEXITSTATUS(status);
            }
            if libc::WIFSIGNALED(status) {
                eprintln!(
                    "{} child killed by signal {}",
                    crate::log::tag("chimera"),
                    libc::WTERMSIG(status)
                );
                return 128 + libc::WTERMSIG(status);
            }
        }
        if r < 0 {
            return 1;
        }

        let mut pfd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
        if pr == 0 {
            continue;
        }
        if pr < 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }

        // batch: drain every notification that is already pending before going
        let mut batch = 0;
        loop {
            let mut notif = SeccompNotif {
                id: 0,
                pid: 0,
                flags: 0,
                data: unsafe { std::mem::zeroed() },
            };
            if let Err(e) = seccomp::notif_recv(listener, &mut notif) {
                if e == libc::EAGAIN {
                    break;
                }
                if e == libc::ENOENT || e == libc::ENOLINK || e == libc::EINVAL {
                    // the notifying task died and its pending notifications
                    break;
                }
                eprintln!("{} notif_recv: errno {e}", crate::log::tag("chimera"));
                break;
            }

            let resp = handle_notification(
                &index,
                &notif,
                arch,
                syscall_args,
                listener,
                &mut ctx,
                &mut state,
                &mut warned,
                &mut exe_printed,
                debug,
            );
            let _ = seccomp::notif_send(listener, &resp);
            batch += 1;
            // safety cap: a notification flood must not starve the exit check.
            if batch >= 4096 {
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_notification<'a>(
    index: &PolicyIndex<'a>,
    notif: &SeccompNotif,
    arch: &'a ArchTable,
    syscall_args: &HashMap<String, Vec<String>>,
    listener: RawFd,
    ctx: &mut emulation::paths::PathCtx,
    state: &mut emulation::state::SandboxState,
    warned: &mut HashSet<&'a str>,
    exe_printed: &mut bool,
    debug: bool,
) -> SeccompNotifResp {
    let name = match arch.nr_to_name.get(&notif.data.nr) {
        Some(n) => n.as_str(),
        None => return continue_resp(notif.id),
    };
    let pid = notif.pid as libc::pid_t;

    if !*exe_printed {
        eprintln!(
            "{} tracee exe (first notif): {}",
            crate::log::tag("chimera"),
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<gone>".into())
        );
        *exe_printed = true;
    }

    if debug {
        eprintln!("{} trace pid={pid} syscall={name}", crate::log::tag("trace"));
    }

    let emulated = emulation::is_emulated(name);
    let relevant = index.policy_relevant(name);

    // fast path: a syscall with no policy body and no emulation is left to the
    // kernel untouched. skip arg maps, scope setup, and policy evaluation.
    if !relevant && !emulated {
        return continue_resp(notif.id);
    }

    let cwd = state.proc(pid).cwd.clone();
    let (args, raw) = build_arg_maps(name, notif, syscall_args, pid);

    // run policy bodies only when one can match; otherwise args are already
    // the merged map (nothing was modified).
    let (outcome, emu_args) = if relevant {
        let mut scope = exec::Scope {
            args: &args,
            root: ctx.rootfs(),
            cwd: &cwd,
            binds: ctx.binds(),
            locals: HashMap::new(),
        };
        let mut outcome = Outcome::default();
        if let Some(o) = index.overrides.get(name) {
            let o = exec::run_body(&o.body, &mut scope);
            outcome.decision = outcome.decision.or(o.decision);
            outcome.modified.extend(o.modified);
        }
        if let Some(gs) = index.memberships.get(name) {
            for gname in gs {
                if let Some(h) = index.handles.get(*gname) {
                    let o = exec::run_body(&h.body, &mut scope);
                    outcome.decision = outcome.decision.or(o.decision);
                    outcome.modified.extend(o.modified);
                }
            }
        }
        let emu_args = if outcome.modified.is_empty() {
            args
        } else {
            let mut merged = args;
            for (k, v) in &outcome.modified {
                merged.insert(k.clone(), v.clone());
            }
            merged
        };
        (outcome, emu_args)
    } else {
        (Outcome::default(), args)
    };

    match &outcome.decision {
        Some(Decision::Deny(err)) => deny_resp(notif.id, *err),
        Some(Decision::Respond(v)) => value_resp(notif.id, *v),
        _ => {
            if emulated {
                match emulation::dispatch(
                    pid,
                    name,
                    notif,
                    &emu_args,
                    &raw,
                    !outcome.modified.is_empty(),
                    listener,
                    ctx,
                    state,
                ) {
                    Some(EmuReply::Value(v)) => value_resp(notif.id, v),
                    Some(EmuReply::Errno(e)) => errno_resp(notif.id, e),
                    Some(EmuReply::Continue) => continue_resp(notif.id),
                    None => {
                        if !outcome.modified.is_empty() && warned.insert(name) {
                            eprintln!(
                                "{} warn: syscall '{name}' was modified by the policy but has no emulation; continuing with original args",
                                crate::log::tag("chimera")
                            );
                        }
                        continue_resp(notif.id)
                    }
                }
            } else if !outcome.modified.is_empty() && warned.insert(name) {
                eprintln!(
                    "{} warn: syscall '{name}' was modified by the policy but has no emulation; continuing with original args",
                    crate::log::tag("chimera")
                );
                continue_resp(notif.id)
            } else {
                continue_resp(notif.id)
            }
        }
    }
}

/// build the arg-name -> string-value and arg-name -> raw-u64 maps for a
/// trapped syscall. reads the tracee's strings via process_vm_readv (no
/// /proc/<pid>/maps parsing, no per-read fd).
fn build_arg_maps(
    name: &str,
    notif: &SeccompNotif,
    syscall_args: &HashMap<String, Vec<String>>,
    pid: libc::pid_t,
) -> (HashMap<String, String>, HashMap<String, u64>) {
    let Some(names) = syscall_args.get(name) else {
        return (HashMap::new(), HashMap::new());
    };
    let mut args = HashMap::with_capacity(names.len());
    let mut raw = HashMap::with_capacity(names.len());
    for (i, an) in names.iter().enumerate() {
        let Some(&v) = notif.data.args.get(i) else { break };
        let value = mem::read_string(pid, v).unwrap_or_else(|| v.to_string());
        args.insert(an.clone(), value);
        raw.insert(an.clone(), v);
    }
    (args, raw)
}

fn continue_resp(id: u64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: seccomp::SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    }
}

fn value_resp(id: u64, val: i64) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val,
        error: 0,
        flags: 0,
    }
}

fn errno_resp(id: u64, err: i32) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: -err,
        flags: 0,
    }
}

fn deny_resp(id: u64, err: i32) -> SeccompNotifResp {
    SeccompNotifResp {
        id,
        val: 0,
        error: -err,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embroider::chmp::{Group, Handle, Override};

    #[test]
    fn policy_index_finds_overrides_and_handled_groups() {
        let mut p = Policy::default();
        p.groups.push(Group {
            name: "files".into(),
            syscalls: vec!["open".into(), "read".into()],
            includes: vec![],
        });
        p.handles.push(Handle {
            group: "files".into(),
            body: vec![],
        });
        p.overrides.push(Override {
            name: "openat".into(),
            body: vec![],
        });
        let idx = PolicyIndex::build(&p, &test_arch());
        assert!(idx.policy_relevant("open"));
        assert!(idx.policy_relevant("read"));
        assert!(idx.policy_relevant("openat"));
        assert!(!idx.policy_relevant("stat"));
        assert!(!idx.policy_relevant("getuid"));
    }

    #[test]
    fn policy_index_canonicalizes_legacy_names() {
        // on x86_64 every legacy name maps to itself; arm64 aliasing is not part
        // of the v2 target yet.
        let mut p = Policy::default();
        p.groups.push(Group {
            name: "files".into(),
            syscalls: vec!["open".into(), "readlink".into(), "mkdir".into()],
            includes: vec![],
        });
        p.handles.push(Handle {
            group: "files".into(),
            body: vec![],
        });
        p.overrides.push(Override {
            name: "stat".into(),
            body: vec![],
        });
        let idx = PolicyIndex::build(&p, &test_arch());
        assert!(idx.policy_relevant("open"));
        assert!(idx.policy_relevant("readlink"));
        assert!(idx.policy_relevant("mkdir"));
        assert!(idx.policy_relevant("stat"));
    }

    fn test_arch() -> crate::arch::ArchTable {
        crate::arch::ArchTable::for_tests("x86", crate::arch::AUDIT_ARCH_X86_64, |n| n)
    }

    #[test]
    fn is_emulated_covers_dispatch_names() {
        for n in [
            "open", "openat", "openat2", "stat", "newfstatat", "lstat", "statx", "access",
            "faccessat", "faccessat2", "readlink", "readlinkat", "statfs", "statfs64", "fstatfs",
            "fstatfs64", "chdir", "fchdir", "getcwd", "mkdir", "mkdirat", "mknod", "mknodat",
            "rmdir", "unlink", "unlinkat", "rename", "renameat", "renameat2", "link", "linkat",
            "symlink", "symlinkat", "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "lchown",
            "fchown", "fchownat", "truncate", "ftruncate", "utimensat", "utime", "utimes",
            "futimesat", "execve", "getxattr", "lgetxattr", "setxattr", "lsetxattr",
            "removexattr", "lremovexattr", "listxattr", "llistxattr", "uname", "getuid",
            "geteuid", "getgid", "getegid", "getresuid", "getresgid", "setuid", "seteuid",
            "setgid", "setegid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
            "getgroups", "getdents", "getdents64", "lseek", "close", "capget", "capset", "socket", "socketpair",
            "bind", "listen", "accept", "accept4", "connect", "getsockname", "getpeername",
            "setsockopt", "getsockopt",
        ] {
            assert!(emulation::is_emulated(n), "{n} must be emulated");
        }
        assert!(!emulation::is_emulated("read"));
        assert!(!emulation::is_emulated("write"));
        assert!(!emulation::is_emulated("mmap"));
        assert!(!emulation::is_emulated("clone"));
    }
}

