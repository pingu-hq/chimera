
use super::chmp::{GLOBAL_CWD, GLOBAL_ROOT, Policy, Statement};
use crate::arch::ArchTable;
use std::collections::{BTreeSet, HashMap};

/// the compile-time view of a policy against one architecture.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrapPlan {
    /// canonical syscall names the seccomp filter must trap (overrides, every
    /// syscall in a handled group, and emulated syscalls in any group).
    /// sorted and deduped.
    pub trap: Vec<String>,
    /// the subset of `trap` the emulator can service through `dispatch`.
    /// sorted and deduped.
    pub emulated: Vec<String>,
    /// the spec's *emulate set*: syscalls whose reachable policy body
    /// (override or handle on a handled group) assigns one of its args, so the
    /// supervisor must run them rather than the kernel. sorted and deduped.
    pub modified: Vec<String>,
    /// canonical syscall names the policy referenced that no arch table entry
    /// matches. the runtime cannot trap these.
    pub unknown: Vec<String>,
}

/// build the trap/emulate plan for `policy` under `arch`.
pub fn plan(policy: &Policy, arch: &ArchTable) -> TrapPlan {
    // reverse lookup so "is this a real syscall" is o(1).
    let mut name_to_nr: HashMap<&str, i32> =
        HashMap::with_capacity(arch.nr_to_name.len());
    for (nr, name) in &arch.nr_to_name {
        name_to_nr.insert(name.as_str(), *nr);
    }

    let handled: BTreeSet<&str> = policy
        .handles
        .iter()
        .map(|h| h.group.as_str())
        .collect();
    let handle_body: HashMap<&str, &[Statement]> = policy
        .handles
        .iter()
        .map(|h| (h.group.as_str(), h.body.as_slice()))
        .collect();

    let mut trap: BTreeSet<String> = BTreeSet::new();
    let mut modified: BTreeSet<String> = BTreeSet::new();

    let consider = |name: &str,
                    t: &mut BTreeSet<String>,
                    m: &mut BTreeSet<String>,
                    body: Option<&[Statement]>| {
        let c = arch.canonical_name(name).to_string();
        if let Some(body) = body {
            if assigns_arg(body) {
                m.insert(c.clone());
            }
        }
        t.insert(c);
    };

    for o in &policy.overrides {
        consider(&o.name, &mut trap, &mut modified, Some(&o.body));
    }
    for g in &policy.groups {
        let has_handle = handled.contains(g.name.as_str());
        let body = handle_body.get(g.name.as_str()).copied();
        for s in &g.syscalls {
            if has_handle {
                consider(s, &mut trap, &mut modified, body);
            } else if crate::emulation::is_emulated(s) {
                consider(s, &mut trap, &mut modified, None);
            }
        }
    }

    // every referenced syscall name must resolve in the arch table, or the
    // policy author mistyped it. report regardless of handle/emulation status
    // so a bad name in an unhandled group is still surfaced.
    let mut unknown: Vec<String> = Vec::new();
    let add_unknown = |name: &str, out: &mut Vec<String>| {
        let c = arch.canonical_name(name).to_string();
        if !name_to_nr.contains_key(c.as_str()) && !out.contains(&c) {
            out.push(c);
        }
    };
    for o in &policy.overrides {
        add_unknown(&o.name, &mut unknown);
    }
    for g in &policy.groups {
        for s in &g.syscalls {
            add_unknown(s, &mut unknown);
        }
    }

    // path-mapping networking is one unit: emulating bind/connect means the
    if trap.iter().any(|c| c == "bind" || c == "connect") {
        for s in ["getsockname", "getpeername"] {
            trap.insert(s.to_string());
        }
    }

    let emulated: Vec<String> = trap
        .iter()
        .filter(|c| crate::emulation::is_emulated(c))
        .cloned()
        .collect();

    TrapPlan {
        trap: trap.into_iter().collect(),
        emulated,
        modified: modified.into_iter().collect(),
        unknown,
    }
}

/// true when any reachable statement in a body assigns a syscall arg (a bare
/// `path = ...` / `mode = ...`; assignments to the read-only `root`/`cwd`
/// globals are not rewrites and don't count).
fn assigns_arg(body: &[Statement]) -> bool {
    body.iter().any(|s| match s {
        Statement::Assign(name, _) => name != GLOBAL_ROOT && name != GLOBAL_CWD,
        Statement::Conditional(c) => {
            assigns_arg(&c.then) || c.otherwise.as_deref().is_some_and(assigns_arg)
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embroider::chmp::{Conditional, Expr, Group, Handle, Override};

    fn arch() -> ArchTable {
        let mut nr_to_name = HashMap::new();
        for (nr, name) in [
            (2, "open"),
            (257, "openat"),
            (4, "stat"),
            (5, "fstat"),
            (262, "newfstatat"),
            (21, "mkdir"),
            (59, "execve"),
            (102, "getuid"),
            (105, "setuid"),
        ] {
            nr_to_name.insert(nr, name.to_string());
        }
        ArchTable::for_tests_nrs("x86", crate::arch::AUDIT_ARCH_X86_64, |n| n, nr_to_name)
    }

    fn base_policy() -> Policy {
        let mut p = Policy::default();
        p.groups.push(Group {
            name: "files".into(),
            syscalls: vec!["open".into(), "stat".into(), "mkdir".into()],
            includes: vec![],
        });
        p.groups.push(Group {
            name: "identity".into(),
            syscalls: vec!["getuid".into()],
            includes: vec![],
        });
        p
    }

    #[test]
    fn handled_group_traps_every_member_and_marks_assigned_args() {
        let mut p = base_policy();
        p.handles.push(Handle {
            group: "files".into(),
            body: vec![
                Statement::Allow,
                Statement::Assign("path".into(), Expr::Ident("path".into())),
            ],
        });
        let tp = plan(&p, &arch());
        assert!(tp.trap.contains(&"open".into()));
        assert!(tp.trap.contains(&"stat".into()));
        assert!(tp.trap.contains(&"mkdir".into()));
        // the handle assigns `path`, so every member is in the emulate set.
        assert_eq!(
            tp.modified,
            vec!["mkdir", "open", "stat"].into_iter().map(String::from).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unhandled_group_traps_only_emulated_syscalls() {
        // identity group has no handle; getuid is emulated -> trapped.
        // mkdir/stat/open in `files` (no handle yet) are emulated too.
        let tp = plan(&base_policy(), &arch());
        assert!(tp.trap.contains(&"getuid".into()));
        assert!(tp.trap.contains(&"open".into()));
        assert!(!tp.trap.contains(&"fstat".into())); // not in any group
        assert!(!tp.modified.contains(&"getuid".into()));
    }

    #[test]
    fn override_is_always_trapped() {
        let mut p = base_policy();
        p.overrides.push(Override {
            name: "fstat".into(),
            body: vec![Statement::Assign("fd".into(), Expr::String("1".into()))],
        });
        let tp = plan(&p, &arch());
        assert!(tp.trap.contains(&"fstat".into()));
        assert!(tp.modified.contains(&"fstat".into()));
    }

    #[test]
    fn conditional_assignment_counts_as_reachable() {
        let mut p = base_policy();
        p.handles.push(Handle {
            group: "files".into(),
            body: vec![Statement::Conditional(Conditional {
                expr: Expr::Ident("flags".into()),
                then: vec![Statement::Assign("path".into(), Expr::String("/x".into()))],
                otherwise: None,
            })],
        });
        let tp = plan(&p, &arch());
        assert!(tp.modified.contains(&"open".into()));
        // read-only global assignments do not count as rewrites
        p.handles[0].body = vec![Statement::Assign(
            "root".into(),
            Expr::String("/x".into()),
        )];
        let tp2 = plan(&p, &arch());
        assert!(tp2.modified.is_empty());
    }

    #[test]
    fn path_mapping_networking_auto_traps_inverse_queries() {
        let mut p = base_policy();
        p.groups.push(Group {
            name: "net".into(),
            syscalls: vec!["bind".into(), "getsockname".into()],
            includes: vec![],
        });
        let tp = plan(&p, &arch());
        // bind is emulated -> trapped, which pulls in the reverse query.
        assert!(tp.trap.contains(&"bind".into()));
        assert!(tp.trap.contains(&"getsockname".into()));
        assert!(tp.trap.contains(&"getpeername".into()));
        assert!(!tp.trap.contains(&"accept".into())); // left to policy
        assert!(tp.emulated.contains(&"getpeername".into()));
    }

    #[test]
    fn unknown_syscall_is_reported_and_not_trapped() {
        let mut p = base_policy();
        p.groups[0].syscalls.push("not_a_syscall".into());
        let tp = plan(&p, &arch());
        assert!(tp.unknown.contains(&"not_a_syscall".into()));
        assert!(!tp.trap.contains(&"not_a_syscall".into()));
    }
}
