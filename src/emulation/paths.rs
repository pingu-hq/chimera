//! shared guest↔host path resolution for emulated syscalls.

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;

/// how many guest→host entries the memo keeps before evicting oldest-first.
const FWD_CACHE_MAX: usize = 8192;
/// same for the reverse (host→guest) memo.
const REV_CACHE_MAX: usize = 4096;

/// the sandbox's immutable path context plus memoized mappings.
pub struct PathCtx {
    rootfs: String,
    binds: Vec<(String, String)>,
    /// absolute guest path -> host path
    fwd: HashMap<String, String>,
    /// insertion order of `fwd` keys, for oldest-first eviction
    order: VecDeque<String>,
    /// host path -> guest path (none for paths outside the sandbox)
    rev: HashMap<String, Option<String>>,
}

impl PathCtx {
    pub fn new(rootfs: &str, binds: &[(String, String)]) -> Self {
        PathCtx {
            rootfs: rootfs.trim_end_matches('/').to_string(),
            binds: binds.to_vec(),
            fwd: HashMap::new(),
            order: VecDeque::new(),
            rev: HashMap::new(),
        }
    }

    /// the rootfs, with any trailing `/` trimmed.
    pub fn rootfs(&self) -> &str {
        &self.rootfs
    }

    /// the sandbox's bind table (`src` guest -> `dst` host).
    pub fn binds(&self) -> &[(String, String)] {
        &self.binds
    }

    /// memoize `guest` → `host`, evicting the oldest entry when the cache is
    /// full, and return the host path.
    fn cache_fwd(&mut self, guest: String, host: String) -> String {
        if !self.fwd.contains_key(&guest) {
            if self.fwd.len() >= FWD_CACHE_MAX {
                if let Some(old) = self.order.pop_front() {
                    self.fwd.remove(&old);
                }
            }
            self.order.push_back(guest.clone());
            self.fwd.insert(guest, host.clone());
        }
        host
    }

    /// memoize `host` → `guest` (or the sentinel that it's outside the
    /// sandbox), evicting an arbitrary entry when the cache is full.
    fn cache_rev(&mut self, host: &str, guest: Option<String>) -> Option<String> {
        if self.rev.len() >= REV_CACHE_MAX && !self.rev.contains_key(host) {
            if let Some(old) = self.rev.keys().next().cloned() {
                self.rev.remove(&old);
            }
        }
        self.rev.insert(host.to_string(), guest.clone());
        guest
    }

    /// map a guest-absolute path to a host path: binds win, otherwise the path
    /// is anchored on the rootfs. memoized.
    pub fn guest_to_host(&mut self, path: &str) -> String {
        if let Some(host) = self.fwd.get(path) {
            return host.clone();
        }
        let host = guest_to_host_raw(path, &self.rootfs, &self.binds);
        self.cache_fwd(path.to_string(), host)
    }

    /// inverse of [`pathctx::guest_to_host`]: turn a host path back into a
    /// guest-absolute path. returns `none` for host paths outside the sandbox.
    /// memoized.
    pub fn host_to_guest(&mut self, path: &str) -> Option<String> {
        if let Some(guest) = self.rev.get(path) {
            return guest.clone();
        }
        let guest = host_to_guest_raw(path, &self.rootfs, &self.binds);
        self.cache_rev(path, guest)
    }

    /// map a policy-processed path to a host path.
    pub fn map_host(&mut self, pid: libc::pid_t, path: &str, cwd: &str) -> String {
        let root = self.rootfs.as_str();
        let path = translate_proc(pid, path);
        if path.starts_with(root) && (path == root || path[root.len()..].starts_with('/')) {
            return path;
        }
        let guest = if path.starts_with('/') {
            path
        } else {
            resolve_guest(cwd, &path)
        };
        self.guest_to_host(&guest)
    }

    /// resolve a path argument for an `*at` syscall.
    pub fn resolve_at(
        &mut self,
        pid: libc::pid_t,
        dirfd: i32,
        path: &str,
        cwd: &str,
    ) -> Option<String> {
        if path.starts_with('/') {
            return Some(self.map_host(pid, path, cwd));
        }
        if dirfd == libc::AT_FDCWD {
            return Some(self.map_host(pid, path, cwd));
        }
        let dir = fd_host_path(pid, dirfd)?;
        if path.is_empty() {
            return Some(dir);
        }
        Some(format!("{dir}/{path}"))
    }
}

/// rewrite the magic `/proc/self` (and `/proc/thread-self`) prefixes of a
pub fn translate_proc(pid: libc::pid_t, path: &str) -> String {
    if path == "/proc/self" {
        return format!("/proc/{pid}");
    }
    if let Some(rest) = path.strip_prefix("/proc/self/") {
        return format!("/proc/{pid}/{rest}");
    }
    // `/proc/thread-self` is the calling thread; the tid is opaque here, so
    // fall back to the pid's main thread entry. better than the supervisor.
    if path == "/proc/thread-self" {
        return format!("/proc/{pid}/task/{pid}");
    }
    if let Some(rest) = path.strip_prefix("/proc/thread-self/") {
        return format!("/proc/{pid}/task/{pid}/{rest}");
    }
    path.to_string()
}

/// lexically resolve `path` against the virtual cwd `cwd` (guest-absolute).
/// `..` above the root stays at `/`.
pub fn resolve_guest(cwd: &str, path: &str) -> String {
    let mut out = String::new();
    if !path.starts_with('/') {
        out.push_str(cwd);
    }
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match out.rfind('/') {
                Some(0) => out.truncate(1),
                Some(i) => out.truncate(i),
                None => out.clear(),
            },
            c => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                if out.is_empty() {
                    out.push('/');
                }
                out.push_str(c);
            }
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

/// un-memoized [`pathctx::guest_to_host`]: binds win, otherwise the path is
/// anchored on the rootfs and absolute guest symlinks are resolved within it
/// (see [`squash_rootfs_symlinks`]).
fn guest_to_host_raw(path: &str, rootfs: &str, binds: &[(String, String)]) -> String {
    for (src, dst) in binds {
        if path == src.as_str() {
            return dst.clone();
        }
        if let Some(rest) = path
            .strip_prefix(src.as_str())
            .and_then(|r| r.strip_prefix('/'))
        {
            return format!("{dst}/{rest}");
        }
    }
    squash_rootfs_symlinks(
        &format!("{}{}", rootfs.trim_end_matches('/'), path),
        rootfs,
    )
}

/// cap on symlink hops while resolving a rootfs path (loops bail out).
const MAX_SYMLINK_DEPTH: u32 = 64;

/// resolve symlinks in a `rootfs`-anchored absolute host path *within the
fn squash_rootfs_symlinks(host: &str, rootfs: &str) -> String {
    let root = rootfs.trim_end_matches('/');
    if !host.starts_with(root) {
        return host.to_string();
    }
    let mut cur = root.to_string();
    let mut parts: VecDeque<String> = host[root.len()..]
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_string)
        .collect();
    let mut depth = 0u32;
    while let Some(p) = parts.pop_front() {
        if depth >= MAX_SYMLINK_DEPTH {
            parts.push_front(p);
            break;
        }
        if p == ".." {
            cur = pop_component(&cur, root);
            continue;
        }
        let cand = join_clamped(&cur, &p, root);
        if let Ok(meta) = std::fs::symlink_metadata(&cand) {
            if meta.file_type().is_symlink() {
                if let Ok(t) = std::fs::read_link(&cand) {
                    // absolute target: rebase onto the rootfs root (the guest's
                    // concept of `/`). relative target: rebase onto the symlink's
                    // parent, as the kernel would.
                    cur = if t.is_absolute() {
                        root.to_string()
                    } else {
                        parent_cloned(&cand)
                    };
                    let t = t.to_string_lossy().into_owned();
                    let mut ins: Vec<String> = split(&t).into_iter().collect();
                    while let Some(c) = ins.pop() {
                        parts.push_front(c);
                    }
                    depth += 1;
                    continue;
                }
            }
        }
        // not a symlink (or unreadable): fold the component into the resolved dir.
        cur = cand;
        depth += 1;
    }
    // append any trailing components that were never resolved (the to-be-created
    // file, or a depth-exceeded prefix).
    let mut out = cur;
    for p in &parts {
        if p == ".." {
            out = pop_component(&out, root);
        } else {
            out.push('/');
            out.push_str(p);
        }
    }
    out
}

/// `dir/component` (or just `component` when `dir` ends in `/`).
fn join_clamped(dir: &str, comp: &str, _root: &str) -> String {
    if dir.is_empty() {
        comp.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{comp}")
    } else {
        format!("{dir}/{comp}")
    }
}

/// drop the final component of `host`, never rising above `root`.
fn pop_component(host: &str, root: &str) -> String {
    let s = host.trim_end_matches('/');
    if s.is_empty() || s == root {
        return root.to_string();
    }
    match s.rfind('/') {
        Some(i) if i > 0 => s[..i].to_string(),
        _ => root.to_string(),
    }
}

/// parent directory of a host path; for single-component paths collapses to `/`.
fn parent_cloned(host: &str) -> String {
    let s = host.trim_end_matches('/');
    match s.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => s[..i].to_string(),
    }
}

fn split(s: &str) -> Vec<String> {
    s.split('/').filter(|c| !c.is_empty() && *c != ".").map(str::to_string).collect()
}

/// un-memoized [`pathctx::host_to_guest`]: turn a host path back into a
/// guest-absolute path. returns `none` for host paths outside the sandbox.
fn host_to_guest_raw(path: &str, rootfs: &str, binds: &[(String, String)]) -> Option<String> {
    let root = rootfs.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(root) {
        let rest = rest.strip_prefix('/').unwrap_or("");
        return Some(if rest.is_empty() {
            "/".to_string()
        } else {
            format!("/{rest}")
        });
    }
    for (src, dst) in binds {
        if path == dst.as_str() {
            return Some(src.clone());
        }
        if let Some(rest) = path
            .strip_prefix(dst.as_str())
            .and_then(|r| r.strip_prefix('/'))
        {
            return Some(format!("{src}/{rest}"));
        }
    }
    None
}

/// resolve the host path behind a tracee fd via `/proc/<pid>/fd/<fd>`.
pub fn fd_host_path(pid: libc::pid_t, fd: i32) -> Option<String> {
    let link = format!("/proc/{pid}/fd/{fd}");
    let host = std::fs::read_link(&link).ok()?;
    let host = host.to_string_lossy();
    Some(host.strip_suffix(" (deleted)").unwrap_or(&host).to_string())
}

/// re-read a path string from the tracee's memory at the raw pointer, falling
pub fn guest_path_arg(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    key: &str,
) -> Option<String> {
    if let Some(&addr) = raw.get(key) {
        if addr == 0 {
            // null path with at_empty_path means "operate on dirfd itself".
            return Some(String::new());
        }
        // a path argument never exceeds path_max (4 kib)
        if let Some(s) = crate::runtime::mem::read_cstring(pid, addr, 4096) {
            return Some(s);
        }
    }
    args.get(key).cloned()
}

pub fn cstr(path: &str) -> Option<CString> {
    CString::new(path).ok()
}

pub fn at_fdcwd(v: Option<&u64>) -> bool {
    v.copied().unwrap_or(u64::MAX) as i32 == libc::AT_FDCWD
}

pub fn dirfd_of(raw: &HashMap<String, u64>, key: &str) -> i32 {
    raw.get(key).copied().unwrap_or(u64::MAX) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squash_resolves_absolute_symlink_within_rootfs() {
        // real on-disk layout in /tmp so the walker can lstat/readlink it.
        let dir = std::env::temp_dir().join(format!("chipaths_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("var")).unwrap();
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::fs::write(dir.join("run/update-menus.pid"), b"").unwrap();
        // var/run -> /run  (absolute target that would otherwise escape)
        std::os::unix::fs::symlink("/run", dir.join("var/run")).unwrap();
        let root = dir.to_str().unwrap();

        let host = squash_rootfs_symlinks(&format!("{root}/var/run/update-menus.pid"), root);
        // re-anchored at the rootfs root, not the machine's real /run.
        assert_eq!(host, format!("{root}/run/update-menus.pid"));

        // a relative symlink resolves relative, staying jailed too.
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::os::unix::fs::symlink("../run", dir.join("a/dot")).unwrap();
        let host2 = squash_rootfs_symlinks(&format!("{root}/a/dot/ready"), root);
        assert_eq!(host2, format!("{root}/run/ready"));

        // a missing trailing file passes through unresolved on the joined dir.
        let host3 = squash_rootfs_symlinks(
            &format!("{root}/run/update-menus.pid.new"),
            root,
        );
        assert_eq!(host3, format!("{root}/run/update-menus.pid.new"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guest_to_host_roundtrips_through_host_to_guest() {
        let mut ctx = PathCtx::new("/srv/rootfs/", &[]);
        let host = ctx.guest_to_host("/etc/passwd");
        assert_eq!(host, "/srv/rootfs/etc/passwd");
        assert_eq!(ctx.host_to_guest(&host).as_deref(), Some("/etc/passwd"));
        // outside the sandbox: not mappable back
        assert_eq!(ctx.host_to_guest("/host/only/file"), None);
    }

    #[test]
    fn cache_returns_the_same_string_without_recomputation() {
        let mut ctx = PathCtx::new("/srv/rootfs", &[]);
        let a = ctx.guest_to_host("/usr/lib/x");
        let b = ctx.guest_to_host("/usr/lib/x");
        assert_eq!(a, b);
        assert_eq!(ctx.fwd.len(), 1);
    }

    #[test]
    fn binds_win_over_the_rootfs_slam() {
        let binds = vec![
            ("/proc".to_string(), "/proc".to_string()),
            ("/sock".to_string(), "/host/sock".to_string()),
        ];
        let mut ctx = PathCtx::new("/srv/rootfs", &binds);
        assert_eq!(ctx.guest_to_host("/proc/self/status"), "/proc/self/status");
        assert_eq!(ctx.guest_to_host("/sock/x.sock"), "/host/sock/x.sock");
        assert_eq!(ctx.guest_to_host("/etc"), "/srv/rootfs/etc");
    }

    #[test]
    fn map_host_resolves_relative_paths_and_translates_proc() {
        let mut ctx = PathCtx::new("/srv/rootfs", &[]);
        // relative -> resolved against cwd, then slammed
        assert_eq!(ctx.map_host(1, "etc/hosts", "/"), "/srv/rootfs/etc/hosts");
        assert_eq!(ctx.map_host(1, "../x", "/a/b"), "/srv/rootfs/a/x");
        // already rootfs-anchored -> untouched
        assert_eq!(ctx.map_host(1, "/srv/rootfs/etc", "/"), "/srv/rootfs/etc");
        // without a bind, /proc is just another rootfs path...
        assert_eq!(
            ctx.map_host(4242, "/proc/self/status", "/"),
            "/srv/rootfs/proc/4242/status"
        );
        // ...and with a /proc bind the translated pid path reaches the host procfs
        let mut bound = PathCtx::new("/srv/rootfs", &[("/proc".to_string(), "/proc".to_string())]);
        assert_eq!(bound.map_host(4242, "/proc/self/status", "/"), "/proc/4242/status");
    }

    #[test]
    fn fwd_cache_evicts_oldest_first() {
        let mut ctx = PathCtx::new("/srv/rootfs", &[]);
        let n = FWD_CACHE_MAX + 8;
        for i in 0..n {
            let guest = format!("/g/{i}");
            let _ = ctx.cache_fwd(guest, format!("/srv/rootfs/g/{i}"));
        }
        // the oldest 8 entries were evicted to stay under the cap
        assert!(!ctx.fwd.contains_key("/g/0"));
        assert!(!ctx.fwd.contains_key("/g/7"));
        // the newest are still cached
        assert!(ctx.fwd.contains_key(&format!("/g/{}", n - 1)));
        assert!(ctx.fwd.len() <= FWD_CACHE_MAX);
    }
}
