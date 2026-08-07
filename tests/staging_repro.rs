//! reproduction harness for the apt/dpkg staging failure:

use chimera::emulation::directories;
use chimera::emulation::paths;
use chimera::emulation::state::SandboxState;
use chimera::emulation::EmuReply;
use std::collections::HashMap;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "chimera-staging-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("var/cache/apt/archives")).unwrap();
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    // a stand-in for a cached .deb
    std::fs::write(
        dir.join("var/cache/apt/archives/libexpat1_2.7.1-2_amd64.deb"),
        b"deb-content",
    )
    .unwrap();
    dir
}

fn args(map: &[(&str, &str)]) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn raw(map: &[(&str, u64)]) -> HashMap<String, u64> {
    map.iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect()
}

/// the guest path apt hands to dpkg for the first stashed deb.
const DEB: &str =
    "/tmp/apt-dpkg-install-83Oxeu/00-libexpat1_2.7.1-2_amd64.deb";
const SRC: &str =
    "/var/cache/apt/archives/libexpat1_2.7.1-2_amd64.deb";

/// host path a guest path resolves to, via the same layer the sandbox uses
/// before the kernel syscall.
fn resolve(pid: libc::pid_t, p: &str, ctx: &mut paths::PathCtx) -> String {
    ctx.resolve_at(pid, libc::AT_FDCWD, p, "/")
        .unwrap_or_else(|| panic!("unresolvable guest path: {p}"))
}

#[test]
fn staging_mkdir_link_stat_roundtrip() {
    let root = scratch("hardlink");
    let rootfs = root.to_str().unwrap();
    let binds: Vec<(String, String)> = vec![];
    let mut state = SandboxState::new();
    let pid = 4242;
    state.ensure(pid);
    let mut ctx = paths::PathCtx::new(rootfs, &binds);

    // 1. apt creates the stash dir under /tmp. the mode arg is a numeric
    // register (0o700 = 448 decimal) read back as the decimal string.
    let mk = directories::dispatch(
        pid,
        "mkdir",
        &args(&[("path", "/tmp/apt-dpkg-install-83Oxeu"), ("mode", "448")]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );
    assert_eq!(mk, Some(EmuReply::Value(0)), "mkdir failed");
    assert!(
        root.join("tmp/apt-dpkg-install-83Oxeu").is_dir(),
        "stash dir missing"
    );

    // 2. apt hardlinks the cached deb into the stash.
    let lk = directories::dispatch(
        pid,
        "link",
        &args(&[("oldpath", SRC), ("newpath", DEB)]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );
    assert_eq!(lk, Some(EmuReply::Value(0)), "link failed");
    assert!(
        root.join("tmp/apt-dpkg-install-83Oxeu/00-libexpat1_2.7.1-2_amd64.deb").is_file(),
        "stashed deb missing"
    );

    // 3. dpkg stats the stash path. the emulated stat can't write its struct
    // out without a live tracee (that would efault), so verify the same thing
    // the sandbox kernel does: the resolved host path must exist. enoent here
    // is exactly the bug dpkg hit.
    let host = resolve(pid, DEB, &mut ctx);
    match std::fs::metadata(&host) {
        Ok(_) => {}
        Err(e) => panic!(
            "dpkg would see ENOENT statting the stashed deb ({e}) for host path {host}"
        ),
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// regression test for the apt/dpkg staging failure: apt stashes each cached
#[test]
fn staging_symlink_follow_roundtrip() {
    let root = scratch("symlink");
    let rootfs = root.to_str().unwrap();
    let binds: Vec<(String, String)> = vec![];
    let mut state = SandboxState::new();
    let pid = 4242;
    state.ensure(pid);
    let mut ctx = paths::PathCtx::new(rootfs, &binds);

    directories::dispatch(
        pid,
        "mkdir",
        &args(&[("path", "/tmp/apt-dpkg-install-83Oxeu"), ("mode", "448")]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );

    // 1. apt creates the stash symlink: absolute target.
    let sl = directories::dispatch(
        pid,
        "symlink",
        &args(&[("target", SRC), ("linkpath", DEB)]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );
    assert_eq!(sl, Some(EmuReply::Value(0)), "symlink failed");

    let stash_host = resolve(pid, DEB, &mut ctx);
    let stored = std::fs::read_link(&stash_host)
        .unwrap_or_else(|e| panic!("read_link failed: {e}"));

    // 2. the stored target must be the rootfs-anchored host path, so the host
    // kernel (no chroot) follows it into the sandbox. the old bug stored the
    // bare guest path, which the kernel resolved against the host root.
    let want = format!("{rootfs}/var/cache/apt/archives/libexpat1_2.7.1-2_amd64.deb");
    assert_eq!(
        stored.to_str().unwrap(),
        want,
        "symlink target not anchored on the rootfs"
    );

    // 3. kernel-follow: dpkg's stat of the stash path must reach the deb
    // (would be enoent with the guest-absolute target).
    std::fs::metadata(&stash_host)
        .unwrap_or_else(|e| panic!("stat of stashed deb failed: {e}"));

    // 4. readlink reverse-translation: the guest must see the original
    // guest-absolute target.
    let back = ctx.host_to_guest(stored.to_str().unwrap());
    assert_eq!(back.as_deref(), Some(SRC), "readlink guest view wrong");

    // 5. relative targets stay verbatim: the kernel resolves them against the
    // symlink's own directory, which is already inside the sandbox.
    let rel_deb = "/tmp/apt-dpkg-install-83Oxeu/rel";
    let sl = directories::dispatch(
        pid,
        "symlink",
        &args(&[("target", "00-libexpat1_2.7.1-2_amd64.deb"), ("linkpath", rel_deb)]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );
    assert_eq!(sl, Some(EmuReply::Value(0)), "relative symlink failed");
    let rel_host = resolve(pid, rel_deb, &mut ctx);
    assert_eq!(
        std::fs::read_link(&rel_host).unwrap().to_str().unwrap(),
        "00-libexpat1_2.7.1-2_amd64.deb",
        "relative target must be stored verbatim"
    );
    std::fs::metadata(&rel_host)
        .unwrap_or_else(|e| panic!("relative symlink not resolvable: {e}"));

    let _ = std::fs::remove_dir_all(&root);
}

/// apt's copyfile fallback when the hardlink fails: open(src, o_rdonly),
#[test]
fn staging_resolve_consistency() {
    let root = scratch("resolve");
    let rootfs = root.to_str().unwrap();
    let binds: Vec<(String, String)> = vec![];
    let mut state = SandboxState::new();
    let pid = 4242;
    state.ensure(pid);
    let mut ctx = paths::PathCtx::new(rootfs, &binds);

    directories::dispatch(
        pid,
        "mkdir",
        &args(&[("path", "/tmp/apt-dpkg-install-83Oxeu"), ("mode", "448")]),
        &raw(&[]),
        &mut ctx,
        &mut state,
    );

    let cwd = "/".to_string();
    let expected_src = format!("{rootfs}{SRC}");
    let expected_dst = format!("{rootfs}{DEB}");
    // open(o_rdonly) on the cached deb
    let src_host = ctx.resolve_at(pid, libc::AT_FDCWD, SRC, &cwd);
    assert_eq!(src_host.as_deref(), Some(expected_src.as_str()), "src resolves wrong");
    // open(o_wronly|o_creat) on the stash copy
    let dst_host = ctx.resolve_at(pid, libc::AT_FDCWD, DEB, &cwd);
    assert_eq!(dst_host.as_deref(), Some(expected_dst.as_str()), "dst resolves wrong");
    // dpkg's stat must resolve identically
    let stat_host = ctx.resolve_at(pid, libc::AT_FDCWD, DEB, &cwd);
    assert_eq!(stat_host, dst_host, "stat resolves differently than the open");

    let _ = std::fs::remove_dir_all(&root);
}
