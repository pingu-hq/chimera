
use crate::emulation::paths;
use crate::emulation::state::SandboxState;
use crate::emulation::EmuReply;
use crate::runtime::mem;
use std::collections::HashMap;

/// execve: map the guest path to a rootfs path and rewrite it in the tracee's
pub fn execve(
    pid: libc::pid_t,
    args: &HashMap<String, String>,
    raw: &HashMap<String, u64>,
    ctx: &mut paths::PathCtx,
    state: &mut SandboxState,
) -> Option<EmuReply> {
    let path = args.get("path")?;
    let addr = *raw.get("path")?;
    if !path.starts_with('/') {
        if state.debug {
            eprintln!(
                "{} execve: path={path:?} not absolute; leaving to kernel",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }
    let root = ctx.rootfs().to_string();

    // the path to write back into the tracee's buffer (rootfs-relative so the
    // kernel resolves it against the pinned cwd) plus the host path of the
    // target binary (to inspect its elf).
    let (mapped, host_path): (String, String) = if let Some(rest) = path.strip_prefix(root.as_str()) {
        // already rootfs-anchored (e.g. the chi's own exec): relativize
        let rel = rest.trim_start_matches('/');
        if rel.is_empty() {
            return None;
        }
        (rel.to_string(), path.clone())
    } else {
        // binds win (guest -> host): the kernel resolves the host path as-is
        let mut bind_hit = false;
        for (src, _dst) in ctx.binds() {
            let rest = if path.as_str() == src.as_str() {
                Some("")
            } else if let Some(r) = path.strip_prefix(src.as_str()).and_then(|r| r.strip_prefix('/')) {
                Some(r)
            } else {
                None
            };
            if rest.is_some() {
                bind_hit = true;
                break;
            }
        }
        if bind_hit {
            return None;
        }
        let rel = path.trim_start_matches('/').to_string();
        let host = format!("{root}/{rel}");
        (rel, host)
    };

    if mapped.len() > path.len() {
        if state.debug {
            eprintln!(
                "{} execve: mapped {mapped:?} longer than {path:?}; leaving to kernel",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }

    if state.debug {
        eprintln!(
            "{} execve: path={path:?} mapped={mapped:?} host={host_path:?}",
            crate::log::tag("debug-exec")
        );
    }

    let debug = state.debug;

    // remember the guest exe path so `/proc/self/exe` and friends answer with
    // a guest path instead of the host shim copy the kernel really exec'd.
    let guest_exe = ctx.host_to_guest(&host_path).unwrap_or_else(|| path.clone());
    state.proc_mut(pid).exe = guest_exe;

    // scripts: the kernel resolves an absolute shebang interpreter against the
    // *host* root. rewrite the shebang so the rootfs interpreter runs instead.
    if let Some(reply) =
        execve_script(pid, addr, &mapped, path, &host_path, ctx.rootfs(), raw, debug)
    {
        return Some(reply);
    }

    if let Some(interp) = pt_interp(&host_path) {
        let interp_rel = interp.trim_start_matches('/');
        let in_rootfs = !interp_rel.is_empty()
            && std::fs::metadata(format!("{root}/{interp_rel}")).is_ok();
        if in_rootfs {
            // guest loader present: route through the shim; if it cannot be
            // prepared (unwritable rootfs) fall back to the plain rewrite
            if let Ok(reply) = execve_shim(pid, addr, path, &host_path, &interp, ctx.rootfs(), raw, debug) {
                return Some(reply);
            }
            if std::path::Path::new(&interp).exists() {
                // the host has a loader at the guest path (already-host-patched
                // binary): the plain rewrite will load it.
            } else {
                eprintln!(
                    "{} warn: loader routing failed for {host_path:?} (PT_INTERP {interp:?}) and {interp:?} does not resolve on the host; this exec will fail with ENOENT. The shim needs a writable scratch dir inside the rootfs - make the rootfs writable (e.g. chown/chmod) or fix the loader path",
                    crate::log::tag("chimera")
                );
            }
        }
        // interp resolves only on the host (already-patched binary): plain rewrite
    }

    rewrite_path(pid, addr, path, &mapped, raw)
}

/// route a dynamic elf exec through the rootfs loader with a pt_interp shim.
fn execve_shim(
    pid: libc::pid_t,
    bin_addr: u64,
    path: &str,
    host_path: &str,
    interp: &str,
    rootfs: &str,
    raw: &HashMap<String, u64>,
    debug: bool,
) -> Result<EmuReply, ()> {
    let shim = shim_binary(pid, host_path, interp, rootfs, path.len(), debug).ok_or(())?;
    rewrite_path(pid, bin_addr, path, &shim, raw).ok_or(())
}

/// prepare a loader-routed copy of `host_path` and return the rootfs-relative
fn shim_binary(
    pid: libc::pid_t,
    host_path: &str,
    interp: &str,
    rootfs: &str,
    bin_buf_len: usize,
    debug: bool,
) -> Option<String> {
    let root = rootfs.trim_end_matches('/');
    let interp_rel = interp.trim_start_matches('/');
    if interp_rel.is_empty() || std::fs::metadata(format!("{root}/{interp_rel}")).is_err() {
        if debug {
            eprintln!(
                "{} shim: interp {interp:?} missing in rootfs; skipping loader routing",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }

    let data = std::fs::read(host_path).ok()?;
    // the patched pt_interp is an absolute host path the kernel opens
    // directly (there is no chroot), so the loader symlink must live at a
    // short host path that fits the binary's interp segment (p_filesz).
    let capacity = interp_capacity(&data)?;
    let (dir, rel_prefix) = scratch_base(rootfs, bin_buf_len, debug)?;

    let target = format!("{root}/{interp_rel}");
    // the patched interp string is what the kernel opens at exec time, so it
    let mut ld_host = format!("{dir}/ld");
    let mut ld_interp = format!("{rel_prefix}/ld");
    if ensure_ld_symlink(&ld_host, &ld_interp, &target, capacity, debug).is_none() {
        ld_host = format!("/chi/chimera-{}/ld", fnv1a_hex(root.as_bytes(), 8));
        ld_interp = ld_host.clone();
        ensure_ld_symlink(&ld_host, &ld_interp, &target, capacity, debug)?;
    }

    // content-addressed patched copy: name derives from a hash of the binary,
    // so it is stale-proof and shared across every exec of the same file
    let name = shim_name_for(&data, &rel_prefix, "t-", bin_buf_len).ok()?;
    let dest = format!("{dir}/t-{name}");
    // the patch rewrites the interp segment in place, so the copy has the same
    // size as the source and an identical elf header. reuse an existing copy
    // only when both hold - a truncated-name collision would otherwise reuse a
    // stale or unrelated file.
    let up_to_date = (|d: &str| -> bool {
        use std::io::Read;
        let Ok(meta) = std::fs::metadata(d) else {
            return false;
        };
        if meta.len() != data.len() as u64 {
            return false;
        }
        let Ok(mut f) = std::fs::File::open(d) else {
            return false;
        };
        let mut buf = [0u8; 64];
        f.read_exact(&mut buf).is_ok() && buf == &data[..64]
    })(&dest);
    if !up_to_date {
        let tmp = format!("{dir}/.{name}.{pid}");
        let mut patched = data;
        if let Err(()) = patch_interp(&mut patched, &ld_interp) {
            if debug {
                eprintln!(
                    "{} shim: cannot patch interp of {host_path:?}; skipping loader routing",
                    crate::log::tag("debug-exec")
                );
            }
            return None;
        }
        if let Err(e) = std::fs::write(&tmp, &patched) {
            if debug {
                eprintln!(
                    "{} shim: cannot write {tmp:?}: {e}; skipping loader routing",
                    crate::log::tag("debug-exec")
                );
            }
            return None;
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        if let Err(e) = std::fs::rename(&tmp, &dest) {
            if debug {
                eprintln!(
                    "{} shim: cannot rename {tmp:?} -> {dest:?}: {e}; skipping loader routing",
                    crate::log::tag("debug-exec")
                );
            }
            return None;
        }
    }

    if debug {
        eprintln!(
            "{} shim: interp={interp:?} ld={ld_interp} exec={rel_prefix}/t-{name}",
            crate::log::tag("debug-exec")
        );
    }

    Some(format!("{rel_prefix}/t-{name}"))
}

/// create (idempotently) the loader symlink at `ld_host` pointing at `target`,
fn ensure_ld_symlink(
    ld_host: &str,
    ld_interp: &str,
    target: &str,
    capacity: usize,
    debug: bool,
) -> Option<()> {
    if ld_interp.len() + 1 > capacity {
        if debug {
            eprintln!(
                "{} shim: interp segment too small for {ld_interp:?}; trying shorter path",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }
    let dir = std::path::Path::new(ld_host).parent().unwrap();
    if let Err(e) = std::fs::create_dir_all(dir) {
        if debug {
            eprintln!(
                "{} shim: cannot create {dir:?}: {e}; trying shorter path",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }
    let probe = format!("{}/.w{}", dir.display(), std::process::id());
    if std::fs::write(&probe, b"x").is_err() {
        if debug {
            eprintln!(
                "{} shim: {dir:?} not writable; trying shorter path",
                crate::log::tag("debug-exec")
            );
        }
        return None;
    }
    let _ = std::fs::remove_file(&probe);
    if std::fs::symlink_metadata(ld_host).is_err() {
        if let Err(e) = std::os::unix::fs::symlink(target, ld_host) {
            if debug {
                eprintln!(
                    "{} shim: cannot symlink {ld_host:?} -> {target:?}: {e}; trying shorter path",
                    crate::log::tag("debug-exec")
                );
            }
            return None;
        }
    }
    Some(())
}

/// byte capacity of the pt_interp string in `data` (the segment's p_filesz),
/// which bounds any replacement interpreter path. `none` for static or
/// non-elf files (no loader routing needed).
fn interp_capacity(data: &[u8]) -> Option<usize> {
    // require a 64-byte elf64 header (ei_class byte = 2)
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        return None;
    }
    let phoff = u64::from_le_bytes(data[32..40].try_into().ok()?);
    let phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as u64;
    let phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as u64;
    if phentsize == 0 {
        return None;
    }
    for i in 0..phnum {
        let off = (phoff + i * phentsize) as usize;
        if off + phentsize as usize > data.len() {
            return None;
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        if p_type != 3 {
            continue;
        }
        let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().ok()?);
        return Some(p_filesz as usize);
    }
    None
}

/// route a script exec (shebang) through the rootfs interpreter.
fn execve_script(
    pid: libc::pid_t,
    bin_addr: u64,
    mapped: &str,
    path: &str,
    host_path: &str,
    rootfs: &str,
    raw: &HashMap<String, u64>,
    debug: bool,
) -> Option<EmuReply> {
    let data = std::fs::read(host_path).ok()?;
    if data.len() < 2 || &data[..2] != b"#!" {
        return None;
    }
    let line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    if line_end < 3 {
        return None;
    }
    let line = std::str::from_utf8(&data[2..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let interp = parts.next()?;
    let arg = parts.next();
    if !interp.starts_with('/') {
        // a relative interpreter already resolves against the tracee's cwd
        // (this is the state we leave on a prior in-place rewrite).
        return None;
    }

    let root = rootfs.trim_end_matches('/');
    let interp_rel = interp.trim_start_matches('/');
    if interp_rel.is_empty() || std::fs::metadata(format!("{root}/{interp_rel}")).is_err() {
        // interpreter exists only on the host: leave the kernel to resolve it.
        return None;
    }

    let interp_shim = shim_binary(pid, &format!("{root}/{interp_rel}"), interp, rootfs, path.len(), debug)?;
    let shebang = match arg {
        Some(a) => format!("#!{interp_shim} {a}"),
        None => format!("#!{interp_shim}"),
    };

    // rewrite the shebang in place and exec the original script path so `$0`
    // stays the guest's real path. the exec target is the relative `mapped`
    // form the kernel resolves against the tracee's pinned rootfs cwd.
    if rewrite_shebang_in_place(host_path, line_end, &shebang) {
        rewrite_path(pid, bin_addr, path, mapped, raw)?;
        return Some(EmuReply::Continue);
    }

    if debug {
        eprintln!(
            "{} shim: cannot rewrite {host_path:?} in place; falling back to an s- copy",
            crate::log::tag("debug-exec")
        );
    }

    // fallback for a read-only root: shadow the script into scratch, execing the
    // copy (its `$0` becomes the copy's path, breaking `basename $0` dispatch).
    let (dir, rel_prefix) = scratch_base(rootfs, path.len(), debug)?;
    let name = shim_name_for(&data, &rel_prefix, "s-", path.len()).ok()?;
    let dest = format!("{dir}/s-{name}");
    let mut shim = Vec::with_capacity(data.len());
    shim.extend_from_slice(shebang.as_bytes());
    shim.push(b'\n');
    if data.len() > line_end + 1 {
        shim.extend_from_slice(&data[line_end + 1..]);
    }

    let up_to_date = std::fs::read(&dest).ok().as_deref() == Some(shim.as_slice());
    if !up_to_date {
        let tmp = format!("{dir}/.{name}.{pid}");
        std::fs::write(&tmp, &shim).ok()?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        std::fs::rename(&tmp, &dest).ok()?;
    }

    if debug {
        eprintln!(
            "{} shim: script interp={interp:?} -> shebang {shebang:?}",
            crate::log::tag("debug-exec")
        );
    }

    rewrite_path(pid, bin_addr, mapped, &format!("{rel_prefix}/s-{name}"), raw)?;
    Some(EmuReply::Continue)
}

/// rewrite the shebang of the script at `host_path` in place (replacing the
/// first line with `shebang`), preserving the file's mode and executing bits.
/// returns true on success.
fn rewrite_shebang_in_place(host_path: &str, line_end: usize, shebang: &str) -> bool {
    let data = match std::fs::read(host_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(shebang.as_bytes());
    out.push(b'\n');
    if data.len() > line_end + 1 {
        out.extend_from_slice(&data[line_end + 1..]);
    }
    let mode = std::fs::metadata(host_path)
        .ok()
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode()
        })
        .unwrap_or(0o755);
    if std::fs::write(host_path, out).is_err() {
        return false;
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(host_path, std::fs::Permissions::from_mode(mode));
    true
}

/// pick a writable scratch directory inside the rootfs and create it, returning
const MIN_SHIM_NAME: usize = 3;

fn scratch_base(rootfs: &str, bin_buf_len: usize, debug: bool) -> Option<(String, String)> {
    let root = rootfs.trim_end_matches('/');
    let hash = fnv1a_hex(root.as_bytes(), 8);

    // (abs dir, rel prefix), in preference order.
    let candidates: Vec<(String, String)> = {
        let mut v = Vec::new();
        for (base, rel_base) in [
            (format!("{root}/chi"), "chi".to_string()),
            (format!("{root}/tmp"), "tmp".to_string()),
            (format!("{root}/var/tmp"), "var/tmp".to_string()),
        ] {
            let sub = format!("chimera-{hash}");
            v.push((format!("{base}/{sub}"), format!("{rel_base}/{sub}")));
            v.push((format!("{base}/chimera"), format!("{rel_base}/chimera")));
            v.push((base, rel_base));
        }
        v.push((format!("{root}/t"), "t".to_string()));
        v
    };

    // `/t-` (or `/s-`) + a name character after the prefix.
    let max_prefix = bin_buf_len.checked_sub(4)?;

    let mut fallback: Option<(String, String)> = None;
    for (abs, rel) in &candidates {
        if rel.len() > max_prefix {
            continue;
        }
        match std::fs::create_dir_all(abs) {
            Ok(()) => {
                let probe = format!("{abs}/.w{}", std::process::id());
                let writable = std::fs::write(&probe, b"x").is_ok();
                let _ = std::fs::remove_file(&probe);
                if !writable {
                    if debug {
                        eprintln!(
                            "{} shim: scratch candidate {abs:?} not writable",
                            crate::log::tag("debug-exec")
                        );
                    }
                    continue;
                }
            }
            Err(e) => {
                if debug {
                    eprintln!(
                        "{} shim: scratch candidate {abs:?} not usable: {e}",
                        crate::log::tag("debug-exec")
                    );
                }
                continue;
            }
        }
        let name_len = bin_buf_len - rel.len() - 3;
        if name_len >= MIN_SHIM_NAME {
            return Some((abs.clone(), rel.clone()));
        }
        if fallback.is_none() {
            fallback = Some((abs.clone(), rel.clone()));
        }
    }
    if fallback.is_none() && debug {
        eprintln!(
            "{} shim: no writable scratch dir under {root:?} fitting a {bin_buf_len}-byte exec path",
            crate::log::tag("debug-exec")
        );
    }
    fallback
}

/// write `new` into the tracee's exec path buffer at `bin_addr` (the kernel
fn rewrite_path(
    pid: libc::pid_t,
    bin_addr: u64,
    orig: &str,
    new: &str,
    raw: &HashMap<String, u64>,
) -> Option<EmuReply> {
    if let Some(a) = raw.get("argv").copied() {
        let orig0 = mem::read_ptrs(pid, a).filter(|v| !v.is_empty()).map(|v| v[0]);
        if orig0 == Some(bin_addr) {
            let scratch = find_scratch(pid, orig.len() + 1, bin_addr, raw)?;
            let mut s = orig.as_bytes().to_vec();
            s.push(0);
            mem::write_bytes(pid, scratch, &s)?;
            mem::write_bytes(pid, a, &scratch.to_le_bytes().to_vec())?;
        }
    }
    let mut out = new.as_bytes().to_vec();
    out.push(0);
    mem::write_bytes(pid, bin_addr, &out)?;
    Some(EmuReply::Continue)
}

/// find a writable address in the tracee for `len` bytes of scratch, avoiding
/// every range the kernel still dereferences at exec time: the path buffer,
/// the argv and envp pointer arrays, and all the strings they point at.
fn find_scratch(
    pid: libc::pid_t,
    len: usize,
    bin_addr: u64,
    raw: &HashMap<String, u64>,
) -> Option<u64> {
    let regions = mem::parse_maps(pid);
    let mut avoid: Vec<(u64, u64)> = Vec::new();
    if let Some(a) = raw.get("argv").copied() {
        if let Some(v) = mem::read_ptrs(pid, a) {
            avoid.push((a, a + 8 * v.len() as u64));
            for &p in &v {
                if let Some(r) = mem::find_region(&regions, p) {
                    if r.readable {
                        if let Some(s) = mem::read_string(pid, p) {
                            avoid.push((p, p + s.len() as u64 + 1));
                        }
                    }
                }
            }
        }
    }
    if let Some(e) = raw.get("envp").copied() {
        if let Some(v) = mem::read_ptrs(pid, e) {
            avoid.push((e, e + 8 * v.len() as u64));
            for &p in &v {
                // envp is null-terminated: stop at the first empty entry
                if p == 0 {
                    break;
                }
                if let Some(r) = mem::find_region(&regions, p) {
                    if r.readable {
                        if let Some(s) = mem::read_string(pid, p) {
                            avoid.push((p, p + s.len() as u64 + 1));
                        }
                    }
                }
            }
        }
    }
    avoid.push((bin_addr, bin_addr + len as u64 + 1));
    avoid.sort_unstable();

    let need = len as u64;
    for r in &regions {
        if !r.writable {
            continue;
        }
        let mut cur = r.start;
        for &(s, e) in &avoid {
            if e <= r.start {
                continue;
            }
            if s >= r.end {
                break;
            }
            let lo = s.max(r.start);
            if cur + need <= lo {
                return Some(cur);
            }
            cur = cur.max(e);
        }
        if cur + need <= r.end {
            return Some(cur);
        }
    }
    None
}

/// derive the short temp-file name for a shim-patched copy. the written exec
/// path `<prefix>/<file-prefix><name>` must fit the original path buffer
/// (`bin_buf_len` bytes), so the name is truncated to fit; long paths get a
/// 12-char base36 name, which leaves collisions effectively impossible.
fn shim_name_for(
    data: &[u8],
    rel_prefix: &str,
    file_prefix: &str,
    bin_buf_len: usize,
) -> Result<String, ()> {
    // `rel_prefix` + '/' + `file_prefix` + name + nul must fit the buffer.
    let max_len = bin_buf_len.checked_sub(rel_prefix.len() + 1 + file_prefix.len() + 1).ok_or(())?;
    shim_name(data, max_len)
}

fn shim_name(data: &[u8], max_len: usize) -> Result<String, ()> {
    let full = base36(fnv1a(data));
    if max_len < 1 {
        return Err(());
    }
    let keep = max_len.min(12).max(1);
    Ok(full[..full.len().min(keep)].to_string())
}

fn fnv1a(buf: &[u8]) -> u64 {
    // fnv-1a 64-bit: offset basis, then multiply by the prime per byte.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in buf {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn fnv1a_hex(buf: &[u8], n: usize) -> String {
    format!("{:x}", fnv1a(buf))[..n].to_string()
}

fn base36(mut v: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut s = Vec::new();
    while v > 0 {
        s.push(DIGITS[(v % 36) as usize]);
        v /= 36;
    }
    if s.is_empty() {
        s.push(b'0');
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

/// overwrite the pt_interp segment of an elf in place with `interp` (nul
/// padded). returns err for non-elf files, a missing segment, or an interp too
/// long for the segment.
fn patch_interp(data: &mut [u8], interp: &str) -> Result<(), ()> {
    // require a 64-byte elf64 header (ei_class byte = 2)
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        return Err(());
    }
    let phoff = u64::from_le_bytes(data[32..40].try_into().map_err(|_| ())?);
    let phentsize = u64::from(u16::from_le_bytes(data[54..56].try_into().map_err(|_| ())?));
    let phnum = u64::from(u16::from_le_bytes(data[56..58].try_into().map_err(|_| ())?));
    if phentsize == 0 {
        return Err(());
    }
    for i in 0..phnum {
        let off = (phoff + i * phentsize) as usize;
        if off + phentsize as usize > data.len() {
            return Err(());
        }
        let p_type = u32::from_le_bytes(data[off..off + 4].try_into().map_err(|_| ())?);
        if p_type != 3 {
            continue;
        }
        let p_offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().map_err(|_| ())?);
        let p_filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().map_err(|_| ())?);
        let start = p_offset as usize;
        let end = start + p_filesz as usize;
        if end > data.len() {
            return Err(());
        }
        let b = interp.as_bytes();
        if b.len() + 1 > p_filesz as usize {
            return Err(());
        }
        data[start..end].fill(0);
        data[start..start + b.len()].copy_from_slice(b);
        return Ok(());
    }
    Err(())
}

/// read the pt_interp string (the dynamic loader's guest path) from the elf at
/// `host_path`. returns `none` for static binaries, non-elf files, or when the
/// header can't be parsed.
fn pt_interp(host_path: &str) -> Option<String> {
    let data = std::fs::read(host_path).ok()?;
    // require a 64-byte elf64 header (ei_class byte = 2)
    if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 {
        return None;
    }
    let phoff = u64::from_le_bytes(data[32..40].try_into().ok()?);
    let phentsize = u16::from_le_bytes(data[54..56].try_into().ok()?) as u64;
    let phnum = u16::from_le_bytes(data[56..58].try_into().ok()?) as u64;
    if phentsize == 0 {
        return None;
    }
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let end = off + phentsize;
        if end as usize > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[off as usize..off as usize + 4].try_into().ok()?);
        if p_type != 3 {
            continue;
        }
        let p_offset = u64::from_le_bytes(data[off as usize + 8..off as usize + 16].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(data[off as usize + 32..off as usize + 40].try_into().ok()?);
        let start = p_offset as usize;
        let end = start + p_filesz as usize;
        if end > data.len() {
            return None;
        }
        let s = &data[start..end];
        let s = s.split(|&b| b == 0).next().unwrap_or(s);
        let s = String::from_utf8_lossy(s).into_owned();
        if s.is_empty() {
            return None;
        }
        return Some(s);
    }
    None
}
