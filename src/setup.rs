//! `setup_perms`: seed `user.chimera.meta` xattrs across a rootfs.

use crate::emulation::state::{MetaPerms, XATTR_META, XATTR_META_VERSION};
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

/// outcome of a `setup_perms` run.
#[derive(Debug, Default)]
pub struct Report {
    pub entries: u64,
    pub xattr_ok: u64,
    pub symlinks: u64,
    pub skipped: Vec<String>,
}

/// walk `rootfs` and stamp every entry with a `user.chimera.meta` xattr
/// carrying `uid`/`gid` and the entry's current permission bits.
pub fn setup_perms(rootfs: &str, uid: u32, gid: u32) -> Result<Report, String> {
    let root = std::fs::canonicalize(rootfs)
        .map_err(|e| format!("rootfs '{rootfs}': {e}"))?
        .to_string_lossy()
        .into_owned();

    let mut report = Report::default();

    match std::fs::symlink_metadata(&root) {
        Ok(md) => {
            let perms = MetaPerms {
                version: XATTR_META_VERSION,
                uid,
                gid,
                mode: md.mode() & 0o7777,
            };
            report.entries += 1;
            if set_xattr(&root, &perms) {
                report.xattr_ok += 1;
            } else {
                report.skipped.push(root.clone());
            }
        }
        Err(e) => report.skipped.push(format!("{root}: {e}")),
    }

    walk(&root, &root, uid, gid, &mut report);
    Ok(report)
}

fn walk(root: &str, dir: &str, uid: u32, gid: u32, report: &mut Report) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            report.skipped.push(format!("{dir}: {e}"));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let path_str = match path.to_str() {
            Some(s) => s.to_string(),
            None => {
                report.entries += 1;
                report.skipped.push(format!("{}: <non-utf8>", path.display()));
                continue;
            }
        };

        match std::fs::symlink_metadata(&path) {
            Ok(md) => {
                report.entries += 1;
                if md.is_symlink() {
                    // the kernel forbids `user.*` xattrs on symlinks; their
                    // ownership is cosmetic to the sandbox, so skip silently.
                    report.symlinks += 1;
                } else {
                    let perms = MetaPerms {
                        version: XATTR_META_VERSION,
                        uid,
                        gid,
                        mode: md.mode() & 0o7777,
                    };
                    if set_xattr(&path_str, &perms) {
                        report.xattr_ok += 1;
                    } else {
                        report.skipped.push(path_str.clone());
                    }
                }
                if md.is_dir() {
                    walk(root, &path_str, uid, gid, report);
                }
            }
            Err(e) => {
                report.entries += 1;
                report.skipped.push(format!("{path_str}: {e}"));
            }
        }
    }
}

/// write the metadata payload on `path` without following a trailing
/// symlink (so symlinks get their own attribute and the walk cannot escape
/// the rootfs).
fn set_xattr(path: &str, perms: &MetaPerms) -> bool {
    let cpath = CString::new(path).ok();
    let cname = CString::new(XATTR_META).ok();
    let (Some(cpath), Some(cname)) = (cpath, cname) else {
        return false;
    };
    let data = perms.to_xattr();
    unsafe {
        libc::lsetxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn stamps_tree_with_meta() {
        let base = std::env::temp_dir().join(format!("chimera-sperm-{}", std::process::id()));
        let dir = base.join("dir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(base.join("file"), b"x").unwrap();
        std::fs::write(dir.join("inner"), b"y").unwrap();
        symlink("dir", base.join("link")).unwrap();

        let report = setup_perms(base.to_str().unwrap(), 1000, 2000).unwrap();
        // base, file, link, dir, inner - the walk must not follow `link`
        assert_eq!(report.entries, 5);
        assert_eq!(report.xattr_ok, 4);
        assert_eq!(report.symlinks, 1);
        assert!(report.skipped.is_empty());

        let got = MetaPerms::from_xattr(&get_meta(&base.join("dir/inner")).unwrap()).unwrap();
        assert_eq!((got.uid, got.gid), (1000, 2000));
        assert_eq!(got.version, XATTR_META_VERSION);

        // a symlink gets no attribute (kernel forbids `user.*` there); the
        // walk must not have followed it
        assert!(get_meta(&base.join("link")).is_none());
        let got = MetaPerms::from_xattr(&get_meta(&base.join("file")).unwrap()).unwrap();
        assert_eq!((got.uid, got.gid), (1000, 2000));

        std::fs::remove_dir_all(&base).unwrap();
    }

    fn get_meta(path: &std::path::Path) -> Option<Vec<u8>> {
        let cpath = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        let cname = CString::new(XATTR_META).ok()?;
        let mut buf = vec![0u8; 64];
        let n = unsafe {
            libc::lgetxattr(
                cpath.as_ptr(),
                cname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }
}
