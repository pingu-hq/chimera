//! architecture-specific syscall context: numbers, names, audit arch, aliases.
//!
//! core emulation and policy logic never branches on `target_arch`; they call
//! [`native()`] and use the returned [`archtable`].

mod x86_64;

use std::collections::HashMap;

pub const AUDIT_ARCH_X86_64: u32 = x86_64::AUDIT_ARCH;

/// loaded syscall table for the running host abi.
pub struct ArchTable {
    pub arch_dir: String,
    pub audit_arch: u32,
    pub nr_to_name: HashMap<i32, String>,
    canonical: fn(&str) -> &str,
}

impl ArchTable {
    pub fn canonical_name<'s>(&self, name: &'s str) -> &'s str {
        (self.canonical)(name)
    }

    /// test-only constructor: builds a table without reading `data/`.
    #[cfg(test)]
    pub(crate) fn for_tests(
        arch_dir: &str,
        audit_arch: u32,
        canonical: fn(&str) -> &str,
    ) -> Self {
        ArchTable {
            arch_dir: arch_dir.to_string(),
            audit_arch,
            nr_to_name: HashMap::new(),
            canonical,
        }
    }

    /// test-only constructor that also carries a syscall table, for tests that
    /// exercise name -> number lookups (e.g. the embroider planning pass).
    #[cfg(test)]
    pub(crate) fn for_tests_nrs(
        arch_dir: &str,
        audit_arch: u32,
        canonical: fn(&str) -> &str,
        nr_to_name: HashMap<i32, String>,
    ) -> Self {
        ArchTable {
            arch_dir: arch_dir.to_string(),
            audit_arch,
            nr_to_name,
            canonical,
        }
    }
}
/// returns `(arch_dir, audit_arch)` for the running machine.
pub fn native_arch() -> (String, u32) {
    native_impl().describe()
}

/// load `data/<arch>/syscall_64.chmd` for the host abi.
pub fn load_arch_table() -> Result<ArchTable, String> {
    native_impl().load()
}

fn native_impl() -> &'static dyn ArchImpl {
    #[cfg(target_arch = "x86_64")]
    {
        &x86_64::ARCH
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        compile_error!("chimera v2 initial target: x86_64 only");
    }
}

trait ArchImpl {
    fn describe(&self) -> (String, u32);
    fn load(&self) -> Result<ArchTable, String>;
}

/// load `data/syscalls.chmd` into a name -> arg-names table (arch-independent).
pub fn load_syscall_args() -> Result<HashMap<String, Vec<String>>, String> {
    let path = "data/syscalls.chmd";
    let src =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    let mut map = HashMap::new();
    for line in src.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-t>") {
            continue;
        }
        if let Some((name, rest)) = line.split_once(':') {
            let args: Vec<String> = rest
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            map.insert(name.trim().to_string(), args);
        }
    }
    Ok(map)
}

fn parse_syscall_chmd(path: &str) -> Result<HashMap<i32, String>, String> {
    let src =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let mut nr_to_name = HashMap::new();
    for line in src.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-t>") {
            continue;
        }
        let mut it = line.split_whitespace();
        if let (Some(nr), Some(name)) = (it.next(), it.next()) {
            if let Ok(nr) = nr.parse::<i32>() {
                nr_to_name.insert(nr, name.to_string());
            }
        }
    }
    Ok(nr_to_name)
}

pub(crate) fn load_table(
    arch_dir: &str,
    audit_arch: u32,
    canonical: fn(&str) -> &str,
) -> Result<ArchTable, String> {
    let path = format!("data/{arch_dir}/syscall_64.chmd");
    let nr_to_name = parse_syscall_chmd(&path)?;
    Ok(ArchTable {
        arch_dir: arch_dir.to_string(),
        audit_arch,
        nr_to_name,
        canonical,
    })
}
