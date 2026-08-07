//! the x86_64 syscall table and policy-name canonicalization (identity mapping).

use super::{load_table, ArchImpl, ArchTable};

pub const AUDIT_ARCH: u32 = 0xc000_003e;

pub struct X86_64;

impl ArchImpl for X86_64 {
    fn describe(&self) -> (String, u32) {
        ("x86".to_string(), AUDIT_ARCH)
    }

    fn load(&self) -> Result<ArchTable, String> {
        load_table("x86", AUDIT_ARCH, canonical_name)
    }
}

pub const ARCH: X86_64 = X86_64;

/// on x86_64 every legacy syscall name exists natively in the table.
pub fn canonical_name(name: &str) -> &str {
    name
}
