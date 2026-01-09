//! Virtual address space capability
//!
//! A VSpace represents a virtual address space, corresponding to
//! TTBR0_EL1 on ARM64. Each process has its own VSpace that defines
//! its user-space memory mappings.
//!
//! # Structure
//!
//! A VSpace owns:
//! - A root page table (L0)
//! - An ASID for TLB isolation
//! - References to all mapped frames and child page tables

use m6_common::PhysAddr;

use crate::slot::ObjectRef;

/// Address Space Identifier.
///
/// ASIDs provide TLB isolation between address spaces. Each VSpace
/// requires a unique ASID to ensure TLB entries don't collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Asid(u16);

impl Asid {
    /// Invalid/unassigned ASID.
    pub const INVALID: Self = Self(0);

    /// Maximum ASID value (ARM64 supports up to 16-bit ASIDs).
    pub const MAX: Self = Self(0xFFFF);

    /// Create a new ASID.
    #[inline]
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get the raw ASID value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Check if this is a valid ASID.
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// VSpace object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct VSpaceObject {
    /// Physical address of the root page table (L0).
    pub root_table: PhysAddr,
    /// Assigned ASID.
    pub asid: Asid,
    /// Reference to the root page table capability.
    pub root_table_cap: ObjectRef,
    /// Number of mapped frames.
    pub mapped_frames: u32,
    /// Number of child page tables.
    pub page_table_count: u16,
    /// Whether this VSpace is currently active on any CPU.
    pub is_active: bool,
}

impl VSpaceObject {
    /// Create a new VSpace object.
    #[inline]
    #[must_use]
    pub const fn new(root_table: PhysAddr, root_table_cap: ObjectRef) -> Self {
        Self {
            root_table,
            asid: Asid::INVALID,
            root_table_cap,
            mapped_frames: 0,
            page_table_count: 1, // Count the root table
            is_active: false,
        }
    }

    /// Check if an ASID is assigned.
    #[inline]
    #[must_use]
    pub const fn has_asid(&self) -> bool {
        self.asid.is_valid()
    }

    /// Assign an ASID to this VSpace.
    #[inline]
    pub fn assign_asid(&mut self, asid: Asid) {
        self.asid = asid;
    }

    /// Increment the mapped frame count.
    #[inline]
    pub fn increment_frames(&mut self) {
        self.mapped_frames = self.mapped_frames.saturating_add(1);
    }

    /// Decrement the mapped frame count.
    #[inline]
    pub fn decrement_frames(&mut self) {
        self.mapped_frames = self.mapped_frames.saturating_sub(1);
    }

    /// Increment the page table count.
    #[inline]
    pub fn increment_page_tables(&mut self) {
        self.page_table_count = self.page_table_count.saturating_add(1);
    }

    /// Decrement the page table count.
    #[inline]
    pub fn decrement_page_tables(&mut self) {
        self.page_table_count = self.page_table_count.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asid() {
        assert!(!Asid::INVALID.is_valid());
        assert!(Asid::new(1).is_valid());
    }

    #[test]
    fn test_vspace_creation() {
        let vspace = VSpaceObject::new(PhysAddr::new(0x1000), ObjectRef::from_index(1));
        assert!(!vspace.has_asid());
        assert_eq!(vspace.page_table_count, 1);
    }
}
