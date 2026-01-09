//! I/O address space capability
//!
//! An IOSpace represents an IOMMU translation domain, analogous to
//! VSpace for CPU translations. Each userspace driver that performs
//! DMA requires an IOSpace for isolation.
//!
//! # Structure
//!
//! An IOSpace owns:
//! - A root page table (same format as CPU page tables)
//! - An IOASID for IOTLB isolation
//! - Bindings to stream IDs (PCIe device identifiers)
//! - References to all mapped frames

use m6_common::PhysAddr;

use crate::slot::ObjectRef;

/// I/O Address Space Identifier.
///
/// IOASIDs provide IOTLB isolation between IOSpaces. Each IOSpace
/// requires a unique IOASID to ensure IOTLB entries don't collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Ioasid(u16);

impl Ioasid {
    /// Invalid/unassigned IOASID.
    pub const INVALID: Self = Self(0);

    /// Maximum IOASID value.
    pub const MAX: Self = Self(0xFFFF);

    /// Create a new IOASID.
    #[inline]
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get the raw IOASID value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Check if this is a valid IOASID.
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// IOSpace object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct IOSpaceObject {
    /// Physical address of the root page table.
    /// Uses same format as ARM64 CPU page tables.
    pub root_table: PhysAddr,
    /// Assigned IOASID for IOTLB isolation.
    pub ioasid: Ioasid,
    /// Reference to the root page table capability.
    pub root_table_cap: ObjectRef,
    /// Number of frames mapped for DMA.
    pub mapped_frames: u32,
    /// Number of bound stream IDs.
    pub stream_count: u16,
    /// Whether this IOSpace is currently configured in the SMMU.
    pub is_active: bool,
    /// SMMU instance index (for multi-SMMU systems).
    pub smmu_index: u8,
}

impl IOSpaceObject {
    /// Create a new IOSpace object.
    #[inline]
    #[must_use]
    pub const fn new(root_table: PhysAddr, root_table_cap: ObjectRef, smmu_index: u8) -> Self {
        Self {
            root_table,
            ioasid: Ioasid::INVALID,
            root_table_cap,
            mapped_frames: 0,
            stream_count: 0,
            is_active: false,
            smmu_index,
        }
    }

    /// Check if an IOASID is assigned.
    #[inline]
    #[must_use]
    pub const fn has_ioasid(&self) -> bool {
        self.ioasid.is_valid()
    }

    /// Assign an IOASID to this IOSpace.
    #[inline]
    pub fn assign_ioasid(&mut self, ioasid: Ioasid) {
        self.ioasid = ioasid;
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

    /// Increment the bound stream count.
    #[inline]
    pub fn increment_streams(&mut self) {
        self.stream_count = self.stream_count.saturating_add(1);
    }

    /// Decrement the bound stream count.
    #[inline]
    pub fn decrement_streams(&mut self) {
        self.stream_count = self.stream_count.saturating_sub(1);
    }

    /// Check if any streams are bound.
    #[inline]
    #[must_use]
    pub const fn has_streams(&self) -> bool {
        self.stream_count > 0
    }

    /// Activate this IOSpace in the SMMU.
    #[inline]
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Deactivate this IOSpace.
    #[inline]
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioasid() {
        assert!(!Ioasid::INVALID.is_valid());
        assert!(Ioasid::new(1).is_valid());
        assert_eq!(Ioasid::new(42).value(), 42);
    }

    #[test]
    fn test_iospace_creation() {
        let iospace = IOSpaceObject::new(PhysAddr::new(0x1000), ObjectRef::from_index(1), 0);
        assert!(!iospace.has_ioasid());
        assert!(!iospace.has_streams());
        assert_eq!(iospace.mapped_frames, 0);
    }

    #[test]
    fn test_iospace_counters() {
        let mut iospace = IOSpaceObject::new(PhysAddr::new(0x1000), ObjectRef::from_index(1), 0);

        iospace.increment_frames();
        iospace.increment_frames();
        assert_eq!(iospace.mapped_frames, 2);

        iospace.decrement_frames();
        assert_eq!(iospace.mapped_frames, 1);

        iospace.increment_streams();
        assert!(iospace.has_streams());
    }
}
