//! Page table object capabilities
//!
//! Page tables form the virtual memory mapping hierarchy on ARM64.
//! M6 uses 4-level paging with 4KB granule:
//!
//! - **L0**: Top-level table (512 entries, each covers 512GB)
//! - **L1**: Second-level table (512 entries, each covers 1GB)
//! - **L2**: Third-level table (512 entries, each covers 2MB)
//! - **L3**: Leaf-level table (512 entries, each covers 4KB)
//!
//! Each page table occupies exactly one 4KB frame.

use m6_common::PhysAddr;

use crate::slot::ObjectRef;

/// Page table level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PageTableLevel {
    /// Level 0 (top-level, 512GB per entry).
    L0 = 0,
    /// Level 1 (1GB per entry).
    L1 = 1,
    /// Level 2 (2MB per entry, can be block descriptor).
    L2 = 2,
    /// Level 3 (4KB per entry, leaf level).
    L3 = 3,
}

impl PageTableLevel {
    /// Coverage of each entry at this level in bytes.
    #[must_use]
    pub const fn entry_coverage(self) -> usize {
        match self {
            Self::L0 => 512 * 1024 * 1024 * 1024, // 512GB
            Self::L1 => 1024 * 1024 * 1024,       // 1GB
            Self::L2 => 2 * 1024 * 1024,          // 2MB
            Self::L3 => 4096,                     // 4KB
        }
    }

    /// Number of entries in a page table at this level.
    #[must_use]
    pub const fn num_entries(self) -> usize {
        512 // All levels have 512 entries with 4KB granule
    }

    /// Index bits for this level (9 bits per level).
    #[must_use]
    pub const fn index_bits(self) -> u8 {
        9
    }

    /// Shift amount for extracting the index from a virtual address.
    #[must_use]
    pub const fn index_shift(self) -> u8 {
        match self {
            Self::L0 => 39,
            Self::L1 => 30,
            Self::L2 => 21,
            Self::L3 => 12,
        }
    }

    /// Next level down (None for L3).
    #[must_use]
    pub const fn next_level(self) -> Option<Self> {
        match self {
            Self::L0 => Some(Self::L1),
            Self::L1 => Some(Self::L2),
            Self::L2 => Some(Self::L3),
            Self::L3 => None,
        }
    }

    /// Can this level have block descriptors (huge pages)?
    #[must_use]
    pub const fn supports_block(self) -> bool {
        matches!(self, Self::L1 | Self::L2)
    }
}

/// Page table object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct PageTableObject {
    /// Physical address of the page table.
    pub phys_addr: PhysAddr,
    /// Page table level.
    pub level: PageTableLevel,
    /// VSpace this page table belongs to.
    pub vspace: ObjectRef,
    /// Number of valid entries.
    pub valid_entries: u16,
    /// Whether this is mapped (installed in a parent table).
    pub is_mapped: bool,
}

impl PageTableObject {
    /// Size of a page table in bytes (always 4KB).
    pub const SIZE: usize = 4096;

    /// Create a new page table object.
    #[inline]
    #[must_use]
    pub const fn new(phys_addr: PhysAddr, level: PageTableLevel, vspace: ObjectRef) -> Self {
        Self {
            phys_addr,
            level,
            vspace,
            valid_entries: 0,
            is_mapped: false,
        }
    }

    /// Check if the page table is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.valid_entries == 0
    }

    /// Check if the page table is full.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.valid_entries >= 512
    }

    /// Increment the valid entry count.
    #[inline]
    pub fn increment_entries(&mut self) {
        self.valid_entries = self.valid_entries.saturating_add(1);
    }

    /// Decrement the valid entry count.
    #[inline]
    pub fn decrement_entries(&mut self) {
        self.valid_entries = self.valid_entries.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_coverage() {
        assert_eq!(PageTableLevel::L3.entry_coverage(), 4096);
        assert_eq!(PageTableLevel::L2.entry_coverage(), 2 * 1024 * 1024);
    }

    #[test]
    fn test_level_progression() {
        assert_eq!(PageTableLevel::L0.next_level(), Some(PageTableLevel::L1));
        assert_eq!(PageTableLevel::L3.next_level(), None);
    }
}
