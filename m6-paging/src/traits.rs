//! Allocator and mapping traits
//!
//! Provides the core traits needed for page table management:
//! - `PageAllocator`: Allocates page table memory
//! - `MapAttributes`: Describes a mapping operation

use crate::address::{TPA, VA};
use crate::permissions::{MemoryType, PtePermissions};
use crate::region::{PhysMemoryRegion, VirtMemoryRegion};

/// Trait for allocating page tables
///
/// Implementations must provide zeroed, page-aligned memory for page tables.
pub trait PageAllocator {
    /// Allocate a page table of the specified type
    ///
    /// Returns a typed physical address to the newly allocated table,
    /// or `None` if allocation fails.
    ///
    /// The allocated memory must be:
    /// - Zeroed (all entries invalid)
    /// - Page-aligned (4KB for 4KB granule)
    /// - Exactly one page in size
    fn allocate_table<T>(&mut self) -> Option<TPA<T>>;
}

/// Trait for TLB invalidation
///
/// After modifying page table entries, TLB invalidation is required
/// to ensure the CPU sees the updated mappings.
pub trait TLBInvalidator {
    /// Invalidate TLB entry for a specific virtual address
    fn invalidate(&self, va: VA);

    /// Invalidate all TLB entries
    fn invalidate_all(&self);
}

/// A no-op TLB invalidator for use during boot
///
/// During boot, before the MMU is enabled, TLB invalidation is not needed.
pub struct NoOpInvalidator;

impl TLBInvalidator for NoOpInvalidator {
    fn invalidate(&self, _va: VA) {}
    fn invalidate_all(&self) {}
}

/// Attributes for a memory mapping operation
#[derive(Clone, Debug)]
pub struct MapAttributes {
    /// Physical memory region to map
    pub phys: PhysMemoryRegion,
    /// Virtual memory region (target addresses)
    pub virt: VirtMemoryRegion,
    /// Memory type (Normal or Device)
    pub mem_type: MemoryType,
    /// Access permissions
    pub perms: PtePermissions,
}

impl MapAttributes {
    /// Create new mapping attributes
    #[inline]
    pub const fn new(
        phys: PhysMemoryRegion,
        virt: VirtMemoryRegion,
        mem_type: MemoryType,
        perms: PtePermissions,
    ) -> Self {
        Self {
            phys,
            virt,
            mem_type,
            perms,
        }
    }

    /// Check if the mapping is valid
    ///
    /// A valid mapping has:
    /// - Equal physical and virtual region sizes
    /// - Non-empty regions
    /// - Page-aligned regions
    #[inline]
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.phys.size() == self.virt.size()
            && !self.phys.is_empty()
            && self.phys.is_page_aligned()
            && self.virt.is_page_aligned()
    }
}

/// Errors that can occur during mapping operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "mapping errors must be handled"]
pub enum MapError {
    /// Physical and virtual region sizes don't match
    SizeMismatch,
    /// Region is too small (less than one page)
    TooSmall,
    /// Region is not page-aligned
    NotAligned,
    /// The virtual address is already mapped
    AlreadyMapped,
    /// Failed to allocate a page table
    AllocationFailed,
    /// Invalid mapping attributes
    InvalidAttributes,
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SizeMismatch => write!(f, "physical and virtual region sizes don't match"),
            Self::TooSmall => write!(f, "region is too small"),
            Self::NotAligned => write!(f, "region is not page-aligned"),
            Self::AlreadyMapped => write!(f, "virtual address is already mapped"),
            Self::AllocationFailed => write!(f, "failed to allocate page table"),
            Self::InvalidAttributes => write!(f, "invalid mapping attributes"),
        }
    }
}
