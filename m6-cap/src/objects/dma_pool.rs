//! DMA pool capability
//!
//! A DmaPool provides IOVA (I/O Virtual Address) allocation for
//! userspace drivers. It manages a region of the I/O address space
//! and tracks allocations using a watermark allocator.
//!
//! # Usage
//!
//! 1. Create a DmaPool from an IOSpace with a base IOVA and size
//! 2. Allocate DMA buffers which return IOVAs
//! 3. Map physical frames to those IOVAs in the IOSpace
//! 4. Devices access memory via the IOVAs
//!
//! # Allocation Strategy
//!
//! Uses a simple bump/watermark allocator. For most DMA patterns,
//! buffers are long-lived and don't need complex free-list management.

use crate::slot::ObjectRef;

/// DMA transfer direction hints for cache coherency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DmaDirection {
    /// Buffer may be read and written by device.
    #[default]
    Bidirectional = 0,
    /// Buffer will only be written by CPU, read by device.
    ToDevice = 1,
    /// Buffer will only be written by device, read by CPU.
    FromDevice = 2,
}

impl DmaDirection {
    /// Create from raw value.
    #[inline]
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Bidirectional),
            1 => Some(Self::ToDevice),
            2 => Some(Self::FromDevice),
            _ => None,
        }
    }
}

/// DmaPool object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct DmaPoolObject {
    /// Associated IOSpace for translations.
    pub iospace: ObjectRef,
    /// Base IOVA for this pool's allocations.
    pub iova_base: u64,
    /// Size of the IOVA region in bytes.
    pub iova_size: u64,
    /// Current allocation watermark (next free IOVA offset).
    pub alloc_watermark: u64,
    /// Number of active allocations.
    pub alloc_count: u32,
    /// Maximum allocation count (0 = unlimited).
    pub max_allocs: u32,
}

impl DmaPoolObject {
    /// Create a new DMA pool.
    #[inline]
    #[must_use]
    pub const fn new(iospace: ObjectRef, iova_base: u64, iova_size: u64) -> Self {
        Self {
            iospace,
            iova_base,
            iova_size,
            alloc_watermark: 0,
            alloc_count: 0,
            max_allocs: 0,
        }
    }

    /// Check if there's space for an allocation of the given size.
    #[inline]
    #[must_use]
    pub const fn can_allocate(&self, size: u64) -> bool {
        self.alloc_watermark.saturating_add(size) <= self.iova_size
    }

    /// Get the remaining space in the pool.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.iova_size.saturating_sub(self.alloc_watermark)
    }

    /// Get the next available IOVA (without allocating).
    #[inline]
    #[must_use]
    pub const fn next_iova(&self) -> u64 {
        self.iova_base.saturating_add(self.alloc_watermark)
    }

    /// Allocate IOVA space with the given size and alignment.
    ///
    /// Returns the allocated IOVA, or None if exhausted.
    /// The alignment must be a power of 2.
    pub fn allocate(&mut self, size: u64, align: u64) -> Option<u64> {
        if size == 0 || align == 0 || !align.is_power_of_two() {
            return None;
        }

        // Align the watermark up
        let align_mask = align - 1;
        let aligned_watermark = (self.alloc_watermark + align_mask) & !align_mask;

        // Check for overflow and space
        let end = aligned_watermark.checked_add(size)?;
        if end > self.iova_size {
            return None;
        }

        // Check max allocations
        if self.max_allocs > 0 && self.alloc_count >= self.max_allocs {
            return None;
        }

        // Perform allocation
        let iova = self.iova_base.saturating_add(aligned_watermark);
        self.alloc_watermark = end;
        self.alloc_count = self.alloc_count.saturating_add(1);

        Some(iova)
    }

    /// Reset the pool (for bulk free).
    ///
    /// This resets the watermark to 0, effectively freeing all allocations.
    /// Only safe when all DMA operations using this pool have completed.
    pub fn reset(&mut self) {
        self.alloc_watermark = 0;
        self.alloc_count = 0;
    }

    /// Set the maximum allocation count.
    #[inline]
    pub fn set_max_allocs(&mut self, max: u32) {
        self.max_allocs = max;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dma_pool_creation() {
        let pool = DmaPoolObject::new(ObjectRef::from_index(1), 0x1_0000_0000, 0x100_0000);
        assert_eq!(pool.iova_base, 0x1_0000_0000);
        assert_eq!(pool.iova_size, 0x100_0000);
        assert_eq!(pool.alloc_watermark, 0);
    }

    #[test]
    fn test_dma_pool_allocation() {
        let mut pool = DmaPoolObject::new(ObjectRef::from_index(1), 0x1000, 0x10000);

        // First allocation
        let iova1 = pool.allocate(0x1000, 0x1000);
        assert_eq!(iova1, Some(0x1000));
        assert_eq!(pool.alloc_count, 1);

        // Second allocation
        let iova2 = pool.allocate(0x2000, 0x1000);
        assert_eq!(iova2, Some(0x2000));
        assert_eq!(pool.alloc_count, 2);

        // Allocation with alignment
        let iova3 = pool.allocate(0x100, 0x1000);
        assert_eq!(iova3, Some(0x5000)); // Aligned to 0x1000
    }

    #[test]
    fn test_dma_pool_exhaustion() {
        let mut pool = DmaPoolObject::new(ObjectRef::from_index(1), 0x1000, 0x2000);

        let iova1 = pool.allocate(0x2000, 0x1000);
        assert!(iova1.is_some());

        // Pool exhausted
        let iova2 = pool.allocate(0x1000, 0x1000);
        assert!(iova2.is_none());
    }

    #[test]
    fn test_dma_pool_reset() {
        let mut pool = DmaPoolObject::new(ObjectRef::from_index(1), 0x1000, 0x10000);

        pool.allocate(0x1000, 0x1000);
        pool.allocate(0x1000, 0x1000);
        assert_eq!(pool.alloc_count, 2);

        pool.reset();
        assert_eq!(pool.alloc_count, 0);
        assert_eq!(pool.alloc_watermark, 0);
    }

    #[test]
    fn test_dma_direction() {
        assert_eq!(DmaDirection::from_u8(0), Some(DmaDirection::Bidirectional));
        assert_eq!(DmaDirection::from_u8(1), Some(DmaDirection::ToDevice));
        assert_eq!(DmaDirection::from_u8(2), Some(DmaDirection::FromDevice));
        assert_eq!(DmaDirection::from_u8(3), None);
    }
}
