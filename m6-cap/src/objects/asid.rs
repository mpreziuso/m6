//! ASID management capabilities
//!
//! ASIDs (Address Space Identifiers) provide TLB isolation between
//! different virtual address spaces. The ASID system has two levels:
//!
//! - **ASIDControl**: Singleton capability to create ASID pools
//! - **ASIDPool**: Contains a pool of ASIDs that can be assigned to VSpaces
//!
//! # ARM64 ASID Support
//!
//! ARM64 supports either 8-bit or 16-bit ASIDs depending on the
//! implementation. M6 uses 16-bit ASIDs where available.

use crate::slot::ObjectRef;

/// Number of ASIDs per pool.
///
/// Each pool contains 1024 ASIDs. Multiple pools can be created
/// from ASIDControl if more ASIDs are needed.
pub const ASIDS_PER_POOL: usize = 1024;

/// ASID pool object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct AsidPoolObject {
    /// Base ASID for this pool (pool covers base..base+1023).
    pub base_asid: u16,
    /// Bitmap of allocated ASIDs (1 = allocated, 0 = free).
    /// 1024 bits = 128 bytes = 16 u64s.
    pub allocation_bitmap: [u64; 16],
    /// Number of allocated ASIDs.
    pub allocated_count: u16,
    /// VSpace references for each ASID slot.
    /// Index i corresponds to ASID base_asid + i.
    pub vspace_refs: [ObjectRef; ASIDS_PER_POOL],
}

impl AsidPoolObject {
    /// Create a new ASID pool.
    #[inline]
    #[must_use]
    pub fn new(base_asid: u16) -> Self {
        Self {
            base_asid,
            allocation_bitmap: [0; 16],
            allocated_count: 0,
            vspace_refs: [ObjectRef::NULL; ASIDS_PER_POOL],
        }
    }

    /// Check if all ASIDs are allocated.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.allocated_count as usize >= ASIDS_PER_POOL
    }

    /// Check if the pool is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.allocated_count == 0
    }

    /// Number of free ASIDs.
    #[inline]
    #[must_use]
    pub const fn free_count(&self) -> usize {
        ASIDS_PER_POOL - self.allocated_count as usize
    }

    /// Allocate an ASID from the pool.
    ///
    /// # Returns
    ///
    /// The allocated ASID, or `None` if the pool is full.
    pub fn allocate(&mut self, vspace: ObjectRef) -> Option<u16> {
        // Find first free ASID
        for (word_idx, word) in self.allocation_bitmap.iter_mut().enumerate() {
            if *word != u64::MAX {
                // Find first zero bit
                let bit_idx = (!*word).trailing_zeros() as usize;
                let asid_offset = word_idx * 64 + bit_idx;

                if asid_offset >= ASIDS_PER_POOL {
                    return None;
                }

                // Mark as allocated
                *word |= 1u64 << bit_idx;
                self.allocated_count += 1;
                self.vspace_refs[asid_offset] = vspace;

                return Some(self.base_asid + asid_offset as u16);
            }
        }
        None
    }

    /// Free an ASID back to the pool.
    ///
    /// # Parameters
    ///
    /// - `asid`: The ASID to free (must be within this pool's range)
    pub fn free(&mut self, asid: u16) {
        let offset = asid.saturating_sub(self.base_asid) as usize;
        if offset >= ASIDS_PER_POOL {
            return;
        }

        let word_idx = offset / 64;
        let bit_idx = offset % 64;

        // Check if actually allocated
        if self.allocation_bitmap[word_idx] & (1u64 << bit_idx) != 0 {
            self.allocation_bitmap[word_idx] &= !(1u64 << bit_idx);
            self.allocated_count = self.allocated_count.saturating_sub(1);
            self.vspace_refs[offset] = ObjectRef::NULL;
        }
    }

    /// Check if an ASID is allocated.
    #[inline]
    #[must_use]
    pub fn is_allocated(&self, asid: u16) -> bool {
        let offset = asid.saturating_sub(self.base_asid) as usize;
        if offset >= ASIDS_PER_POOL {
            return false;
        }

        let word_idx = offset / 64;
        let bit_idx = offset % 64;
        self.allocation_bitmap[word_idx] & (1u64 << bit_idx) != 0
    }
}

/// ASID control object metadata.
///
/// There is exactly one ASIDControl capability in the system,
/// given to the root task at boot.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct AsidControlObject {
    /// Number of ASID pools created.
    pub pools_created: u16,
    /// Maximum number of pools (depends on ASID width).
    pub max_pools: u16,
}

impl AsidControlObject {
    /// Create a new ASID control object.
    ///
    /// # Parameters
    ///
    /// - `asid_bits`: Number of ASID bits (8 or 16)
    #[inline]
    #[must_use]
    pub const fn new(asid_bits: u8) -> Self {
        let max_asids = 1u32 << asid_bits;
        let max_pools = (max_asids / ASIDS_PER_POOL as u32) as u16;
        Self {
            pools_created: 0,
            max_pools,
        }
    }

    /// Check if more pools can be created.
    #[inline]
    #[must_use]
    pub const fn can_create_pool(&self) -> bool {
        self.pools_created < self.max_pools
    }

    /// Get the base ASID for the next pool.
    #[inline]
    #[must_use]
    pub const fn next_pool_base(&self) -> u16 {
        self.pools_created * ASIDS_PER_POOL as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asid_pool_allocate() {
        let mut pool = AsidPoolObject::new(0);
        let vspace = ObjectRef::from_index(1);

        let asid = pool.allocate(vspace).unwrap();
        assert_eq!(asid, 0);
        assert!(pool.is_allocated(0));
        assert_eq!(pool.allocated_count, 1);
    }

    #[test]
    fn test_asid_pool_free() {
        let mut pool = AsidPoolObject::new(0);
        let vspace = ObjectRef::from_index(1);

        let asid = pool.allocate(vspace).unwrap();
        pool.free(asid);
        assert!(!pool.is_allocated(asid));
        assert_eq!(pool.allocated_count, 0);
    }

    #[test]
    fn test_asid_control() {
        let ctrl = AsidControlObject::new(16);
        assert!(ctrl.can_create_pool());
        assert_eq!(ctrl.max_pools, 64); // 65536 / 1024
    }
}
