//! Large allocation side table
//!
//! Tracks large (direct-mapped) allocations in a hash table keyed by
//! the returned pointer address.

use crate::config::{MAX_LARGE_ENTRIES, PAGE_SIZE};
use crate::error::AllocError;
use crate::lock::SpinLock;

/// Entry in the large allocation side table
#[derive(Debug, Clone, Copy)]
pub struct LargeEntry {
    /// Virtual address (0 = empty slot)
    pub vaddr: usize,
    /// Requested allocation size
    pub requested_size: usize,
    /// Actual mapped size (page-aligned)
    pub mapped_size: usize,
    /// Number of pages mapped
    pub page_count: usize,
    /// Frame capability pointer for unmapping
    pub frame_cptr: u64,
    /// Whether a guard page is present (if feature enabled)
    #[cfg(feature = "guard-pages")]
    pub has_guard: bool,
}

impl LargeEntry {
    /// Create an empty entry
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            requested_size: 0,
            mapped_size: 0,
            page_count: 0,
            frame_cptr: 0,
            #[cfg(feature = "guard-pages")]
            has_guard: false,
        }
    }

    /// Check if this entry is empty
    pub fn is_empty(&self) -> bool {
        self.vaddr == 0
    }
}

/// Side table tracking large allocations
///
/// Uses open addressing with linear probing.
pub struct LargeSideTable {
    /// Hash table entries
    entries: [LargeEntry; MAX_LARGE_ENTRIES],
    /// Number of active entries
    count: usize,
}

impl LargeSideTable {
    /// Create an empty side table
    pub const fn new() -> Self {
        Self {
            entries: [const { LargeEntry::empty() }; MAX_LARGE_ENTRIES],
            count: 0,
        }
    }

    /// Hash function for addresses
    ///
    /// Addresses are page-aligned so we shift right by 12 bits
    /// and use a multiplicative hash.
    fn hash(vaddr: usize) -> usize {
        let shifted = vaddr >> 12;
        // Use golden ratio constant for good distribution
        shifted.wrapping_mul(0x9e37_79b9_7f4a_7c15) % MAX_LARGE_ENTRIES
    }

    /// Insert a large allocation entry
    ///
    /// # Returns
    /// Ok(()) on success, Err if the table is full
    pub fn insert(&mut self, entry: LargeEntry) -> Result<(), AllocError> {
        if self.count >= MAX_LARGE_ENTRIES {
            return Err(AllocError::SideTableFull);
        }

        let hash = Self::hash(entry.vaddr);

        // Linear probing to find an empty slot
        for i in 0..MAX_LARGE_ENTRIES {
            let idx = (hash + i) % MAX_LARGE_ENTRIES;
            if self.entries[idx].is_empty() {
                self.entries[idx] = entry;
                self.count += 1;
                return Ok(());
            }
        }

        // Should not reach here if count < MAX_LARGE_ENTRIES
        Err(AllocError::SideTableFull)
    }

    /// Look up a large allocation by address
    pub fn lookup(&self, vaddr: usize) -> Option<&LargeEntry> {
        let hash = Self::hash(vaddr);

        for i in 0..MAX_LARGE_ENTRIES {
            let idx = (hash + i) % MAX_LARGE_ENTRIES;
            let entry = &self.entries[idx];

            if entry.vaddr == vaddr {
                return Some(entry);
            }

            if entry.is_empty() {
                // Empty slot means not found (with linear probing)
                break;
            }
        }

        None
    }

    /// Remove a large allocation entry
    ///
    /// # Returns
    /// The removed entry, or None if not found
    pub fn remove(&mut self, vaddr: usize) -> Option<LargeEntry> {
        let hash = Self::hash(vaddr);

        for i in 0..MAX_LARGE_ENTRIES {
            let idx = (hash + i) % MAX_LARGE_ENTRIES;

            if self.entries[idx].vaddr == vaddr {
                let entry = self.entries[idx];
                self.entries[idx] = LargeEntry::empty();
                self.count -= 1;

                // Rehash subsequent entries to maintain linear probing invariant
                self.rehash_after_removal(idx);

                return Some(entry);
            }

            if self.entries[idx].is_empty() {
                break;
            }
        }

        None
    }

    /// Rehash entries after a removal to maintain linear probing invariant
    fn rehash_after_removal(&mut self, removed_idx: usize) {
        let mut idx = (removed_idx + 1) % MAX_LARGE_ENTRIES;

        loop {
            if self.entries[idx].is_empty() {
                break;
            }

            let entry = self.entries[idx];
            self.entries[idx] = LargeEntry::empty();

            // Re-insert the entry
            let hash = Self::hash(entry.vaddr);
            for i in 0..MAX_LARGE_ENTRIES {
                let new_idx = (hash + i) % MAX_LARGE_ENTRIES;
                if self.entries[new_idx].is_empty() {
                    self.entries[new_idx] = entry;
                    break;
                }
            }

            idx = (idx + 1) % MAX_LARGE_ENTRIES;
        }
    }

    /// Get the number of entries in the table
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for LargeSideTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for the large side table
pub struct SyncLargeSideTable {
    inner: SpinLock<LargeSideTable>,
}

impl SyncLargeSideTable {
    /// Create a new synchronised side table
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(LargeSideTable::new()),
        }
    }

    /// Insert an entry
    pub fn insert(&self, entry: LargeEntry) -> Result<(), AllocError> {
        self.inner.lock().insert(entry)
    }

    /// Look up and clone an entry
    pub fn lookup(&self, vaddr: usize) -> Option<LargeEntry> {
        self.inner.lock().lookup(vaddr).copied()
    }

    /// Remove an entry
    pub fn remove(&self, vaddr: usize) -> Option<LargeEntry> {
        self.inner.lock().remove(vaddr)
    }

    /// Get the count
    pub fn count(&self) -> usize {
        self.inner.lock().count()
    }
}

impl Default for SyncLargeSideTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the number of pages needed for a large allocation
pub fn pages_for_size(size: usize) -> usize {
    size.div_ceil(PAGE_SIZE)
}

/// Calculate the mapped size for a large allocation (page-aligned)
pub fn mapped_size(size: usize) -> usize {
    pages_for_size(size) * PAGE_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_lookup_remove() {
        let mut table = LargeSideTable::new();

        let entry = LargeEntry {
            vaddr: 0x1000_0000,
            requested_size: 8192,
            mapped_size: 8192,
            page_count: 2,
            frame_cptr: 1,
            #[cfg(feature = "guard-pages")]
            has_guard: false,
        };

        assert!(table.insert(entry).is_ok());
        assert_eq!(table.count(), 1);

        let found = table.lookup(0x1000_0000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().requested_size, 8192);

        let removed = table.remove(0x1000_0000);
        assert!(removed.is_some());
        assert_eq!(table.count(), 0);

        // Should not find after removal
        assert!(table.lookup(0x1000_0000).is_none());
    }

    #[test]
    fn test_collision_handling() {
        let mut table = LargeSideTable::new();

        // Insert multiple entries
        for i in 0..10 {
            let entry = LargeEntry {
                vaddr: 0x1000_0000 + (i * PAGE_SIZE),
                requested_size: PAGE_SIZE,
                mapped_size: PAGE_SIZE,
                page_count: 1,
                frame_cptr: i as u64,
                #[cfg(feature = "guard-pages")]
                has_guard: false,
            };
            assert!(table.insert(entry).is_ok());
        }

        assert_eq!(table.count(), 10);

        // All should be findable
        for i in 0..10 {
            let found = table.lookup(0x1000_0000 + (i * PAGE_SIZE));
            assert!(found.is_some());
        }
    }

    #[test]
    fn test_pages_for_size() {
        assert_eq!(pages_for_size(1), 1);
        assert_eq!(pages_for_size(4096), 1);
        assert_eq!(pages_for_size(4097), 2);
        assert_eq!(pages_for_size(8192), 2);
    }
}
