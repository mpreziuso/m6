//! Physical Region Page (PRP) Builder
//!
//! NVMe uses PRPs (Physical Region Pages) to describe data buffers for DMA.
//! Each PRP entry is a 64-bit address pointing to a memory page.
//!
//! # PRP Addressing
//!
//! - PRP1: First page of data (may have offset within page)
//! - PRP2: Either second page address or pointer to PRP list

#![allow(dead_code)]
//!
//! # Transfer Sizes
//!
//! - 1 page: PRP1 only
//! - 2 pages: PRP1 + PRP2 (direct addresses)
//! - >2 pages: PRP1 + PRP list at PRP2
//!
//! # PRP List Format
//!
//! A PRP list is a page containing 512 PRP entries (4096 / 8 = 512).
//! Each entry points to a data page. For very large transfers,
//! the last entry can point to another PRP list page.

/// Memory page size (4KB for NVMe default)
pub const MPS: u64 = 4096;

/// Number of PRP entries per list page (4096 / 8 = 512)
pub const PRPS_PER_PAGE: usize = (MPS as usize) / 8;

/// Result of building a PRP chain.
#[derive(Clone, Copy, Debug)]
pub struct PrpResult {
    /// First PRP (can have offset within page)
    pub prp1: u64,
    /// Second PRP or PRP list pointer
    pub prp2: u64,
    /// Number of PRP list pages used (0 if none needed)
    pub prp_list_pages: usize,
}

/// A page containing PRP entries for multi-page transfers.
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct PrpListPage {
    /// PRP entries (512 per page)
    pub entries: [u64; PRPS_PER_PAGE],
}

impl Default for PrpListPage {
    fn default() -> Self {
        Self {
            entries: [0; PRPS_PER_PAGE],
        }
    }
}

impl PrpListPage {
    /// Create a new zeroed PRP list page.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [0; PRPS_PER_PAGE],
        }
    }

    /// Get the number of entries in this page.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        PRPS_PER_PAGE
    }
}

/// Build PRP entries for a data transfer.
///
/// # Arguments
///
/// - `base_iova`: Starting IOVA of the data buffer
/// - `len`: Length of the transfer in bytes
/// - `prp_list_iova`: IOVA of the PRP list page(s) if needed
/// - `prp_list_vaddr`: Virtual address of PRP list page(s) for writing
///
/// # Returns
///
/// A `PrpResult` containing PRP1, PRP2, and number of PRP list pages used.
///
/// # PRP Building Rules
///
/// 1. Single page (len <= MPS - offset): PRP1 = base_iova, PRP2 = 0
/// 2. Two pages: PRP1 = base_iova, PRP2 = next_page_iova
/// 3. More pages: PRP1 = base_iova, PRP2 = prp_list_iova
///
/// # Safety
///
/// The caller must ensure `prp_list_vaddr` points to valid memory
/// if more than 2 pages are needed.
pub fn build_prp(
    base_iova: u64,
    len: u64,
    prp_list_iova: u64,
    prp_list_vaddr: *mut PrpListPage,
) -> PrpResult {
    // Calculate offset within first page
    let offset = base_iova & (MPS - 1);

    // Calculate how much data fits in the first page
    let first_page_len = MPS - offset;

    // Single page transfer
    if len <= first_page_len {
        return PrpResult {
            prp1: base_iova,
            prp2: 0,
            prp_list_pages: 0,
        };
    }

    // Calculate remaining bytes after first page
    let remaining = len - first_page_len;

    // Two page transfer
    if remaining <= MPS {
        return PrpResult {
            prp1: base_iova,
            prp2: (base_iova & !(MPS - 1)) + MPS, // Next page-aligned address
            prp_list_pages: 0,
        };
    }

    // Multi-page transfer - need PRP list
    // Calculate number of pages needed (excluding first page)
    let pages_needed = remaining.div_ceil(MPS) as usize;

    // Fill in the PRP list
    // SAFETY: Caller guarantees prp_list_vaddr is valid if we get here
    unsafe {
        let list = &mut *prp_list_vaddr;
        let mut current_iova = (base_iova & !(MPS - 1)) + MPS; // Start of second page

        for i in 0..pages_needed {
            list.entries[i] = current_iova;
            current_iova += MPS;
        }
    }

    // Calculate how many PRP list pages we used
    let prp_list_pages = pages_needed.div_ceil(PRPS_PER_PAGE);

    PrpResult {
        prp1: base_iova,
        prp2: prp_list_iova,
        prp_list_pages,
    }
}

/// Calculate the number of PRP list pages needed for a transfer.
///
/// # Arguments
///
/// - `base_iova`: Starting IOVA of the data buffer
/// - `len`: Length of the transfer in bytes
///
/// # Returns
///
/// Number of PRP list pages needed (0 if 2 or fewer pages).
#[inline]
#[must_use]
pub const fn prp_list_pages_needed(base_iova: u64, len: u64) -> usize {
    let offset = base_iova & (MPS - 1);
    let first_page_len = MPS - offset;

    if len <= first_page_len {
        return 0; // Single page, no list needed
    }

    let remaining = len - first_page_len;
    if remaining <= MPS {
        return 0; // Two pages, no list needed
    }

    // Multi-page: need PRP list
    let pages_needed = remaining.div_ceil(MPS) as usize;
    pages_needed.div_ceil(PRPS_PER_PAGE)
}

/// Simple PRP list cache for per-queue allocation.
///
/// Provides a fixed pool of PRP list pages for a single queue,
/// avoiding global contention.
pub struct PrpListCache<const N: usize> {
    /// Virtual addresses of cached PRP list pages
    pages_vaddr: [*mut PrpListPage; N],
    /// IOVAs of cached PRP list pages
    pages_iova: [u64; N],
    /// Number of pages in the cache
    count: usize,
    /// Bitmap of free pages (bit set = free)
    free_bitmap: u64,
}

impl<const N: usize> PrpListCache<N> {
    /// Create a new PRP list cache.
    ///
    /// # Arguments
    ///
    /// - `pages_vaddr`: Array of virtual addresses for PRP list pages
    /// - `pages_iova`: Array of IOVAs for PRP list pages
    /// - `count`: Number of pages available
    ///
    /// # Safety
    ///
    /// The caller must ensure all pointers in `pages_vaddr` are valid
    /// and the corresponding IOVAs are correct.
    pub unsafe fn new(
        pages_vaddr: [*mut PrpListPage; N],
        pages_iova: [u64; N],
        count: usize,
    ) -> Self {
        debug_assert!(count <= N);
        debug_assert!(count <= 64, "Free bitmap limited to 64 pages");

        // All pages start as free
        let free_bitmap = if count == 64 {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };

        Self {
            pages_vaddr,
            pages_iova,
            count,
            free_bitmap,
        }
    }

    /// Allocate a PRP list page from the cache.
    ///
    /// Returns `Some((vaddr, iova))` if available, `None` if cache is exhausted.
    pub fn alloc(&mut self) -> Option<(*mut PrpListPage, u64)> {
        if self.free_bitmap == 0 {
            return None;
        }

        // Find first free page
        let idx = self.free_bitmap.trailing_zeros() as usize;
        if idx >= self.count {
            return None;
        }

        // Mark as allocated
        self.free_bitmap &= !(1u64 << idx);

        Some((self.pages_vaddr[idx], self.pages_iova[idx]))
    }

    /// Free a PRP list page back to the cache.
    ///
    /// # Arguments
    ///
    /// - `iova`: IOVA of the page to free
    pub fn free(&mut self, iova: u64) {
        // Find the page by IOVA
        for i in 0..self.count {
            if self.pages_iova[i] == iova {
                self.free_bitmap |= 1u64 << i;
                return;
            }
        }
        // IOVA not found - ignore (or could panic in debug)
        debug_assert!(false, "Attempted to free unknown PRP list IOVA");
    }

    /// Get the number of free pages in the cache.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_bitmap.count_ones() as usize
    }

    /// Check if the cache is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.free_bitmap == 0
    }
}

// SAFETY: PrpListCache can be sent if the pointers it contains are valid
unsafe impl<const N: usize> Send for PrpListCache<N> {}
