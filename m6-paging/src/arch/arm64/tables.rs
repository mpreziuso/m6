//! ARM64 page table types
//!
//! Provides type-safe wrappers for page tables at each level:
//! - L0Table: Top level (512GB per entry)
//! - L1Table: Second level (1GB per entry)
//! - L2Table: Third level (2MB per entry)
//! - L3Table: Bottom level (4KB per entry)
//!
//! Each table type enforces correct descriptor usage through the type system.

use core::ptr;

use super::descriptors::{
    L0Descriptor, L1Descriptor, L2Descriptor, L3Descriptor, PageTableEntry, TableMapper,
};
use crate::address::{TPA, VA};
use crate::{ENTRIES_PER_TABLE, PAGE_SIZE};

/// Mask for extracting table index from virtual address
const INDEX_MASK: u64 = 0x1FF; // 9 bits = 512 entries

/// Trait for page table operations
///
/// Implemented by each level's table type to provide level-specific
/// indexing and descriptor access.
pub trait PgTable: Clone + Copy + Sized {
    /// Shift amount for extracting index from virtual address
    const SHIFT: usize;

    /// Descriptor type for this level
    type Descriptor: PageTableEntry;

    /// Create a table wrapper from a typed physical address
    ///
    /// # Safety
    /// The address must point to a valid, aligned page table.
    unsafe fn from_pa(pa: TPA<Self>) -> Self;

    /// Get the physical address of this table
    fn to_pa(self) -> TPA<Self>;

    /// Calculate table index from virtual address
    #[inline]
    fn index(va: VA) -> usize {
        ((va.value() >> Self::SHIFT) & INDEX_MASK) as usize
    }

    /// Get descriptor at the given virtual address
    fn get_desc(&self, va: VA) -> Self::Descriptor;

    /// Set descriptor at the given virtual address
    ///
    /// # Safety
    /// Caller must ensure the descriptor is valid and that any TLB
    /// invalidation is performed as needed.
    unsafe fn set_desc(&mut self, va: VA, desc: Self::Descriptor);

    /// Get raw pointer to the table entries
    fn as_ptr(&self) -> *const u64;

    /// Get mutable raw pointer to the table entries
    fn as_mut_ptr(&mut self) -> *mut u64;

    /// Clear all entries (make invalid)
    ///
    /// # Safety
    /// Caller must ensure no mappings are in use and TLB is invalidated.
    unsafe fn clear(&mut self) {
        // SAFETY: Caller guarantees the table is safe to clear
        unsafe {
            ptr::write_bytes(self.as_mut_ptr(), 0, ENTRIES_PER_TABLE);
        }
    }
}

/// Trait for table levels that can point to a next level
pub trait TableLevel: PgTable
where
    Self::Descriptor: TableMapper,
{
    /// The next level table type
    type NextLevel: PgTable;

    /// Get the next-level table if one exists
    ///
    /// Returns `None` if the entry is invalid, a block mapping, or doesn't
    /// point to a table.
    fn get_next_table(&self, va: VA) -> Option<Self::NextLevel> {
        let desc = self.get_desc(va);
        let pa = desc.next_table_address()?;
        // SAFETY: If next_table_address returns Some, the address points to a valid table
        Some(unsafe { Self::NextLevel::from_pa(pa.cast()) })
    }
}

// =============================================================================
// L0 Table
// =============================================================================

/// L0 page table (512GB per entry, table only)
#[derive(Clone, Copy)]
pub struct L0Table {
    base: *mut u64,
}

// SAFETY: Page tables are shared between CPUs in SMP systems
unsafe impl Send for L0Table {}
unsafe impl Sync for L0Table {}

impl PgTable for L0Table {
    const SHIFT: usize = 39;
    type Descriptor = L0Descriptor;

    #[inline]
    unsafe fn from_pa(pa: TPA<Self>) -> Self {
        Self {
            base: pa.as_mut_ptr(),
        }
    }

    #[inline]
    fn to_pa(self) -> TPA<Self> {
        // SAFETY: We created this from a TPA, so converting back is safe
        unsafe { TPA::from_ptr(self.base) }
    }

    #[inline]
    fn get_desc(&self, va: VA) -> Self::Descriptor {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        // SAFETY: index is bounds-checked by INDEX_MASK
        unsafe { L0Descriptor::from_raw(ptr::read_volatile(self.base.add(index))) }
    }

    #[inline]
    unsafe fn set_desc(&mut self, va: VA, desc: Self::Descriptor) {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        // SAFETY: index is bounds-checked, caller ensures validity
        unsafe {
            ptr::write_volatile(self.base.add(index), desc.as_raw());
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u64 {
        self.base
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u64 {
        self.base
    }
}

impl TableLevel for L0Table {
    type NextLevel = L1Table;
}

impl core::fmt::Debug for L0Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L0Table({:p})", self.base)
    }
}

// =============================================================================
// L1 Table
// =============================================================================

/// L1 page table (1GB per entry, table or block)
#[derive(Clone, Copy)]
pub struct L1Table {
    base: *mut u64,
}

unsafe impl Send for L1Table {}
unsafe impl Sync for L1Table {}

impl PgTable for L1Table {
    const SHIFT: usize = 30;
    type Descriptor = L1Descriptor;

    #[inline]
    unsafe fn from_pa(pa: TPA<Self>) -> Self {
        Self {
            base: pa.as_mut_ptr(),
        }
    }

    #[inline]
    fn to_pa(self) -> TPA<Self> {
        unsafe { TPA::from_ptr(self.base) }
    }

    #[inline]
    fn get_desc(&self, va: VA) -> Self::Descriptor {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe { L1Descriptor::from_raw(ptr::read_volatile(self.base.add(index))) }
    }

    #[inline]
    unsafe fn set_desc(&mut self, va: VA, desc: Self::Descriptor) {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe {
            ptr::write_volatile(self.base.add(index), desc.as_raw());
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u64 {
        self.base
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u64 {
        self.base
    }
}

impl TableLevel for L1Table {
    type NextLevel = L2Table;
}

impl core::fmt::Debug for L1Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L1Table({:p})", self.base)
    }
}

// =============================================================================
// L2 Table
// =============================================================================

/// L2 page table (2MB per entry, table or block)
#[derive(Clone, Copy)]
pub struct L2Table {
    base: *mut u64,
}

unsafe impl Send for L2Table {}
unsafe impl Sync for L2Table {}

impl PgTable for L2Table {
    const SHIFT: usize = 21;
    type Descriptor = L2Descriptor;

    #[inline]
    unsafe fn from_pa(pa: TPA<Self>) -> Self {
        Self {
            base: pa.as_mut_ptr(),
        }
    }

    #[inline]
    fn to_pa(self) -> TPA<Self> {
        unsafe { TPA::from_ptr(self.base) }
    }

    #[inline]
    fn get_desc(&self, va: VA) -> Self::Descriptor {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe { L2Descriptor::from_raw(ptr::read_volatile(self.base.add(index))) }
    }

    #[inline]
    unsafe fn set_desc(&mut self, va: VA, desc: Self::Descriptor) {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe {
            ptr::write_volatile(self.base.add(index), desc.as_raw());
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u64 {
        self.base
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u64 {
        self.base
    }
}

impl TableLevel for L2Table {
    type NextLevel = L3Table;
}

impl core::fmt::Debug for L2Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L2Table({:p})", self.base)
    }
}

// =============================================================================
// L3 Table
// =============================================================================

/// L3 page table (4KB per entry, page only)
#[derive(Clone, Copy)]
pub struct L3Table {
    base: *mut u64,
}

unsafe impl Send for L3Table {}
unsafe impl Sync for L3Table {}

impl PgTable for L3Table {
    const SHIFT: usize = 12;
    type Descriptor = L3Descriptor;

    #[inline]
    unsafe fn from_pa(pa: TPA<Self>) -> Self {
        Self {
            base: pa.as_mut_ptr(),
        }
    }

    #[inline]
    fn to_pa(self) -> TPA<Self> {
        unsafe { TPA::from_ptr(self.base) }
    }

    #[inline]
    fn get_desc(&self, va: VA) -> Self::Descriptor {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe { L3Descriptor::from_raw(ptr::read_volatile(self.base.add(index))) }
    }

    #[inline]
    unsafe fn set_desc(&mut self, va: VA, desc: Self::Descriptor) {
        let index = Self::index(va);
        debug_assert!(index < ENTRIES_PER_TABLE);
        unsafe {
            ptr::write_volatile(self.base.add(index), desc.as_raw());
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u64 {
        self.base
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u64 {
        self.base
    }
}

// Note: L3 does not implement TableLevel as it's the last level

impl core::fmt::Debug for L3Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "L3Table({:p})", self.base)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Initialize a page table by zeroing all entries
///
/// # Safety
/// The physical address must point to a valid, writable page of memory.
#[inline]
pub unsafe fn zero_table(pa: TPA<()>) {
    unsafe {
        ptr::write_bytes(pa.as_mut_ptr::<u8>(), 0, PAGE_SIZE);
    }
}
