//! CNode kernel storage
//!
//! CNodes are variable-size capability tables. They are allocated from
//! the kernel heap with size determined by their radix (2^radix slots).
//!
//! This module implements the [`CNodeOps`] trait from `m6-cap`.

extern crate alloc;

use core::alloc::Layout;
use core::ptr::NonNull;

use m6_cap::{
    CapSlot, CNodeGuard, CNodeMeta, CNodeOps, CNodeRadix, CapError, CapResult,
    MAX_CNODE_RADIX, MIN_CNODE_RADIX,
};

/// CNode kernel storage.
///
/// Allocated from the kernel heap. The structure is:
/// - Fixed header with metadata
/// - Variable-length slot array (16 bytes per slot)
///
/// The total size is `size_of::<CNodeMeta>() + 16 * 2^radix`.
#[repr(C)]
pub struct CNodeStorage {
    /// CNode metadata.
    meta: CNodeMeta,
    /// Capability slots (flexible array).
    ///
    /// This is a zero-length array marker; actual slots follow in memory.
    slots: [CapSlot; 0],
}

impl CNodeStorage {
    /// Calculate the allocation size for a CNode with the given radix.
    pub const fn alloc_size(radix: CNodeRadix) -> usize {
        core::mem::size_of::<CNodeMeta>() + (16 << radix)
    }

    /// Calculate the allocation layout for a CNode.
    pub fn alloc_layout(radix: CNodeRadix) -> Option<Layout> {
        Layout::from_size_align(Self::alloc_size(radix), 16).ok()
    }

    /// Allocate and initialise a new CNode.
    ///
    /// Returns a pointer to the allocated CNode, or `None` if allocation fails.
    pub fn alloc(radix: CNodeRadix, guard: CNodeGuard) -> Option<NonNull<Self>> {
        if !(MIN_CNODE_RADIX..=MAX_CNODE_RADIX).contains(&radix) {
            return None;
        }

        let layout = Self::alloc_layout(radix)?;

        // SAFETY: Layout is valid and non-zero size.
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return None;
        }

        let cnode = ptr as *mut CNodeStorage;

        // Initialise metadata
        // SAFETY: We just allocated this memory.
        unsafe {
            (*cnode).meta = CNodeMeta::new(radix, guard).ok()?;
        }

        NonNull::new(cnode)
    }

    /// Deallocate a CNode.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated by [`alloc`](Self::alloc) and
    /// must not be used after this call.
    pub unsafe fn dealloc(ptr: *mut Self) {
        if ptr.is_null() {
            return;
        }

        // SAFETY: Caller guarantees ptr was allocated by alloc().
        let radix = unsafe { (*ptr).meta.radix() };
        if let Some(layout) = Self::alloc_layout(radix) {
            // SAFETY: Layout matches allocation.
            unsafe { alloc::alloc::dealloc(ptr as *mut u8, layout) };
        }
    }

    /// Get the slots as a slice.
    fn slots(&self) -> &[CapSlot] {
        let num_slots = self.meta.num_slots();
        // SAFETY: We allocated enough space for num_slots slots.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr(), num_slots) }
    }

    /// Get the slots as a mutable slice.
    fn slots_mut(&mut self) -> &mut [CapSlot] {
        let num_slots = self.meta.num_slots();
        // SAFETY: We allocated enough space for num_slots slots.
        unsafe { core::slice::from_raw_parts_mut(self.slots.as_mut_ptr(), num_slots) }
    }
}

impl CNodeOps for CNodeStorage {
    fn get_slot(&self, index: usize) -> Option<&CapSlot> {
        self.slots().get(index)
    }

    fn get_slot_mut(&mut self, index: usize) -> Option<&mut CapSlot> {
        self.slots_mut().get_mut(index)
    }

    fn meta(&self) -> &CNodeMeta {
        &self.meta
    }

    fn meta_mut(&mut self) -> &mut CNodeMeta {
        &mut self.meta
    }
}

/// Create a new CNode and return a raw pointer.
///
/// This is a convenience function for the object table.
pub fn create_cnode(radix: CNodeRadix, guard: CNodeGuard) -> CapResult<*mut CNodeStorage> {
    CNodeStorage::alloc(radix, guard)
        .map(|ptr| ptr.as_ptr())
        .ok_or(CapError::OutOfMemory)
}

/// Destroy a CNode and free its memory.
///
/// # Safety
///
/// The pointer must have been allocated by [`create_cnode`] and must not
/// be used after this call.
pub unsafe fn destroy_cnode(ptr: *mut CNodeStorage) {
    // SAFETY: Caller guarantees validity.
    unsafe { CNodeStorage::dealloc(ptr) }
}
