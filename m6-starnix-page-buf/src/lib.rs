// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2025 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Buffers backed by VMOs mapped into the root VMAR.
//!
//! M6 adaptation: upstream backs each `PageBuf` with a Zircon VMO mapped into
//! the root VMAR (and optionally a second, pinning VMAR). M6 cannot map into a
//! shared `Arc<zx::Vmar>` yet, so the buffer is instead backed by a page-rounded
//! heap allocation. The public API the fork relies on is preserved exactly; the
//! "extra VMAR" is retained for parity but never mapped into. The backing
//! allocation lives for the lifetime of the `PageBuf` and is released on drop.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(unused)]

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

const DEFAULT_VMO_NAME: zx::Name = zx::Name::from_bytes_lossy(b"starnix_page_buf");

/// A buffer backed by a page-rounded allocation.
///
/// M6 adaptation: upstream maps a VMO into the root VMAR (and an optional extra
/// VMAR); here the backing store is a heap allocation. The optional extra VMAR
/// is kept for API parity but is not mapped into.
pub struct PageBuf<T> {
    base: NonNull<MaybeUninit<u8>>,
    mapped_len: usize,
    extra_vmar: Option<Arc<zx::Vmar>>,
    _ty: PhantomData<T>,
}

impl<T> core::fmt::Debug for PageBuf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `zx::Vmar` does not implement `Debug`; omit the extra VMAR handle.
        f.debug_struct("PageBuf")
            .field("base", &self.base)
            .field("mapped_len", &self.mapped_len)
            .field("has_extra_vmar", &self.extra_vmar.is_some())
            .finish()
    }
}

impl<T> PageBuf<T> {
    /// Create a new `PageBuf`.
    pub fn new(capacity: usize) -> Result<Self, zx::Status> {
        Self::new_internal(capacity, None)
    }

    /// Create a new `PageBuf` and also retain the provided "extra" VMAR.
    ///
    /// M6 adaptation: upstream maps the backing VMO into `extra_vmar` read-only
    /// to pin it; here the VMAR is retained but not mapped into.
    pub fn new_with_extra_vmar(
        capacity: usize,
        extra_vmar: Arc<zx::Vmar>,
    ) -> Result<Self, zx::Status> {
        Self::new_internal(capacity, Some(extra_vmar))
    }

    fn new_internal(capacity: usize, extra_vmar: Option<Arc<zx::Vmar>>) -> Result<Self, zx::Status> {
        let page_size = zx::system_get_page_size() as usize;
        let capacity_bytes = capacity.saturating_mul(core::mem::size_of::<T>());
        // Round up to a whole number of pages, mirroring the VMO mapping length.
        // Always allocate at least one page so the base pointer is non-null.
        let mapped_len = capacity_bytes.next_multiple_of(page_size).max(page_size);

        // The slice produced by `as_mut` must be aligned for `T`; allocate with
        // at least `T`'s alignment (and at least the page size for parity with
        // the VMO mapping's page alignment).
        let align = core::mem::align_of::<T>().max(page_size);
        let layout =
            Layout::from_size_align(mapped_len, align).map_err(|_| zx::Status::INVALID_ARGS)?;

        // SAFETY: `layout` has a non-zero size (>= one page).
        let ptr = unsafe { alloc(layout) } as *mut MaybeUninit<u8>;
        let base = NonNull::new(ptr).ok_or(zx::Status::NO_MEMORY)?;

        let this = Self { base, mapped_len, extra_vmar, _ty: PhantomData };
        this.set_name(&DEFAULT_VMO_NAME);
        Ok(this)
    }

    /// Set the name of the buffer's backing object.
    ///
    /// M6 adaptation: there is no backing VMO to name, so this is a no-op kept
    /// for API parity.
    pub fn set_name(&self, name: &zx::Name) {
        let _ = name;
    }

    /// Number of `T` elements that fit in the buffer.
    pub fn len(&self) -> usize {
        self.len_bytes() / core::mem::size_of::<T>()
    }

    /// Whether the buffer holds no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of bytes in the backing allocation.
    pub fn len_bytes(&self) -> usize {
        self.mapped_len
    }

    /// Return a mutable reference to the underlying memory.
    // Name mirrors the upstream Starnix `PageBuf::as_mut` that the fork calls;
    // it intentionally shadows the inherent-method shape of `AsMut::as_mut`.
    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut [MaybeUninit<T>] {
        assert!(
            core::mem::align_of::<T>() <= zx::system_get_page_size() as usize,
            "can't handle types with alignment greater than a page yet"
        );

        // SAFETY: the base address is valid for `mapped_len` bytes for as long as
        // `self` is live, and the `&mut self` receiver gives exclusive access.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.mapped_len) };
        let num_elems = bytes.len() / core::mem::size_of::<T>();
        let bytes_as_t = bytes.as_mut_ptr().cast::<MaybeUninit<T>>();

        // SAFETY: `MaybeUninit<T>` imposes no requirements on the backing memory
        // and `num_elems` keeps the slice within the bounds of `bytes`. The base
        // is aligned to at least `align_of::<T>()` by construction.
        unsafe { core::slice::from_raw_parts_mut(bytes_as_t, num_elems) }
    }

    fn layout(&self) -> Layout {
        let align = core::mem::align_of::<T>().max(zx::system_get_page_size() as usize);
        // SAFETY: these are the same arguments used by `new_internal`, which
        // already validated them.
        unsafe { Layout::from_size_align_unchecked(self.mapped_len, align) }
    }
}

// SAFETY: PageBuf owns a unique heap allocation; it can be sent across threads
// if T is Send.
unsafe impl<T: Send> Send for PageBuf<T> {}
// SAFETY: PageBuf has no interior mutability reachable through `&self`; it is Sync
// if T is Sync.
unsafe impl<T: Sync> Sync for PageBuf<T> {}

impl<T> Drop for PageBuf<T> {
    fn drop(&mut self) {
        let layout = self.layout();
        // SAFETY: the allocation was made with this exact layout in
        // `new_internal` and is owned uniquely by this `PageBuf`.
        unsafe { dealloc(self.base.as_ptr() as *mut u8, layout) };
    }
}
