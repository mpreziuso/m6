// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `usercopy` — fault-aware copies between Starnix (normal-mode) and
//! user/restricted-mode buffers.
//!
//! M6 adaptation: the pure slice-shaping helpers ([`slice_to_maybe_uninit_mut`])
//! are ported verbatim. The fault-aware raw copy routines that upstream backs
//! with a Zircon exception-handling thread are provided here as documented,
//! functional-but-simplified versions: M6 does not yet expose a per-thread
//! page-fault recovery mechanism for these helpers, so the copies are performed
//! as plain in-process `memcpy`/`memset` against addresses that fall inside the
//! configured restricted address range. They cannot recover from a genuine
//! fault; an out-of-range address is treated as a fault and copies zero bytes.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(unused)]
// The atomic helpers return `Result<_, ()>` to mirror the upstream Starnix
// `Usercopy` API exactly (the fork relies on these signatures); a custom error
// type would diverge from the surface the fork imports.
#![allow(clippy::result_unit_err)]

extern crate alloc;

use core::mem::MaybeUninit;
use core::ops::Range;
use core::sync::atomic::{AtomicU32, Ordering};

// -- Pure slice helpers (ported verbatim)

/// Converts a slice to an equivalent `MaybeUninit` slice.
pub fn slice_to_maybe_uninit_mut<T>(slice: &mut [T]) -> &mut [MaybeUninit<T>] {
    let ptr = slice.as_mut_ptr();
    let ptr = ptr as *mut MaybeUninit<T>;
    // SAFETY: This is effectively reinterpreting the `slice` reference as a
    // slice of uninitialised T's. `MaybeUninit<T>` has the same layout[1] as
    // `T` and we know the original slice is initialised and it's okay to go from
    // initialised to maybe-initialised.
    //
    // [1]: https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#layout-1
    unsafe { core::slice::from_raw_parts_mut(ptr, slice.len()) }
}

/// Assumes the buffer's first `initialized_until` bytes are initialised and
/// returns the initialised and uninitialised portions.
///
/// # Safety
///
/// The caller must guarantee that `buf`'s first `initialized_until` bytes are
/// initialised.
unsafe fn assume_initialized_until(
    buf: &mut [MaybeUninit<u8>],
    initialized_until: usize,
) -> (&mut [u8], &mut [MaybeUninit<u8>]) {
    let (init_bytes, uninit_bytes) = buf.split_at_mut(initialized_until);
    debug_assert_eq!(init_bytes.len(), initialized_until);

    // SAFETY: by the caller's contract the first `initialized_until` bytes are
    // initialised, so reinterpreting them as initialised `u8`s is sound.
    let init_bytes = unsafe {
        core::slice::from_raw_parts_mut(init_bytes.as_mut_ptr() as *mut u8, init_bytes.len())
    };

    (init_bytes, uninit_bytes)
}

// -- Usercopy

/// Fault-aware copier between normal-mode and restricted/user-mode memory.
///
/// M6 adaptation: upstream spawns an exception-handling thread that catches
/// page faults raised by hand-written assembly copy routines. M6 has no such
/// mechanism wired yet, so this implementation performs ordinary in-process
/// copies but still honours the restricted address range bounds-check that
/// upstream relies on (addresses outside the range, or the address `0`, are
/// treated as faults and copy zero bytes). The copies therefore cannot recover
/// from a genuine hardware fault.
#[derive(Debug)]
pub struct Usercopy {
    /// The range of the restricted address space.
    restricted_address_range: Range<usize>,
}

impl Usercopy {
    /// Returns a new instance of `Usercopy` for the given restricted address
    /// range.
    ///
    /// M6 adaptation: this never fails (upstream may fail to create the
    /// exception-handling thread), so it always returns `Ok`.
    pub fn new(restricted_address_range: Range<usize>) -> Result<Self, zx::Status> {
        Ok(Self { restricted_address_range })
    }

    #[inline]
    fn in_range(&self, addr: usize) -> bool {
        // Assumption: the address 0 is invalid and cannot be mapped. The error
        // encoding scheme has a collision on the value 0 — it could mean a fault
        // at address 0 or no fault. We always treat 0 as a fault.
        addr != 0 && self.restricted_address_range.contains(&addr)
    }

    /// Copies bytes from the source address to the destination address.
    ///
    /// Returns the number of bytes copied (`count` on success).
    ///
    /// # Safety
    ///
    /// Only one of `source`/`dest` may be an address to a buffer owned by
    /// user/restricted-mode (`ret_dest` indicates whether the user-owned buffer
    /// is `dest` when `true`). The other must be a valid Starnix/normal-mode
    /// buffer that will never cause a fault when the first `count` bytes are
    /// read/written.
    pub unsafe fn raw_hermetic_copy(
        &self,
        dest: *mut u8,
        source: *const u8,
        count: usize,
        ret_dest: bool,
    ) -> usize {
        let user_addr = if ret_dest { dest as usize } else { source as usize };
        if !self.in_range(user_addr) {
            return 0;
        }
        // SAFETY: the caller guarantees that the non-user buffer is valid for
        // `count` bytes and the user buffer is in-range and (by M6's simplified
        // model) backed by mapped memory.
        unsafe { core::ptr::copy(source, dest, count) };
        count
    }

    /// Zeros `count` bytes starting at `dest_addr`.
    ///
    /// Returns the number of bytes zeroed.
    pub fn zero(&self, dest_addr: usize, count: usize) -> usize {
        if !self.in_range(dest_addr) {
            return 0;
        }
        // SAFETY: `dest_addr` is in the restricted range and, under M6's
        // simplified model, backed by mapped writable memory for `count` bytes.
        unsafe { core::ptr::write_bytes(dest_addr as *mut u8, 0, count) };
        count
    }

    /// Copies data from `source` to the restricted address `dest_addr`.
    ///
    /// Returns the number of bytes copied.
    pub fn copyout(&self, source: &[u8], dest_addr: usize) -> usize {
        if !self.in_range(dest_addr) {
            return 0;
        }
        // SAFETY: `dest_addr` is in-range and `source` is a valid Starnix-owned
        // buffer of `source.len()` bytes.
        unsafe { core::ptr::copy(source.as_ptr(), dest_addr as *mut u8, source.len()) };
        source.len()
    }

    /// Copies data from the restricted address `source_addr` to `dest`.
    ///
    /// Returns the read and unread bytes. The returned slices always reference
    /// `dest`, so `dest` and the returned initialised slice share an address.
    pub fn copyin<'a>(
        &self,
        source_addr: usize,
        dest: &'a mut [MaybeUninit<u8>],
    ) -> (&'a mut [u8], &'a mut [MaybeUninit<u8>]) {
        let read_count = if !self.in_range(source_addr) {
            0
        } else {
            // SAFETY: `source_addr` is in-range and `dest` is a valid
            // Starnix-owned buffer of `dest.len()` bytes.
            unsafe {
                core::ptr::copy(
                    source_addr as *const u8,
                    dest.as_mut_ptr() as *mut u8,
                    dest.len(),
                );
            }
            dest.len()
        };

        // SAFETY: `dest`'s first `read_count` bytes are now initialised.
        unsafe { assume_initialized_until(dest, read_count) }
    }

    /// Copies data from the restricted address `source_addr` to `dest` until the
    /// first null byte (inclusive).
    ///
    /// Returns the read and unread bytes. The read bytes include the null byte
    /// if present.
    pub fn copyin_until_null_byte<'a>(
        &self,
        source_addr: usize,
        dest: &'a mut [MaybeUninit<u8>],
    ) -> (&'a mut [u8], &'a mut [MaybeUninit<u8>]) {
        let read_count = if !self.in_range(source_addr) {
            0
        } else {
            let len = dest.len();
            let mut copied = 0;
            // Copy byte-by-byte so we can stop at the first NUL like `strncpy`.
            while copied < len {
                // SAFETY: `source_addr + copied` is within the user buffer and
                // `dest[copied]` is within the destination buffer.
                let byte = unsafe { *((source_addr + copied) as *const u8) };
                dest[copied].write(byte);
                copied += 1;
                if byte == 0 {
                    break;
                }
            }
            copied
        };

        // SAFETY: `dest`'s first `read_count` bytes are now initialised.
        unsafe { assume_initialized_until(dest, read_count) }
    }

    // -- Atomics
    //
    // M6 adaptation: these operate on `AtomicU32`s synthesised over the user
    // address. They honour the restricted-range bounds-check (an out-of-range
    // address yields `Err(())`, mirroring a fault) but cannot recover from a
    // genuine fault.

    #[inline]
    fn atomic_ref(&self, addr: usize) -> Option<&AtomicU32> {
        if !self.in_range(addr) {
            return None;
        }
        // SAFETY: `addr` is in the restricted range, 4-byte aligned by the
        // caller's contract, and (under M6's simplified model) backed by mapped
        // memory holding a `u32`.
        Some(unsafe { &*(addr as *const AtomicU32) })
    }

    /// Performs an atomic load of a 32-bit value at `addr`.
    /// `addr` must be aligned to 4 bytes.
    pub fn atomic_load_u32_relaxed(&self, addr: usize) -> Result<u32, ()> {
        self.atomic_ref(addr).map(|a| a.load(Ordering::Relaxed)).ok_or(())
    }

    /// Performs an atomic load of a 32-bit value at `addr`.
    /// `addr` must be aligned to 4 bytes.
    pub fn atomic_load_u32_acquire(&self, addr: usize) -> Result<u32, ()> {
        self.atomic_ref(addr).map(|a| a.load(Ordering::Acquire)).ok_or(())
    }

    /// Performs an atomic store of a 32-bit value to `addr`.
    /// `addr` must be aligned to 4 bytes.
    pub fn atomic_store_u32_relaxed(&self, addr: usize, value: u32) -> Result<(), ()> {
        match self.atomic_ref(addr) {
            Some(a) => {
                a.store(value, Ordering::Relaxed);
                Ok(())
            }
            None => Err(()),
        }
    }

    /// Performs an atomic store of a 32-bit value to `addr`.
    /// `addr` must be aligned to 4 bytes.
    pub fn atomic_store_u32_release(&self, addr: usize, value: u32) -> Result<(), ()> {
        match self.atomic_ref(addr) {
            Some(a) => {
                a.store(value, Ordering::Release);
                Ok(())
            }
            None => Err(()),
        }
    }

    /// Performs an atomic compare-and-exchange of a 32-bit value at `addr`.
    /// `addr` must be aligned to 4 bytes.
    ///
    /// The outer `Result` distinguishes a fault (`Err(())`) from a completed
    /// operation; the inner `Result` is `Ok(observed)` on success and
    /// `Err(observed)` when the exchange did not take place.
    pub fn atomic_compare_exchange_u32_acq_rel(
        &self,
        addr: usize,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, ()> {
        match self.atomic_ref(addr) {
            Some(a) => Ok(a.compare_exchange(
                expected,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            )),
            None => Err(()),
        }
    }

    /// Performs a weak atomic compare-and-exchange of a 32-bit value at `addr`.
    /// `addr` must be aligned to 4 bytes.
    pub fn atomic_compare_exchange_weak_u32_acq_rel(
        &self,
        addr: usize,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, ()> {
        match self.atomic_ref(addr) {
            Some(a) => Ok(a.compare_exchange_weak(
                expected,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            )),
            None => Err(()),
        }
    }
}
