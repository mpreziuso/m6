//! Kernel CPRNG bindings
//!
//! Placeholder entropy source. Both functions always fill their buffer; the
//! bytes are currently zeroes until an M6 entropy source is wired in. This is a
//! documented stub, not a secure random source.

use core::mem::MaybeUninit;

/// Draws random bytes to fill `buffer`. Always fills the whole buffer.
pub fn cprng_draw(buffer: &mut [u8]) {
    // SAFETY: `&mut [u8]` and `&mut [MaybeUninit<u8>]` share the same layout.
    let uninit = unsafe {
        core::slice::from_raw_parts_mut(
            buffer.as_mut_ptr().cast::<MaybeUninit<u8>>(),
            buffer.len(),
        )
    };
    cprng_draw_uninit(uninit);
}

/// Draws random bytes to fill `buffer`, returning the now-initialised slice.
pub fn cprng_draw_uninit(buffer: &mut [MaybeUninit<u8>]) -> &mut [u8] {
    let ptr = buffer.as_mut_ptr().cast::<u8>();
    let len = buffer.len();
    // SAFETY: `zx_cprng_draw` fully initialises `len` bytes at `ptr`, which is
    // valid for writes for the lifetime of `buffer`.
    unsafe {
        crate::sys::zx_cprng_draw(ptr, len);
        core::slice::from_raw_parts_mut(ptr, len)
    }
}
