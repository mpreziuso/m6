//! Memory poisoning patterns
//!
//! Feature-gated under the `debug-poison` feature.
//! Writes recognisable patterns to memory on allocation and free
//! to help detect use-after-free and use-of-uninitialised bugs.

/// Pattern for freshly allocated memory
pub const ALLOC_POISON: u8 = 0xAA;

/// Pattern for freed memory
pub const FREE_POISON: u8 = 0xDD;

/// Pattern for guard bytes (if used)
pub const GUARD_POISON: u8 = 0xFD;

/// Poison freshly allocated memory
///
/// Fills the memory with `ALLOC_POISON` pattern to help detect
/// use of uninitialised memory.
pub fn poison_alloc(ptr: *mut u8, len: usize) {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        core::ptr::write_bytes(ptr, ALLOC_POISON, len);
    }
}

/// Poison freed memory
///
/// Fills the memory with `FREE_POISON` pattern to help detect
/// use-after-free bugs.
pub fn poison_free(ptr: *mut u8, len: usize) {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        core::ptr::write_bytes(ptr, FREE_POISON, len);
    }
}

/// Verify that memory contains the free poison pattern
///
/// Returns true if all bytes match `FREE_POISON`.
/// Used to detect corruption of freed memory.
pub fn verify_free_poison(ptr: *const u8, len: usize) -> bool {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    slice.iter().all(|&b| b == FREE_POISON)
}

/// Verify that memory contains the alloc poison pattern
///
/// Returns true if all bytes match `ALLOC_POISON`.
/// Used to detect if memory was properly poisoned on allocation.
pub fn verify_alloc_poison(ptr: *const u8, len: usize) -> bool {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    slice.iter().all(|&b| b == ALLOC_POISON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poison_patterns() {
        let mut buf = [0u8; 64];

        poison_alloc(buf.as_mut_ptr(), buf.len());
        assert!(verify_alloc_poison(buf.as_ptr(), buf.len()));

        poison_free(buf.as_mut_ptr(), buf.len());
        assert!(verify_free_poison(buf.as_ptr(), buf.len()));
    }
}
