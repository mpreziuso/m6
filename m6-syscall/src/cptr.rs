//! CPtr (capability pointer) formatting utilities
//!
//! seL4-style CPtrs use MSB-first bit extraction. For a CNode with radix R,
//! a cptr to slot S should have S in the top R bits.
//!
//! For a flat CSpace (single root CNode with no guard), the conversion is:
//! ```text
//! cptr = slot_index << (64 - radix)
//! ```
//!
//! Example for radix 12 (4096 slots):
//! - Slot 0: cptr = 0x0000_0000_0000_0000
//! - Slot 1: cptr = 0x0001_0000_0000_0000
//! - Slot 7: cptr = 0x0007_0000_0000_0000

/// Convert a slot index to a CPtr for a flat CSpace.
///
/// # Arguments
///
/// * `slot` - The slot index in the CNode
/// * `radix` - The CNode's radix (log2 of number of slots)
///
/// # Returns
///
/// The properly formatted CPtr value for MSB-first extraction.
#[inline]
#[must_use]
pub const fn slot_to_cptr(slot: u64, radix: u8) -> u64 {
    let shift = 64u8.saturating_sub(radix);
    slot << shift
}

/// Convert a CPtr back to a slot index for a flat CSpace.
///
/// # Arguments
///
/// * `cptr` - The capability pointer
/// * `radix` - The CNode's radix
///
/// # Returns
///
/// The slot index extracted from the CPtr.
#[inline]
#[must_use]
pub const fn cptr_to_slot(cptr: u64, radix: u8) -> u64 {
    let shift = 64u8.saturating_sub(radix);
    cptr >> shift
}

/// CPtr context for a specific CSpace configuration.
///
/// Stores the radix so you don't need to pass it to every conversion.
#[derive(Clone, Copy, Debug)]
pub struct CptrContext {
    /// The CNode radix (log2 of number of slots).
    pub radix: u8,
}

impl CptrContext {
    /// Create a new CPtr context for a CNode with the given radix.
    #[inline]
    #[must_use]
    pub const fn new(radix: u8) -> Self {
        Self { radix }
    }

    /// Convert a slot index to a CPtr.
    #[inline]
    #[must_use]
    pub const fn slot(&self, index: u64) -> u64 {
        slot_to_cptr(index, self.radix)
    }

    /// Convert a CPtr back to a slot index.
    #[inline]
    #[must_use]
    pub const fn index(&self, cptr: u64) -> u64 {
        cptr_to_slot(cptr, self.radix)
    }
}
