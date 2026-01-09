//! Capability pointer (CPtr) addressing
//!
//! A CPtr addresses a capability slot within a CSpace through a hierarchical
//! path of CNode indices. The CPtr is interpreted as concatenated indices
//! into the CNode hierarchy, with optional guard values for efficient
//! addressing.
//!
//! # Structure
//!
//! A CPtr is a 64-bit value interpreted from most-significant to
//! least-significant bits. The interpretation depends on the CNode
//! configuration:
//!
//! ```text
//! | Guard bits | Index bits | Remaining bits (for next level) |
//! ```
//!
//! # Type Safety
//!
//! The [`CPtr<T>`] type is parameterised by the expected object type,
//! providing compile-time safety. The type parameter has no runtime
//! cost (phantom data).

use core::fmt;
use core::marker::PhantomData;

use crate::objects::{CapObjectType, NullObj};

/// Capability pointer - addresses a slot in the CSpace.
///
/// A CPtr is a 64-bit value interpreted as concatenated indices into
/// a hierarchy of CNodes. The type parameter `T` indicates the expected
/// object type, providing compile-time type safety.
///
/// # Type Parameter
///
/// - `T`: The expected capability object type. Use [`NullObj`] for
///   type-erased pointers.
///
/// # Layout
///
/// The CPtr uses `#[repr(transparent)]` for zero-cost abstraction.
/// The inner value is a u64 that encodes the path through the CNode
/// hierarchy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CPtr<T: CapObjectType = NullObj> {
    /// Raw CPtr value.
    value: u64,
    /// Phantom type marker.
    _type: PhantomData<T>,
}

impl<T: CapObjectType> CPtr<T> {
    /// Create a CPtr from a raw value.
    #[inline]
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self {
            value,
            _type: PhantomData,
        }
    }

    /// Get the raw CPtr value.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.value
    }

    /// Create a null CPtr.
    #[inline]
    #[must_use]
    pub const fn null() -> Self {
        Self::from_raw(0)
    }

    /// Check if this is a null CPtr.
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.value == 0
    }

    /// Convert to an untyped CPtr (erases type information).
    #[inline]
    #[must_use]
    pub const fn to_untyped(self) -> RawCPtr {
        CPtr::from_raw(self.value)
    }

    /// Cast to a differently-typed CPtr.
    ///
    /// # Safety
    ///
    /// Caller must ensure the slot actually contains a capability
    /// of type `U`. Incorrect casts may lead to type confusion.
    #[inline]
    #[must_use]
    pub const unsafe fn cast<U: CapObjectType>(self) -> CPtr<U> {
        CPtr::from_raw(self.value)
    }

    /// Create a CPtr from a single slot index.
    ///
    /// This creates a CPtr for a single-level CSpace with the given
    /// index shifted to the appropriate position.
    ///
    /// # Parameters
    ///
    /// - `index`: The slot index within the root CNode
    /// - `radix`: The radix (log2 of slot count) of the root CNode
    #[inline]
    #[must_use]
    pub const fn from_index(index: u64, radix: u8) -> Self {
        // Shift index to the top bits (after any guard)
        let shift = 64 - radix;
        Self::from_raw(index << shift)
    }

    /// Extract the index for a CNode with the given radix.
    ///
    /// # Parameters
    ///
    /// - `radix`: The radix of the CNode
    /// - `depth`: The current resolution depth (bits already consumed)
    ///
    /// # Returns
    ///
    /// The index into the CNode at this level.
    #[inline]
    #[must_use]
    pub const fn extract_index(self, radix: u8, depth: u8) -> usize {
        let shift = 64u8.saturating_sub(depth).saturating_sub(radix);
        let mask = (1u64 << radix) - 1;
        ((self.value >> shift) & mask) as usize
    }

    /// Check if the guard matches at the given depth.
    ///
    /// # Parameters
    ///
    /// - `guard_value`: The expected guard value
    /// - `guard_bits`: The number of guard bits
    /// - `depth`: The current resolution depth
    ///
    /// # Returns
    ///
    /// `true` if the guard matches, `false` otherwise.
    #[inline]
    #[must_use]
    pub const fn check_guard(self, guard_value: u64, guard_bits: u8, depth: u8) -> bool {
        if guard_bits == 0 {
            return true;
        }
        let shift = 64u8.saturating_sub(depth).saturating_sub(guard_bits);
        let mask = (1u64 << guard_bits) - 1;
        let extracted = (self.value >> shift) & mask;
        extracted == guard_value
    }
}

impl<T: CapObjectType> Default for CPtr<T> {
    fn default() -> Self {
        Self::null()
    }
}

impl<T: CapObjectType> fmt::Debug for CPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "CPtr<{}>::null()", T::NAME)
        } else {
            write!(f, "CPtr<{}>({:#018x})", T::NAME, self.value)
        }
    }
}

impl<T: CapObjectType> fmt::Display for CPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "null")
        } else {
            write!(f, "{:#x}", self.value)
        }
    }
}

impl<T: CapObjectType> fmt::LowerHex for CPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.value, f)
    }
}

impl<T: CapObjectType> fmt::UpperHex for CPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.value, f)
    }
}

/// Untyped CPtr (type-erased).
///
/// This is the default CPtr type when the capability type is not
/// statically known.
pub type RawCPtr = CPtr<NullObj>;

/// CPtr depth - tracks resolution progress.
///
/// During CPtr resolution, we track how many bits have been consumed.
/// This helps detect depth exceeded errors and determines where to
/// extract the next index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CptrDepth {
    /// Number of bits consumed so far.
    bits_consumed: u8,
}

impl CptrDepth {
    /// Maximum depth (all 64 bits consumed).
    pub const MAX: Self = Self { bits_consumed: 64 };

    /// Start of resolution (no bits consumed).
    pub const START: Self = Self { bits_consumed: 0 };

    /// Create a new depth tracker.
    #[inline]
    #[must_use]
    pub const fn new(bits_consumed: u8) -> Self {
        Self {
            bits_consumed: if bits_consumed > 64 {
                64
            } else {
                bits_consumed
            },
        }
    }

    /// Get the number of bits consumed.
    #[inline]
    #[must_use]
    pub const fn bits_consumed(self) -> u8 {
        self.bits_consumed
    }

    /// Get the number of bits remaining.
    #[inline]
    #[must_use]
    pub const fn bits_remaining(self) -> u8 {
        64 - self.bits_consumed
    }

    /// Check if all bits have been consumed.
    #[inline]
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.bits_consumed >= 64
    }

    /// Consume bits for a guard and index.
    #[inline]
    #[must_use]
    pub const fn consume(self, guard_bits: u8, radix: u8) -> Self {
        let total = guard_bits.saturating_add(radix);
        let new_consumed = self.bits_consumed.saturating_add(total);
        Self {
            bits_consumed: if new_consumed > 64 { 64 } else { new_consumed },
        }
    }

    /// Check if there are enough bits remaining for the given guard and radix.
    #[inline]
    #[must_use]
    pub const fn has_room(self, guard_bits: u8, radix: u8) -> bool {
        let needed = guard_bits.saturating_add(radix);
        self.bits_remaining() >= needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::Endpoint;

    #[test]
    fn test_cptr_null() {
        let cptr: CPtr<Endpoint> = CPtr::null();
        assert!(cptr.is_null());
        assert_eq!(cptr.raw(), 0);
    }

    #[test]
    fn test_cptr_from_index() {
        // 8-bit radix (256 slots), index 5
        let cptr: RawCPtr = CPtr::from_index(5, 8);
        let index = cptr.extract_index(8, 0);
        assert_eq!(index, 5);
    }

    #[test]
    fn test_cptr_guard_check() {
        // Create a CPtr with guard value 0b11 in top 2 bits
        let cptr: RawCPtr = CPtr::from_raw(0xC000_0000_0000_0000);
        assert!(cptr.check_guard(0b11, 2, 0));
        assert!(!cptr.check_guard(0b10, 2, 0));
    }

    #[test]
    fn test_depth_tracking() {
        let depth = CptrDepth::START;
        assert_eq!(depth.bits_remaining(), 64);

        let depth = depth.consume(4, 8); // 4 guard bits + 8 radix bits
        assert_eq!(depth.bits_consumed(), 12);
        assert_eq!(depth.bits_remaining(), 52);
    }
}
