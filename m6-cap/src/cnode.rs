//! CNode - Capability Node container
//!
//! A CNode is a table of capability slots, addressed by index. CNodes
//! form the hierarchical capability space (CSpace) structure, where
//! CNodes can reference other CNodes.
//!
//! # Addressing
//!
//! CNodes use guards to enable efficient addressing. A guard is a
//! sequence of bits that must match in the CPtr before the index
//! is extracted. This allows skipping levels in the hierarchy when
//! the CPtr structure is known.
//!
//! # Configuration
//!
//! - **Radix**: The number of slots is 2^radix (e.g., radix 8 = 256 slots)
//! - **Guard**: Optional prefix bits for efficient addressing
//! - **Size**: CNode size in bytes = 16 * 2^radix (each slot is 16 bytes)

use core::fmt;

use crate::CPtr;
use crate::cptr::CptrDepth;
use crate::error::CapError;
use crate::objects::NullObj;
use crate::slot::CapSlot;

/// CNode radix type.
///
/// The radix determines the number of slots in the CNode:
/// - `radix = 1`: 2 slots
/// - `radix = 8`: 256 slots
/// - `radix = 12`: 4096 slots
pub type CNodeRadix = u8;

/// Minimum CNode radix (2^1 = 2 slots).
pub const MIN_CNODE_RADIX: CNodeRadix = 1;

/// Maximum CNode radix (2^12 = 4096 slots).
///
/// This limit ensures CNodes don't consume excessive memory and that
/// CPtr resolution terminates in reasonable time.
pub const MAX_CNODE_RADIX: CNodeRadix = 12;

/// Maximum guard size in bits.
pub const MAX_GUARD_BITS: u8 = 58;

/// Guard value for CPtr resolution.
///
/// Guards allow efficient CPtr addressing by requiring certain bits
/// to match before extracting the index. This enables:
///
/// - Skipping levels in a sparse CSpace
/// - Efficient single-level addressing
/// - Namespace isolation between components
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct CNodeGuard {
    /// The guard value to match.
    pub value: u64,
    /// Number of bits in the guard (0-58).
    pub bits: u8,
}

impl CNodeGuard {
    /// No guard (matches everything, consumes no bits).
    pub const NONE: Self = Self { value: 0, bits: 0 };

    /// Create a new guard.
    ///
    /// # Parameters
    ///
    /// - `value`: The guard value (only `bits` LSBs are used)
    /// - `bits`: Number of guard bits (0 to MAX_GUARD_BITS)
    ///
    /// # Panics
    ///
    /// Panics if `bits > MAX_GUARD_BITS`.
    #[inline]
    #[must_use]
    pub const fn new(value: u64, bits: u8) -> Self {
        assert!(bits <= MAX_GUARD_BITS);
        let mask = if bits == 64 {
            u64::MAX
        } else if bits == 0 {
            0
        } else {
            (1u64 << bits) - 1
        };
        Self {
            value: value & mask,
            bits,
        }
    }

    /// Try to create a new guard, returning None if bits is too large.
    #[inline]
    #[must_use]
    pub const fn try_new(value: u64, bits: u8) -> Option<Self> {
        if bits > MAX_GUARD_BITS {
            None
        } else {
            Some(Self::new(value, bits))
        }
    }

    /// Check if a CPtr matches this guard at the given depth.
    ///
    /// # Parameters
    ///
    /// - `cptr`: The capability pointer to check
    /// - `depth`: Current resolution depth (bits already consumed)
    ///
    /// # Returns
    ///
    /// `true` if the guard matches, `false` otherwise.
    #[inline]
    #[must_use]
    pub const fn matches(&self, cptr: CPtr<NullObj>, depth: CptrDepth) -> bool {
        cptr.check_guard(self.value, self.bits, depth.bits_consumed())
    }

    /// Check if this is an empty guard (no bits).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }
}

impl fmt::Display for CNodeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "no guard")
        } else {
            write!(f, "guard({:#x}, {} bits)", self.value, self.bits)
        }
    }
}

/// CNode metadata (stored separately from slots for cache efficiency).
///
/// This structure contains the configuration of a CNode. It is stored
/// separately from the slot array to improve cache efficiency when
/// iterating over slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CNodeMeta {
    /// Number of slots as 2^radix.
    radix: CNodeRadix,
    /// Guard for CPtr resolution.
    guard: CNodeGuard,
    /// Number of used (non-empty) slots.
    used_slots: u32,
}

impl CNodeMeta {
    /// Create metadata for a new CNode.
    ///
    /// # Parameters
    ///
    /// - `radix`: The CNode radix (1 to MAX_CNODE_RADIX)
    /// - `guard`: The guard configuration
    ///
    /// # Errors
    ///
    /// Returns `CapError::InvalidRadix` if radix is out of range.
    pub const fn new(radix: CNodeRadix, guard: CNodeGuard) -> Result<Self, CapError> {
        if radix < MIN_CNODE_RADIX || radix > MAX_CNODE_RADIX {
            return Err(CapError::InvalidRadix);
        }
        Ok(Self {
            radix,
            guard,
            used_slots: 0,
        })
    }

    /// Create metadata with no guard.
    pub const fn with_radix(radix: CNodeRadix) -> Result<Self, CapError> {
        Self::new(radix, CNodeGuard::NONE)
    }

    /// Get the radix.
    #[inline]
    #[must_use]
    pub const fn radix(&self) -> CNodeRadix {
        self.radix
    }

    /// Get the guard.
    #[inline]
    #[must_use]
    pub const fn guard(&self) -> CNodeGuard {
        self.guard
    }

    /// Get the number of slots in this CNode.
    #[inline]
    #[must_use]
    pub const fn num_slots(&self) -> usize {
        1 << self.radix
    }

    /// Get the number of used slots.
    #[inline]
    #[must_use]
    pub const fn used_slots(&self) -> u32 {
        self.used_slots
    }

    /// Get the number of free slots.
    #[inline]
    #[must_use]
    pub const fn free_slots(&self) -> u32 {
        (self.num_slots() as u32).saturating_sub(self.used_slots)
    }

    /// Check if the CNode is full.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.used_slots as usize >= self.num_slots()
    }

    /// Check if the CNode is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.used_slots == 0
    }

    /// Increment the used slot count.
    pub fn increment_used(&mut self) {
        self.used_slots = self.used_slots.saturating_add(1);
    }

    /// Decrement the used slot count.
    pub fn decrement_used(&mut self) {
        self.used_slots = self.used_slots.saturating_sub(1);
    }

    /// Total bits consumed by this CNode (guard + radix).
    #[inline]
    #[must_use]
    pub const fn bits_consumed(&self) -> u8 {
        self.guard.bits.saturating_add(self.radix)
    }

    /// Size of the CNode in bytes.
    ///
    /// Each slot is 16 bytes, so total size is 16 * 2^radix.
    #[inline]
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        16 << self.radix
    }
}

/// CNode operations trait.
///
/// This trait defines operations on a CNode. The kernel implements
/// this for its internal CNode storage, allowing `m6-cap` to define
/// the logic while the kernel provides the storage.
pub trait CNodeOps {
    /// Get a reference to a slot by index.
    fn get_slot(&self, index: usize) -> Option<&CapSlot>;

    /// Get a mutable reference to a slot by index.
    fn get_slot_mut(&mut self, index: usize) -> Option<&mut CapSlot>;

    /// Get the CNode metadata.
    fn meta(&self) -> &CNodeMeta;

    /// Get mutable CNode metadata.
    fn meta_mut(&mut self) -> &mut CNodeMeta;

    /// Resolve a CPtr through this CNode.
    ///
    /// This resolves one level of CPtr addressing:
    /// 1. Check the guard matches
    /// 2. Extract the index
    /// 3. Return the index and updated depth
    ///
    /// # Parameters
    ///
    /// - `cptr`: The capability pointer to resolve
    /// - `depth`: Current resolution depth
    ///
    /// # Returns
    ///
    /// On success, returns `(index, new_depth)`.
    ///
    /// # Errors
    ///
    /// - `CapError::GuardMismatch`: Guard bits don't match
    /// - `CapError::DepthExceeded`: Not enough bits remaining
    /// - `CapError::InvalidIndex`: Computed index is out of bounds
    fn resolve_local(
        &self,
        cptr: CPtr<NullObj>,
        depth: CptrDepth,
    ) -> Result<(usize, CptrDepth), CapError> {
        let meta = self.meta();

        // Check if we have enough bits remaining
        if !depth.has_room(meta.guard.bits, meta.radix) {
            return Err(CapError::DepthExceeded);
        }

        // Check guard
        if !meta.guard.matches(cptr, depth) {
            return Err(CapError::GuardMismatch);
        }

        // Consume guard bits and extract index
        let after_guard = depth.consume(meta.guard.bits, 0);
        let index = cptr.extract_index(meta.radix, after_guard.bits_consumed());
        let new_depth = after_guard.consume(0, meta.radix);

        // Validate index
        if index >= meta.num_slots() {
            return Err(CapError::InvalidIndex);
        }

        Ok((index, new_depth))
    }

    /// Find the first empty slot.
    ///
    /// # Returns
    ///
    /// The index of the first empty slot, or `None` if full.
    fn find_empty_slot(&self) -> Option<usize> {
        let num_slots = self.meta().num_slots();
        for i in 0..num_slots {
            if let Some(slot) = self.get_slot(i)
                && slot.is_empty()
            {
                return Some(i);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_creation() {
        let guard = CNodeGuard::new(0xFF, 8);
        assert_eq!(guard.value, 0xFF);
        assert_eq!(guard.bits, 8);
    }

    #[test]
    fn test_guard_masking() {
        // Value should be masked to guard bits
        let guard = CNodeGuard::new(0xFFFF, 4);
        assert_eq!(guard.value, 0x0F);
    }

    #[test]
    fn test_meta_creation() {
        let meta = CNodeMeta::new(8, CNodeGuard::NONE).unwrap();
        assert_eq!(meta.radix(), 8);
        assert_eq!(meta.num_slots(), 256);
        assert_eq!(meta.size_bytes(), 4096);
    }

    #[test]
    fn test_invalid_radix() {
        assert!(CNodeMeta::new(0, CNodeGuard::NONE).is_err());
        assert!(CNodeMeta::new(13, CNodeGuard::NONE).is_err());
    }

    #[test]
    fn test_bits_consumed() {
        let meta = CNodeMeta::new(8, CNodeGuard::new(0, 4)).unwrap();
        assert_eq!(meta.bits_consumed(), 12); // 4 guard + 8 radix
    }
}
