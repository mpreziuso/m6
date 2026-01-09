//! CNode object capability
//!
//! A CNode (Capability Node) is a table of capability slots that forms
//! the hierarchical capability space (CSpace). CNodes can reference
//! other CNodes, creating a tree structure for capability addressing.
//!
//! # Structure
//!
//! - Each CNode has 2^radix slots (radix 1-12, so 2-4096 slots)
//! - Each slot is 16 bytes ([`CapSlot`](crate::CapSlot))
//! - Total size: 16 * 2^radix bytes (32 bytes to 64KB)

use m6_common::PhysAddr;

use crate::cnode::{CNodeGuard, CNodeRadix, MAX_CNODE_RADIX, MIN_CNODE_RADIX};
use crate::slot::ObjectRef;

/// CNode object metadata.
///
/// This is stored in the kernel's object table. The actual slot
/// storage is at `phys_addr`.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CNodeObject {
    /// Physical address of the slot array.
    pub phys_addr: PhysAddr,
    /// Radix (log2 of slot count).
    pub radix: CNodeRadix,
    /// Guard for CPtr resolution.
    pub guard: CNodeGuard,
    /// Number of non-empty slots.
    pub used_slots: u32,
    /// Owner TCB (for debugging/accounting).
    pub owner: ObjectRef,
}

impl CNodeObject {
    /// Create a new CNode object.
    ///
    /// # Parameters
    ///
    /// - `phys_addr`: Physical address of the slot array
    /// - `radix`: Number of slots as 2^radix
    /// - `owner`: Owner TCB reference
    #[inline]
    #[must_use]
    pub const fn new(phys_addr: PhysAddr, radix: CNodeRadix, owner: ObjectRef) -> Self {
        Self {
            phys_addr,
            radix,
            guard: CNodeGuard::NONE,
            used_slots: 0,
            owner,
        }
    }

    /// Create a new CNode with a guard.
    #[inline]
    #[must_use]
    pub const fn with_guard(
        phys_addr: PhysAddr,
        radix: CNodeRadix,
        guard: CNodeGuard,
        owner: ObjectRef,
    ) -> Self {
        Self {
            phys_addr,
            radix,
            guard,
            used_slots: 0,
            owner,
        }
    }

    /// Number of slots in this CNode.
    #[inline]
    #[must_use]
    pub const fn num_slots(&self) -> usize {
        1 << self.radix
    }

    /// Size of the slot array in bytes.
    #[inline]
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        16 << self.radix
    }

    /// Check if the CNode is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.used_slots == 0
    }

    /// Check if the CNode is full.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.used_slots as usize >= self.num_slots()
    }

    /// Number of free slots.
    #[inline]
    #[must_use]
    pub const fn free_slots(&self) -> usize {
        self.num_slots().saturating_sub(self.used_slots as usize)
    }

    /// Increment the used slot count.
    #[inline]
    pub fn increment_used(&mut self) {
        self.used_slots = self.used_slots.saturating_add(1);
    }

    /// Decrement the used slot count.
    #[inline]
    pub fn decrement_used(&mut self) {
        self.used_slots = self.used_slots.saturating_sub(1);
    }

    /// Check if the radix is valid.
    #[inline]
    #[must_use]
    pub const fn is_valid_radix(radix: CNodeRadix) -> bool {
        radix >= MIN_CNODE_RADIX && radix <= MAX_CNODE_RADIX
    }

    /// Bits consumed during CPtr resolution.
    #[inline]
    #[must_use]
    pub const fn bits_consumed(&self) -> u8 {
        self.guard.bits + self.radix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnode_size() {
        let cnode = CNodeObject::new(PhysAddr::new(0x1000), 8, ObjectRef::NULL);
        assert_eq!(cnode.num_slots(), 256);
        assert_eq!(cnode.size_bytes(), 4096);
    }

    #[test]
    fn test_cnode_valid_radix() {
        assert!(!CNodeObject::is_valid_radix(0));
        assert!(CNodeObject::is_valid_radix(1));
        assert!(CNodeObject::is_valid_radix(12));
        assert!(!CNodeObject::is_valid_radix(13));
    }
}
