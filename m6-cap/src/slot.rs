//! Capability slot storage
//!
//! A capability slot is the fundamental unit of capability storage.
//! Each slot holds exactly one capability or is empty. Slots are
//! organised into CNodes (capability nodes) which form the hierarchical
//! capability space (CSpace).
//!
//! # Layout
//!
//! The [`CapSlot`] structure is carefully designed to fit in 16 bytes,
//! allowing 4 slots per cache line (64 bytes) on most architectures.
//! This improves cache efficiency and enables atomic operations on
//! the entire slot.

use core::fmt;

use crate::{Badge, CapRights};

/// Object reference - kernel-internal index to the actual object.
///
/// This is an index into the kernel's object table, not a raw pointer.
/// Using indices provides several benefits:
///
/// - **Bounds checking**: Index can be validated against table size
/// - **Revocation safety**: Clearing a table entry invalidates all references
/// - **Compact**: 32 bits is sufficient for millions of objects
/// - **No pointer provenance issues**: Simpler unsafe code
///
/// # Null Reference
///
/// An `ObjectRef` of zero (`ObjectRef::NULL`) indicates no object is
/// referenced. This is used for empty capability slots.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ObjectRef(u32);

impl ObjectRef {
    /// Null reference (no object).
    pub const NULL: Self = Self(0);

    /// Create an object reference from a raw index.
    ///
    /// # Note
    ///
    /// Index 0 is reserved for NULL. Valid object indices start at 1.
    #[inline]
    #[must_use]
    pub const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Get the raw index value.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }

    /// Check if this is a null reference.
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if this is a valid (non-null) reference.
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "ObjectRef::NULL")
        } else {
            write!(f, "ObjectRef({})", self.0)
        }
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "null")
        } else {
            write!(f, "#{}", self.0)
        }
    }
}

/// Object type discriminant.
///
/// This enum identifies the type of kernel object that a capability
/// refers to. It is stored as a single byte in the capability slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum ObjectType {
    /// Empty slot (no capability).
    #[default]
    Empty = 0,

    // Memory objects
    /// Untyped memory.
    Untyped = 1,
    /// Normal memory frame.
    Frame = 2,
    /// Device memory frame.
    DeviceFrame = 3,
    /// Page table level 0.
    PageTableL0 = 4,
    /// Page table level 1.
    PageTableL1 = 5,
    /// Page table level 2.
    PageTableL2 = 6,
    /// Page table level 3.
    PageTableL3 = 7,
    /// Virtual address space.
    VSpace = 8,

    // ASID objects
    /// ASID pool.
    ASIDPool = 9,
    /// ASID control.
    ASIDControl = 10,

    // IPC objects
    /// Synchronous endpoint.
    Endpoint = 11,
    /// Asynchronous notification.
    Notification = 12,
    /// One-time reply.
    Reply = 13,

    // Execution objects
    /// Capability node (CNode).
    CNode = 14,
    /// Thread control block.
    TCB = 15,

    // System objects
    /// IRQ handler.
    IRQHandler = 16,
    /// IRQ control.
    IRQControl = 17,
    /// Scheduling context.
    SchedContext = 18,
    /// Scheduling control.
    SchedControl = 19,

    // IOMMU objects
    /// I/O address space (IOMMU translation domain).
    IOSpace = 20,
    /// DMA buffer pool.
    DmaPool = 21,
    /// SMMU control (singleton).
    SmmuControl = 22,
}

impl ObjectType {
    /// Get the human-readable name for this object type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty => "Empty",
            Self::Untyped => "Untyped",
            Self::Frame => "Frame",
            Self::DeviceFrame => "DeviceFrame",
            Self::PageTableL0 => "PageTableL0",
            Self::PageTableL1 => "PageTableL1",
            Self::PageTableL2 => "PageTableL2",
            Self::PageTableL3 => "PageTableL3",
            Self::VSpace => "VSpace",
            Self::ASIDPool => "ASIDPool",
            Self::ASIDControl => "ASIDControl",
            Self::Endpoint => "Endpoint",
            Self::Notification => "Notification",
            Self::Reply => "Reply",
            Self::CNode => "CNode",
            Self::TCB => "TCB",
            Self::IRQHandler => "IRQHandler",
            Self::IRQControl => "IRQControl",
            Self::SchedContext => "SchedContext",
            Self::SchedControl => "SchedControl",
            Self::IOSpace => "IOSpace",
            Self::DmaPool => "DmaPool",
            Self::SmmuControl => "SmmuControl",
        }
    }

    /// Check if this object type supports badging.
    #[inline]
    #[must_use]
    pub const fn supports_badge(self) -> bool {
        matches!(self, Self::Endpoint | Self::Notification)
    }

    /// Check if this is an empty slot.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Check if this is a memory object type.
    #[inline]
    #[must_use]
    pub const fn is_memory(self) -> bool {
        matches!(
            self,
            Self::Untyped
                | Self::Frame
                | Self::DeviceFrame
                | Self::PageTableL0
                | Self::PageTableL1
                | Self::PageTableL2
                | Self::PageTableL3
                | Self::VSpace
        )
    }

    /// Check if this is an IPC object type.
    #[inline]
    #[must_use]
    pub const fn is_ipc(self) -> bool {
        matches!(self, Self::Endpoint | Self::Notification | Self::Reply)
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Slot flags for internal bookkeeping.
///
/// These flags track metadata about the capability slot that is not
/// part of the capability's logical content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SlotFlags(u16);

impl SlotFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);

    /// This slot is part of a CDT (has parent or children).
    pub const IN_CDT: Self = Self(1 << 0);

    /// This is the original capability (root of derivation).
    pub const IS_ORIGINAL: Self = Self(1 << 1);

    /// Check if a flag is set.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    #[inline]
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Clear a flag.
    #[inline]
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Get the raw bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Create from raw bits.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
}

/// Capability slot - stores a single capability.
///
/// # Layout
///
/// The slot is carefully packed into 16 bytes for cache efficiency:
///
/// | Offset | Size | Field       | Description                           |
/// |--------|------|-------------|---------------------------------------|
/// | 0      | 4    | object_ref  | Index into kernel object table        |
/// | 4      | 1    | cap_type    | Object type discriminant              |
/// | 5      | 1    | rights      | Access rights (packed)                |
/// | 6      | 2    | flags       | Slot flags (CDT membership, etc.)     |
/// | 8      | 8    | badge       | Badge value for IPC identification    |
///
/// This layout allows 4 slots per 64-byte cache line.
///
/// # Invariants
///
/// - If `cap_type` is `ObjectType::Empty`, all other fields are zero
/// - `badge` is only meaningful if `cap_type.supports_badge()` is true
/// - `object_ref` is null if and only if `cap_type` is `Empty`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct CapSlot {
    /// Reference to the kernel object (index, not pointer).
    object_ref: ObjectRef,
    /// Type of the capability.
    cap_type: ObjectType,
    /// Access rights.
    rights: CapRights,
    /// Slot flags (for CDT tracking).
    flags: SlotFlags,
    /// Badge value (for minted capabilities).
    badge: Badge,
}

// Compile-time size and alignment verification
const _: () = assert!(core::mem::size_of::<CapSlot>() == 16);
const _: () = assert!(core::mem::align_of::<CapSlot>() == 16);

impl CapSlot {
    /// Create an empty slot.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            object_ref: ObjectRef::NULL,
            cap_type: ObjectType::Empty,
            rights: CapRights::NONE,
            flags: SlotFlags::NONE,
            badge: Badge::NONE,
        }
    }

    /// Create a new capability slot.
    #[inline]
    #[must_use]
    pub const fn new(
        object_ref: ObjectRef,
        cap_type: ObjectType,
        rights: CapRights,
        badge: Badge,
        flags: SlotFlags,
    ) -> Self {
        Self {
            object_ref,
            cap_type,
            rights,
            flags,
            badge,
        }
    }

    /// Check if the slot is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cap_type.is_empty()
    }

    /// Get the object reference.
    #[inline]
    #[must_use]
    pub const fn object_ref(&self) -> ObjectRef {
        self.object_ref
    }

    /// Get the capability type.
    #[inline]
    #[must_use]
    pub const fn cap_type(&self) -> ObjectType {
        self.cap_type
    }

    /// Get the access rights.
    #[inline]
    #[must_use]
    pub const fn rights(&self) -> CapRights {
        self.rights
    }

    /// Get the badge.
    #[inline]
    #[must_use]
    pub const fn badge(&self) -> Badge {
        self.badge
    }

    /// Get the flags.
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> SlotFlags {
        self.flags
    }

    /// Set the flags.
    #[inline]
    pub fn set_flags(&mut self, flags: SlotFlags) {
        self.flags = flags;
    }

    /// Clear the slot (make empty).
    #[inline]
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Check if this slot has the specified right.
    #[inline]
    #[must_use]
    pub const fn has_right(&self, right: CapRights) -> bool {
        self.rights.contains(right)
    }

    /// Check if this is in the CDT.
    #[inline]
    #[must_use]
    pub const fn is_in_cdt(&self) -> bool {
        self.flags.contains(SlotFlags::IN_CDT)
    }

    /// Check if this is an original capability.
    #[inline]
    #[must_use]
    pub const fn is_original(&self) -> bool {
        self.flags.contains(SlotFlags::IS_ORIGINAL)
    }
}

impl Default for CapSlot {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for CapSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "<empty>")
        } else {
            write!(f, "{} {} [{}]", self.cap_type, self.object_ref, self.rights)?;
            if self.badge.is_some() {
                write!(f, " badge={}", self.badge)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_size() {
        assert_eq!(core::mem::size_of::<CapSlot>(), 16);
        assert_eq!(core::mem::align_of::<CapSlot>(), 16);
    }

    #[test]
    fn test_empty_slot() {
        let slot = CapSlot::empty();
        assert!(slot.is_empty());
        assert!(slot.object_ref().is_null());
        assert_eq!(slot.cap_type(), ObjectType::Empty);
    }

    #[test]
    fn test_object_type_badge_support() {
        assert!(ObjectType::Endpoint.supports_badge());
        assert!(ObjectType::Notification.supports_badge());
        assert!(!ObjectType::Frame.supports_badge());
        assert!(!ObjectType::TCB.supports_badge());
    }
}
