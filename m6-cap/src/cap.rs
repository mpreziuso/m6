//! Type-safe capability references
//!
//! This module provides [`Cap<T>`], a type-safe handle to a capability
//! that enforces type safety at compile time. The actual capability data
//! is stored in a [`CapSlot`]; this type provides a typed view.
//!
//! # Design
//!
//! The type parameter `T` uses the sealed [`CapObjectType`] trait to
//! ensure only valid kernel object types can be used. This provides
//! compile-time type safety without runtime overhead.

use core::fmt;
use core::marker::PhantomData;

use crate::objects::CapObjectType;
use crate::slot::{CapSlot, ObjectRef, ObjectType};
use crate::{Badge, CapRights};

/// A type-safe capability reference.
///
/// This is a handle to a capability that enforces type safety at compile
/// time. The type parameter `T` indicates the object type, allowing the
/// compiler to catch type mismatches.
///
/// # Usage
///
/// ```ignore
/// use m6_cap::{Cap, objects::Endpoint};
///
/// fn send_message(ep: Cap<Endpoint>, msg: &[u8]) -> Result<(), CapError> {
///     // Compiler ensures we have an Endpoint capability
///     if !ep.has_right(CapRights::WRITE) {
///         return Err(CapError::InsufficientRights);
///     }
///     // ... send message
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct Cap<T: CapObjectType> {
    /// The capability slot contents.
    slot: CapSlot,
    /// Type marker.
    _type: PhantomData<T>,
}

impl<T: CapObjectType> Cap<T> {
    /// Create a Cap from a slot.
    ///
    /// # Safety
    ///
    /// Caller must ensure the slot contains a capability of type `T`.
    /// Using an incorrectly typed Cap may lead to undefined behaviour
    /// when the capability is invoked.
    #[inline]
    pub const unsafe fn from_slot(slot: CapSlot) -> Self {
        Self {
            slot,
            _type: PhantomData,
        }
    }

    /// Try to create a Cap from a slot with runtime type checking.
    ///
    /// # Parameters
    ///
    /// - `slot`: The capability slot
    /// - `expected_type`: The expected object type
    ///
    /// # Returns
    ///
    /// `Some(Cap)` if the slot contains the expected type, `None` otherwise.
    pub fn try_from_slot(slot: CapSlot, expected_type: ObjectType) -> Option<Self> {
        if slot.cap_type() == expected_type {
            // SAFETY: We verified the type matches
            Some(unsafe { Self::from_slot(slot) })
        } else {
            None
        }
    }

    /// Get the access rights.
    #[inline]
    #[must_use]
    pub const fn rights(&self) -> CapRights {
        self.slot.rights()
    }

    /// Get the badge.
    #[inline]
    #[must_use]
    pub const fn badge(&self) -> Badge {
        self.slot.badge()
    }

    /// Get the object reference.
    #[inline]
    #[must_use]
    pub const fn object_ref(&self) -> ObjectRef {
        self.slot.object_ref()
    }

    /// Get the object type.
    #[inline]
    #[must_use]
    pub const fn cap_type(&self) -> ObjectType {
        self.slot.cap_type()
    }

    /// Check if this capability has a specific right.
    #[inline]
    #[must_use]
    pub const fn has_right(&self, right: CapRights) -> bool {
        self.slot.rights().contains(right)
    }

    /// Check if this capability can read.
    #[inline]
    #[must_use]
    pub const fn can_read(&self) -> bool {
        self.has_right(CapRights::READ)
    }

    /// Check if this capability can write.
    #[inline]
    #[must_use]
    pub const fn can_write(&self) -> bool {
        self.has_right(CapRights::WRITE)
    }

    /// Check if this capability can grant.
    #[inline]
    #[must_use]
    pub const fn can_grant(&self) -> bool {
        self.has_right(CapRights::GRANT)
    }

    /// Get the underlying slot (read-only).
    #[inline]
    #[must_use]
    pub const fn slot(&self) -> &CapSlot {
        &self.slot
    }

    /// Get the type name for debugging.
    #[inline]
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        T::NAME
    }

    /// Check if this capability is valid (has a valid object reference).
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.slot.is_empty() && self.slot.object_ref().is_valid()
    }
}

impl<T: CapObjectType> Clone for Cap<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: CapObjectType> Copy for Cap<T> {}

impl<T: CapObjectType> PartialEq for Cap<T> {
    fn eq(&self, other: &Self) -> bool {
        self.slot.object_ref() == other.slot.object_ref()
            && self.slot.cap_type() == other.slot.cap_type()
            && self.slot.rights() == other.slot.rights()
            && self.slot.badge() == other.slot.badge()
    }
}

impl<T: CapObjectType> Eq for Cap<T> {}

impl<T: CapObjectType> fmt::Display for Cap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cap<{}>({})", T::NAME, self.slot)
    }
}

/// A type-erased capability reference.
///
/// This is used when the capability type is not statically known,
/// such as when iterating over all capabilities in a CNode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnyCap {
    /// The capability slot contents.
    slot: CapSlot,
}

impl AnyCap {
    /// Create an AnyCap from a slot.
    #[inline]
    #[must_use]
    pub const fn from_slot(slot: CapSlot) -> Self {
        Self { slot }
    }

    /// Get the access rights.
    #[inline]
    #[must_use]
    pub const fn rights(&self) -> CapRights {
        self.slot.rights()
    }

    /// Get the badge.
    #[inline]
    #[must_use]
    pub const fn badge(&self) -> Badge {
        self.slot.badge()
    }

    /// Get the object reference.
    #[inline]
    #[must_use]
    pub const fn object_ref(&self) -> ObjectRef {
        self.slot.object_ref()
    }

    /// Get the object type.
    #[inline]
    #[must_use]
    pub const fn cap_type(&self) -> ObjectType {
        self.slot.cap_type()
    }

    /// Check if this is an empty capability.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slot.is_empty()
    }

    /// Get the underlying slot.
    #[inline]
    #[must_use]
    pub const fn slot(&self) -> &CapSlot {
        &self.slot
    }

    /// Try to convert to a typed capability.
    ///
    /// # Returns
    ///
    /// `Some(Cap<T>)` if the object type matches, `None` otherwise.
    pub fn try_into_typed<T: CapObjectType>(self, expected_type: ObjectType) -> Option<Cap<T>> {
        Cap::try_from_slot(self.slot, expected_type)
    }
}

impl fmt::Display for AnyCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnyCap({})", self.slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::Endpoint;
    use crate::slot::SlotFlags;

    #[test]
    fn test_cap_creation() {
        let slot = CapSlot::new(
            ObjectRef::from_index(1),
            ObjectType::Endpoint,
            CapRights::RW,
            Badge::NONE,
            SlotFlags::NONE,
        );

        // SAFETY: We know the slot contains an Endpoint
        let cap: Cap<Endpoint> = unsafe { Cap::from_slot(slot) };

        assert!(cap.is_valid());
        assert!(cap.can_read());
        assert!(cap.can_write());
        assert!(!cap.can_grant());
    }

    #[test]
    fn test_cap_type_name() {
        let slot = CapSlot::new(
            ObjectRef::from_index(1),
            ObjectType::Endpoint,
            CapRights::RW,
            Badge::NONE,
            SlotFlags::NONE,
        );

        let cap: Cap<Endpoint> = unsafe { Cap::from_slot(slot) };
        assert_eq!(cap.type_name(), "Endpoint");
    }

    #[test]
    fn test_try_from_slot() {
        let slot = CapSlot::new(
            ObjectRef::from_index(1),
            ObjectType::Endpoint,
            CapRights::RW,
            Badge::NONE,
            SlotFlags::NONE,
        );

        let cap: Option<Cap<Endpoint>> = Cap::try_from_slot(slot, ObjectType::Endpoint);
        assert!(cap.is_some());

        // Wrong type should fail
        let cap: Option<Cap<Endpoint>> = Cap::try_from_slot(slot, ObjectType::Frame);
        assert!(cap.is_none());
    }
}
