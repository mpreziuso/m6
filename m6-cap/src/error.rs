//! Capability error types
//!
//! This module defines the error types that can occur during capability
//! operations such as copy, move, mint, delete, and revoke.

use core::fmt;

/// Errors that can occur during capability operations.
///
/// All capability operations return `Result<T, CapError>` to indicate
/// success or failure. These errors are designed to be informative
/// while not leaking sensitive information about the system state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use = "capability errors must be handled"]
pub enum CapError {
    /// The slot index is out of bounds for the CNode.
    InvalidIndex,

    /// The source slot is empty (no capability present).
    EmptySlot,

    /// The destination slot is already occupied.
    ///
    /// Capabilities cannot overwrite existing capabilities.
    /// Delete the existing capability first.
    SlotOccupied,

    /// CPtr guard value did not match.
    ///
    /// The guard bits in the CPtr did not match the CNode's guard.
    GuardMismatch,

    /// Attempted to increase capability rights.
    ///
    /// Rights can only be reduced (attenuated), never increased.
    /// This error occurs when minting with rights that are not
    /// a subset of the source capability's rights.
    RightsEscalation,

    /// The object type does not support badging.
    ///
    /// Only Endpoint and Notification objects support badges.
    BadgeNotSupported,

    /// The capability already has a badge.
    ///
    /// A badge can only be set once during minting.
    /// If the source capability already has a badge, the minted
    /// capability must use the same badge or no badge.
    BadgeAlreadySet,

    /// Insufficient rights for the requested operation.
    ///
    /// The capability does not have the required rights for
    /// the operation being attempted.
    InsufficientRights,

    /// Object type mismatch.
    ///
    /// The capability's object type does not match what was expected
    /// for the operation.
    TypeMismatch,

    /// Out of memory or capability slots.
    ///
    /// No free slots available in the CNode, or no free CDT nodes
    /// available for tracking capability derivations.
    OutOfMemory,

    /// Invalid operation for this object type.
    ///
    /// The operation is not valid for capabilities of this type.
    InvalidOperation,

    /// The capability has been revoked.
    ///
    /// The capability or its ancestor was revoked, invalidating
    /// this capability.
    Revoked,

    /// CPtr resolution depth exceeded.
    ///
    /// The CPtr has more levels than the maximum allowed depth,
    /// or the resolution ran out of bits before reaching a
    /// non-CNode capability.
    DepthExceeded,

    /// Untyped memory exhausted.
    ///
    /// The untyped memory object does not have enough remaining
    /// space to create the requested object.
    UntypedExhausted,

    /// Object size is too small.
    ///
    /// The requested size is smaller than the minimum for this
    /// object type.
    SizeTooSmall,

    /// Alignment requirement not met.
    ///
    /// The address or size is not properly aligned for this
    /// object type.
    AlignmentError,

    /// CNode radix is out of valid range.
    ///
    /// The CNode radix must be between MIN_CNODE_RADIX and
    /// MAX_CNODE_RADIX.
    InvalidRadix,

    /// Guard bits exceed maximum.
    ///
    /// The guard size exceeds the maximum allowed bits.
    InvalidGuard,

    /// Object not found.
    ///
    /// The object referenced by the capability does not exist.
    ObjectNotFound,

    /// Cannot delete last capability to an object.
    ///
    /// Some objects require at least one capability to exist.
    LastCapability,

    /// Circular dependency detected.
    ///
    /// The operation would create a circular reference, which
    /// is not allowed.
    CircularDependency,

    /// Object is currently in use.
    ///
    /// The object cannot be modified or deleted because it is
    /// currently being used (e.g., a TCB that is running).
    ObjectInUse,

    /// Invalid state for operation.
    ///
    /// The object is not in the correct state for the requested
    /// operation.
    InvalidState,
}

impl CapError {
    /// Get a short description of the error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIndex => "invalid slot index",
            Self::EmptySlot => "slot is empty",
            Self::SlotOccupied => "destination slot is occupied",
            Self::GuardMismatch => "CPtr guard mismatch",
            Self::RightsEscalation => "cannot increase capability rights",
            Self::BadgeNotSupported => "object type does not support badging",
            Self::BadgeAlreadySet => "capability already has a badge",
            Self::InsufficientRights => "insufficient rights for operation",
            Self::TypeMismatch => "object type mismatch",
            Self::OutOfMemory => "out of memory or slots",
            Self::InvalidOperation => "invalid operation for object type",
            Self::Revoked => "capability has been revoked",
            Self::DepthExceeded => "CPtr resolution depth exceeded",
            Self::UntypedExhausted => "untyped memory exhausted",
            Self::SizeTooSmall => "object size too small",
            Self::AlignmentError => "alignment requirement not met",
            Self::InvalidRadix => "invalid CNode radix",
            Self::InvalidGuard => "invalid guard size",
            Self::ObjectNotFound => "object not found",
            Self::LastCapability => "cannot delete last capability",
            Self::CircularDependency => "circular dependency detected",
            Self::ObjectInUse => "object is currently in use",
            Self::InvalidState => "invalid state for operation",
        }
    }
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type for capability operations.
pub type CapResult<T> = Result<T, CapError>;
