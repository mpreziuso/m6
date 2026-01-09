//! Syscall error codes
//!
//! Defines error codes returned from syscalls. Negative values indicate
//! errors, zero indicates success, positive values may carry additional
//! information depending on the syscall.

use m6_cap::CapError;

/// Syscall return codes.
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallError {
    /// Success.
    Ok = 0,

    /// Invalid capability pointer.
    InvalidCap = -1,
    /// Insufficient rights on capability.
    NoRights = -2,
    /// Invalid argument.
    InvalidArg = -3,
    /// Destination slot occupied.
    SlotOccupied = -4,
    /// Source slot empty.
    EmptySlot = -5,
    /// Object type mismatch.
    TypeMismatch = -6,
    /// Out of memory/resources.
    NoMemory = -7,
    /// Would block (for non-blocking operations).
    WouldBlock = -8,
    /// Object deleted/revoked.
    Revoked = -9,
    /// Alignment error.
    Alignment = -10,
    /// Range error (address/size out of bounds).
    Range = -11,
    /// Operation not supported.
    NotSupported = -12,
    /// Invalid state for operation.
    InvalidState = -13,
    /// Guard mismatch in CPtr resolution.
    GuardMismatch = -14,
    /// CPtr depth exceeded.
    DepthExceeded = -15,
    /// Truncated message (IPC buffer overflow).
    Truncated = -16,
    /// Invalid syscall number.
    InvalidSyscall = -17,
    /// Object in use (cannot delete/revoke).
    ObjectInUse = -18,
    /// Last capability (cannot delete original).
    LastCapability = -19,
    /// Circular dependency detected.
    CircularDependency = -20,
}

impl SyscallError {
    /// Convert to raw i64 for return.
    #[inline]
    pub const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Check if this represents success.
    #[inline]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Check if this represents an error.
    #[inline]
    pub const fn is_err(self) -> bool {
        !self.is_ok()
    }

    /// Get the error name for logging.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::InvalidCap => "InvalidCap",
            Self::NoRights => "NoRights",
            Self::InvalidArg => "InvalidArg",
            Self::SlotOccupied => "SlotOccupied",
            Self::EmptySlot => "EmptySlot",
            Self::TypeMismatch => "TypeMismatch",
            Self::NoMemory => "NoMemory",
            Self::WouldBlock => "WouldBlock",
            Self::Revoked => "Revoked",
            Self::Alignment => "Alignment",
            Self::Range => "Range",
            Self::NotSupported => "NotSupported",
            Self::InvalidState => "InvalidState",
            Self::GuardMismatch => "GuardMismatch",
            Self::DepthExceeded => "DepthExceeded",
            Self::Truncated => "Truncated",
            Self::InvalidSyscall => "InvalidSyscall",
            Self::ObjectInUse => "ObjectInUse",
            Self::LastCapability => "LastCapability",
            Self::CircularDependency => "CircularDependency",
        }
    }
}

impl From<CapError> for SyscallError {
    fn from(e: CapError) -> Self {
        match e {
            CapError::InvalidIndex => Self::InvalidCap,
            CapError::EmptySlot => Self::EmptySlot,
            CapError::SlotOccupied => Self::SlotOccupied,
            CapError::InsufficientRights => Self::NoRights,
            CapError::RightsEscalation => Self::NoRights,
            CapError::TypeMismatch => Self::TypeMismatch,
            CapError::OutOfMemory => Self::NoMemory,
            CapError::GuardMismatch => Self::GuardMismatch,
            CapError::DepthExceeded => Self::DepthExceeded,
            CapError::Revoked => Self::Revoked,
            CapError::ObjectInUse => Self::ObjectInUse,
            CapError::LastCapability => Self::LastCapability,
            CapError::CircularDependency => Self::CircularDependency,
            CapError::AlignmentError => Self::Alignment,
            CapError::SizeTooSmall => Self::Range,
            CapError::UntypedExhausted => Self::NoMemory,
            CapError::InvalidRadix => Self::InvalidArg,
            CapError::InvalidGuard => Self::InvalidArg,
            CapError::BadgeNotSupported => Self::InvalidArg,
            CapError::BadgeAlreadySet => Self::InvalidArg,
            CapError::ObjectNotFound => Self::Revoked,
            CapError::InvalidOperation => Self::NotSupported,
            CapError::InvalidState => Self::InvalidState,
        }
    }
}

/// Syscall result type.
pub type SyscallResult = Result<i64, SyscallError>;

/// Convert a syscall result to a raw return value.
#[inline]
pub fn to_return_value(result: SyscallResult) -> i64 {
    match result {
        Ok(v) => v,
        Err(e) => e.as_i64(),
    }
}
