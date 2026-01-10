//! Syscall error codes
//!
//! Re-exports error definitions from the shared ABI crate and provides
//! kernel-specific conversions.

pub use m6_syscall::error::SyscallError;
use m6_cap::CapError;

/// Convert a capability error to a syscall error.
///
/// This is a standalone function because of Rust's orphan rules - we cannot
/// implement From<CapError> for SyscallError since both types are from
/// external crates.
pub fn cap_error_to_syscall(e: CapError) -> SyscallError {
    match e {
        CapError::InvalidIndex => SyscallError::InvalidCap,
        CapError::EmptySlot => SyscallError::EmptySlot,
        CapError::SlotOccupied => SyscallError::SlotOccupied,
        CapError::InsufficientRights => SyscallError::NoRights,
        CapError::RightsEscalation => SyscallError::NoRights,
        CapError::TypeMismatch => SyscallError::TypeMismatch,
        CapError::OutOfMemory => SyscallError::NoMemory,
        CapError::GuardMismatch => SyscallError::GuardMismatch,
        CapError::DepthExceeded => SyscallError::DepthExceeded,
        CapError::Revoked => SyscallError::Revoked,
        CapError::ObjectInUse => SyscallError::ObjectInUse,
        CapError::LastCapability => SyscallError::LastCapability,
        CapError::CircularDependency => SyscallError::CircularDependency,
        CapError::AlignmentError => SyscallError::Alignment,
        CapError::SizeTooSmall => SyscallError::Range,
        CapError::UntypedExhausted => SyscallError::NoMemory,
        CapError::InvalidRadix => SyscallError::InvalidArg,
        CapError::InvalidGuard => SyscallError::InvalidArg,
        CapError::BadgeNotSupported => SyscallError::InvalidArg,
        CapError::BadgeAlreadySet => SyscallError::InvalidArg,
        CapError::ObjectNotFound => SyscallError::Revoked,
        CapError::InvalidOperation => SyscallError::NotSupported,
        CapError::InvalidState => SyscallError::InvalidState,
    }
}

/// Syscall result type.
pub type SyscallResult = Result<i64, SyscallError>;

/// Sentinel value indicating IPC message was delivered to registers.
///
/// When an IPC syscall returns this value, the message has already been
/// written to the caller's context (x0-x4 for message, x6 for badge).
/// The syscall dispatcher should NOT overwrite x0 with the return value.
pub const IPC_MESSAGE_DELIVERED: i64 = i64::MIN;

/// Convert a syscall result to a raw return value.
#[inline]
pub fn to_return_value(result: SyscallResult) -> i64 {
    match result {
        Ok(v) => v,
        Err(e) => e.as_i64(),
    }
}
