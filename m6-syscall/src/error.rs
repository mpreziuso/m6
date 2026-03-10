//! Syscall error codes
//!
//! Defines error codes returned from syscalls. Negative values indicate
//! errors, zero indicates success, positive values may carry additional
//! information depending on the syscall.

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
    /// Address already mapped.
    AlreadyMapped = -21,
    /// Address not mapped.
    NotMapped = -22,
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

    /// Try to convert from a raw i64 value.
    pub fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            -1 => Some(Self::InvalidCap),
            -2 => Some(Self::NoRights),
            -3 => Some(Self::InvalidArg),
            -4 => Some(Self::SlotOccupied),
            -5 => Some(Self::EmptySlot),
            -6 => Some(Self::TypeMismatch),
            -7 => Some(Self::NoMemory),
            -8 => Some(Self::WouldBlock),
            -9 => Some(Self::Revoked),
            -10 => Some(Self::Alignment),
            -11 => Some(Self::Range),
            -12 => Some(Self::NotSupported),
            -13 => Some(Self::InvalidState),
            -14 => Some(Self::GuardMismatch),
            -15 => Some(Self::DepthExceeded),
            -16 => Some(Self::Truncated),
            -17 => Some(Self::InvalidSyscall),
            -18 => Some(Self::ObjectInUse),
            -19 => Some(Self::LastCapability),
            -20 => Some(Self::CircularDependency),
            -21 => Some(Self::AlreadyMapped),
            -22 => Some(Self::NotMapped),
            _ => None,
        }
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
            Self::AlreadyMapped => "AlreadyMapped",
            Self::NotMapped => "NotMapped",
        }
    }
}

/// The minimum (most negative) syscall error code. Used by IPC recv/call
/// to distinguish kernel error codes from valid IPC message labels.
/// Must be kept in sync with the last variant of `SyscallError`.
pub const MIN_SYSCALL_ERROR: i64 = SyscallError::NotMapped as i64; // -22

/// Syscall result type for userspace.
pub type SyscallResult<T = i64> = Result<T, SyscallError>;

/// Check a raw syscall return value and convert to Result.
#[inline]
pub fn check_result(value: i64) -> SyscallResult {
    if value >= 0 {
        Ok(value)
    } else {
        Err(SyscallError::from_i64(value).unwrap_or(SyscallError::InvalidSyscall))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[(i64, SyscallError)] = &[
        (0, SyscallError::Ok),
        (-1, SyscallError::InvalidCap),
        (-2, SyscallError::NoRights),
        (-3, SyscallError::InvalidArg),
        (-4, SyscallError::SlotOccupied),
        (-5, SyscallError::EmptySlot),
        (-6, SyscallError::TypeMismatch),
        (-7, SyscallError::NoMemory),
        (-8, SyscallError::WouldBlock),
        (-9, SyscallError::Revoked),
        (-10, SyscallError::Alignment),
        (-11, SyscallError::Range),
        (-12, SyscallError::NotSupported),
        (-13, SyscallError::InvalidState),
        (-14, SyscallError::GuardMismatch),
        (-15, SyscallError::DepthExceeded),
        (-16, SyscallError::Truncated),
        (-17, SyscallError::InvalidSyscall),
        (-18, SyscallError::ObjectInUse),
        (-19, SyscallError::LastCapability),
        (-20, SyscallError::CircularDependency),
        (-21, SyscallError::AlreadyMapped),
        (-22, SyscallError::NotMapped),
    ];

    #[test_case]
    fn test_as_i64_round_trip() {
        for &(expected_i64, variant) in ALL_VARIANTS {
            assert_eq!(variant.as_i64(), expected_i64);
        }
    }

    #[test_case]
    fn test_from_i64_round_trip() {
        for &(raw, expected) in ALL_VARIANTS {
            assert_eq!(SyscallError::from_i64(raw), Some(expected));
        }
    }

    #[test_case]
    fn test_from_i64_unmapped_values() {
        assert_eq!(SyscallError::from_i64(1), None);
        assert_eq!(SyscallError::from_i64(-23), None);
        assert_eq!(SyscallError::from_i64(-100), None);
        assert_eq!(SyscallError::from_i64(i64::MIN), None);
        assert_eq!(SyscallError::from_i64(i64::MAX), None);
    }

    #[test_case]
    fn test_is_ok_only_for_ok() {
        assert!(SyscallError::Ok.is_ok());
        for &(_, variant) in ALL_VARIANTS.iter().skip(1) {
            assert!(!variant.is_ok(), "{variant:?} should not be ok");
        }
    }

    #[test_case]
    fn test_is_err_for_all_non_ok() {
        assert!(!SyscallError::Ok.is_err());
        for &(_, variant) in ALL_VARIANTS.iter().skip(1) {
            assert!(variant.is_err(), "{variant:?} should be an error");
        }
    }

    #[test_case]
    fn test_name_non_empty_for_all() {
        for &(_, variant) in ALL_VARIANTS {
            assert!(
                !variant.name().is_empty(),
                "{variant:?} name must be non-empty"
            );
        }
    }

    #[test_case]
    fn test_check_result_success() {
        assert_eq!(check_result(0), Ok(0));
        assert_eq!(check_result(42), Ok(42));
    }

    #[test_case]
    fn test_check_result_error() {
        assert_eq!(check_result(-1), Err(SyscallError::InvalidCap));
        assert_eq!(check_result(-7), Err(SyscallError::NoMemory));
    }

    #[test_case]
    fn test_check_result_unknown_error() {
        // Unknown negative values fall back to InvalidSyscall
        assert_eq!(check_result(-100), Err(SyscallError::InvalidSyscall));
    }
}
