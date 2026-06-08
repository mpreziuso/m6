//! Zircon exception types
//!
//! Mirrors the upstream `zx::ExceptionType`, `ExceptionReport` and the
//! architecture-specific `ExceptionArchData` for aarch64.

use crate::Status;

/// A policy-error code carried by [`ExceptionType::PolicyError`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PolicyCode {
    pub code: u32,
    pub data: u32,
}

impl PolicyCode {
    /// Builds a policy code from its raw fields.
    pub const fn from_raw(code: u32, data: u32) -> Self {
        Self { code, data }
    }
}

/// The kind of exception that occurred.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExceptionType {
    /// A general exception occurred.
    General,
    /// The process generated an unhandled page fault.
    FatalPageFault {
        /// The error code returned by the page-fault handler.
        status: Status,
    },
    /// The process attempted to execute an undefined instruction.
    UndefinedInstruction,
    /// A software breakpoint was reached.
    SoftwareBreakpoint,
    /// A hardware breakpoint was reached.
    HardwareBreakpoint,
    /// An unaligned memory access was attempted.
    UnalignedAccess,
    /// A thread is starting (debugger-only).
    ThreadStarting,
    /// A thread is exiting (debugger-only).
    ThreadExiting,
    /// A job-policy error occurred.
    PolicyError(PolicyCode),
    /// A process is starting (job-debugger-only).
    ProcessStarting,
    /// The process' name changed.
    ProcessNameChanged,
    /// A user-generated exception of an unknown type.
    UnknownUserGenerated { code: u32, data: u32 },
    /// An unknown exception type.
    Unknown { ty: u32, code: u32, data: u32 },
}

/// Architecture-specific exception context (aarch64).
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct ExceptionArchData {
    /// The Exception Syndrome Register value.
    pub esr: u32,
    /// The Fault Address Register value.
    pub far: u64,
}

/// A full exception report.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ExceptionReport {
    /// The kind of exception.
    pub ty: ExceptionType,
    /// Architecture-specific context.
    pub arch: ExceptionArchData,
}
