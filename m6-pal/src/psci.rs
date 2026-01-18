//! PSCI (Power State Coordination Interface) Driver
//!
//! Implements ARM PSCI v1.0+ for CPU power management.
//! Used primarily to bring up secondary CPUs during SMP initialisation.
//!
//! The PSCI conduit (SMC vs HVC) is determined from the DTB /psci node.
//!
//! Reference: ARM DEN0022D - Power State Coordination Interface

use core::arch::asm;
use crate::dtb_platform::PsciMethod;
use crate::platform::current_platform;

// -- PSCI Function IDs (SMC64 convention for 64-bit calls)

/// Get PSCI version
const PSCI_VERSION: u32 = 0x8400_0000;

/// CPU_ON - Start a CPU at a given entry point
const CPU_ON_64: u32 = 0xC400_0003;

/// CPU_OFF - Power down the calling CPU
const CPU_OFF: u32 = 0x8400_0002;

/// AFFINITY_INFO - Query power state of a CPU
const AFFINITY_INFO_64: u32 = 0xC400_0004;

/// SYSTEM_OFF - Power off the system
#[allow(dead_code)]
const SYSTEM_OFF: u32 = 0x8400_0008;

/// SYSTEM_RESET - Reset the system
#[allow(dead_code)]
const SYSTEM_RESET: u32 = 0x8400_0009;

// -- PSCI Return Codes

/// PSCI error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PsciError {
    /// Operation completed successfully
    Success = 0,
    /// Operation not supported
    NotSupported = -1,
    /// Invalid parameters
    InvalidParameters = -2,
    /// Operation denied
    Denied = -3,
    /// CPU already on
    AlreadyOn = -4,
    /// CPU on pending
    OnPending = -5,
    /// Internal failure
    InternalFailure = -6,
    /// CPU not present
    NotPresent = -7,
    /// CPU disabled
    Disabled = -8,
    /// Invalid address
    InvalidAddress = -9,
}

impl PsciError {
    fn from_i64(value: i64) -> Self {
        match value as i32 {
            0 => Self::Success,
            -1 => Self::NotSupported,
            -2 => Self::InvalidParameters,
            -3 => Self::Denied,
            -4 => Self::AlreadyOn,
            -5 => Self::OnPending,
            -6 => Self::InternalFailure,
            -7 => Self::NotPresent,
            -8 => Self::Disabled,
            -9 => Self::InvalidAddress,
            _ => Self::InternalFailure,
        }
    }
}

/// Affinity level states returned by AFFINITY_INFO
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AffinityState {
    /// CPU is on
    On = 0,
    /// CPU is off
    Off = 1,
    /// CPU on is pending
    OnPending = 2,
}

// -- PSCI Conduit Functions (SMC and HVC)

/// Issue a PSCI call via HVC (Hypervisor Call).
///
/// HVC traps to EL2 where QEMU or a hypervisor provides PSCI services.
///
/// # Safety
/// This issues an HVC instruction.
#[inline]
unsafe fn psci_call_hvc(func: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!(
            "hvc #0",
            inout("x0") func as u64 => result,
            inout("x1") arg0 => _,
            inout("x2") arg1 => _,
            inout("x3") arg2 => _,
            options(nomem, nostack)
        );
    }
    result
}

/// Issue a PSCI call via SMC (Secure Monitor Call).
///
/// SMC traps to EL3 where firmware (e.g., TF-A) provides PSCI services.
///
/// # Safety
/// This issues an SMC instruction.
#[inline]
unsafe fn psci_call_smc(func: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let result: i64;
    unsafe {
        asm!(
            "smc #0",
            inout("x0") func as u64 => result,
            inout("x1") arg0 => _,
            inout("x2") arg1 => _,
            inout("x3") arg2 => _,
            options(nomem, nostack)
        );
    }
    result
}

/// Get the PSCI method from platform configuration.
///
/// Returns the method detected from DTB, or HVC as default.
fn get_psci_method() -> PsciMethod {
    current_platform()
        .map(|p| p.psci_method())
        .unwrap_or(PsciMethod::Hvc)
}

/// Issue a PSCI call using the platform-configured conduit (SMC or HVC).
///
/// # Safety
/// The caller must ensure the function ID and arguments are valid.
#[inline]
unsafe fn psci_call(func: u32, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    match get_psci_method() {
        PsciMethod::Smc => unsafe { psci_call_smc(func, arg0, arg1, arg2) },
        PsciMethod::Hvc => unsafe { psci_call_hvc(func, arg0, arg1, arg2) },
    }
}

// -- Public PSCI Interface

/// Get the PSCI version supported by firmware.
///
/// Returns (major, minor) version tuple.
pub fn version() -> (u16, u16) {
    // SAFETY: PSCI_VERSION is always safe to call
    let v = unsafe { psci_call(PSCI_VERSION, 0, 0, 0) };
    let major = ((v >> 16) & 0xFFFF) as u16;
    let minor = (v & 0xFFFF) as u16;
    (major, minor)
}

/// Start a CPU at the specified entry point.
///
/// # Arguments
/// * `target_cpu` - MPIDR_EL1 affinity value of the target CPU
/// * `entry_point` - Physical address of the entry point
/// * `context_id` - Value passed to the target CPU in x0
///
/// # Returns
/// `Ok(())` on success, or `Err(PsciError)` on failure.
///
/// # Safety
/// - `entry_point` must be a valid physical address of executable code
/// - The entry point code must be prepared to run on a fresh CPU
/// - The stack and other resources must be set up for the target CPU
pub unsafe fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> Result<(), PsciError> {
    // SAFETY: Caller guarantees entry_point is valid executable code
    let result = unsafe { psci_call(CPU_ON_64, target_cpu, entry_point, context_id) };

    if result == 0 {
        Ok(())
    } else {
        Err(PsciError::from_i64(result))
    }
}

/// Power down the calling CPU.
///
/// This function does not return on success.
///
/// # Safety
/// The CPU must be in a state where it's safe to power down.
/// All interrupts should be disabled and the CPU should not
/// hold any locks or be in the middle of critical operations.
pub unsafe fn cpu_off() -> Result<(), PsciError> {
    // SAFETY: CPU_OFF is safe if the CPU is ready to power down
    let result = unsafe { psci_call(CPU_OFF, 0, 0, 0) };

    // If we get here, it failed (success doesn't return)
    Err(PsciError::from_i64(result))
}

/// Query the power state of a CPU.
///
/// # Arguments
/// * `target_cpu` - MPIDR_EL1 affinity value of the target CPU
///
/// # Returns
/// The current power state of the CPU.
pub fn affinity_info(target_cpu: u64) -> Result<AffinityState, PsciError> {
    // SAFETY: AFFINITY_INFO is always safe to call
    let result = unsafe { psci_call(AFFINITY_INFO_64, target_cpu, 0, 0) };

    match result {
        0 => Ok(AffinityState::On),
        1 => Ok(AffinityState::Off),
        2 => Ok(AffinityState::OnPending),
        _ => Err(PsciError::from_i64(result)),
    }
}

/// Check if a CPU is currently online.
///
/// Convenience wrapper around `affinity_info`.
pub fn is_cpu_on(target_cpu: u64) -> bool {
    matches!(affinity_info(target_cpu), Ok(AffinityState::On))
}

/// Check if PSCI is available and working.
///
/// Returns `true` if PSCI version can be queried successfully.
pub fn is_available() -> bool {
    let (major, _minor) = version();
    // Version 0.0 means not available or error
    major > 0
}
