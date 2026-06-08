//! Minimal `no_std` `fuchsia_scheduler` shim for the M6 Starnix fork.
//!
//! Upstream sets a thread's scheduling "role" via the Fuchsia RoleManager FIDL
//! service. M6's scheduler (EEVDF in the microkernel) has no role mechanism yet,
//! so setting a role is a no-op that always succeeds. Thread priority/role
//! integration with the M6 scheduler is future work.

#![no_std]

/// Error type for role operations. Implements `Display` so callers can log it.
#[derive(Debug)]
pub struct RoleError;

impl core::fmt::Display for RoleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "scheduler role management is not supported on M6")
    }
}

/// Sets the scheduling role for the current thread. No-op on M6 (always Ok).
pub fn set_role_for_this_thread(_role: &str) -> Result<(), RoleError> {
    Ok(())
}
