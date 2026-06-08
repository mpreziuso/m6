//! Minimal `fuchsia_runtime` shim for the M6 Starnix fork.
//!
//! Only the UTC clock timeline types are provided on the default build; the
//! process/job/vmar runtime accessors are Fuchsia-runtime-specific and remain
//! gated behind the `fuchsia` feature in `m6-starnix`. The UTC types are simple
//! aliases over the `zx` time machinery so timestamps (file times, clock
//! syscalls) compile.

#![no_std]

pub use zx::{UtcDuration, UtcInstant, UtcTimeline};

/// A handle to the system UTC clock.
///
/// Upstream this is `zx::Clock<zx::BootTimeline, UtcTimeline>`; M6 has no live
/// UTC clock object yet, so this aliases the `zx` clock stub (sufficient for the
/// handle operations the fork performs, e.g. reading a koid).
pub type UtcClock = zx::Clock;

/// Returns a handle to the current process.
///
/// M6 has no Zircon process object for the Starnix service; this returns a
/// placeholder `zx::Process` handle. The Starnix kthreads store it as
/// `starnix_process` and only read it back for handle/koid operations on the
/// (gated) Fuchsia paths, so a placeholder is sufficient for the minimal core.
pub fn process_self() -> zx::Process {
    zx::Process::new(0, 0, 0)
}

