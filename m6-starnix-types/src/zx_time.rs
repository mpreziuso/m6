// M6: Zircon-time/futex compatibility shim.
//
// The timeline types (`Instant`, `Duration`, `MonotonicInstant`,
// `MonotonicDuration`, `Timeline`, the timeline markers and their aliases) are
// re-exported verbatim from `m6-zx-shim` so the whole fork shares ONE time-type
// hierarchy — otherwise `starnix_types::zx_time::Instant<T>` and
// `zx::Instant<T, U>` are distinct types and every site that mixes them fails to
// typecheck. Only the small `sys`/`Status`/`Futex` bring-up helpers are local.

use core::sync::atomic::{AtomicI32, Ordering};

// -- Unified timeline types (single source of truth: m6-zx-shim)
pub use zx::{
    BootDuration, BootInstant, BootTimeline, Duration, Instant, MonotonicDuration,
    MonotonicInstant, MonotonicTimeline, SyntheticDuration, SyntheticInstant, SyntheticTimeline,
    Timeline, UtcDuration, UtcInstant, UtcTimeline,
};

/// M6: subset of `zx::sys` used by `thread_start_info`. Re-exported from the
/// real `zx` shim so `zx_restricted_state_t` is ONE type across the fork (the
/// register-frame seam) rather than a parallel local definition.
pub mod sys {
    #![allow(non_camel_case_types)]
    pub use zx::sys::{
        ZX_REG_CPSR_ARCH_32_MASK, ZX_REG_CPSR_THUMB_MASK, zx_restricted_state_t, zx_vaddr_t,
    };
}

/// Minimal subset of `zx::Status` used by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    BadState,
}

/// Minimal futex backed by an atomic word.
///
/// M6: `wait`/`wake_single_owner` are no-op stubs (no kernel futex syscall is
/// wired up in this crate yet). The atomic accounting still works, so the
/// `ownership` ref-counting logic is correct; only the blocking-wait is elided.
#[derive(Debug)]
pub struct Futex(AtomicI32);

impl Futex {
    pub const fn new(value: i32) -> Self {
        Self(AtomicI32::new(value))
    }
    pub fn load(&self, order: Ordering) -> i32 {
        self.0.load(order)
    }
    pub fn fetch_add(&self, value: i32, order: Ordering) -> i32 {
        self.0.fetch_add(value, order)
    }
    pub fn fetch_sub(&self, value: i32, order: Ordering) -> i32 {
        self.0.fetch_sub(value, order)
    }
    /// M6: stub — returns immediately. A real implementation would block.
    pub fn wait(
        &self,
        _expected: i32,
        _owner: Option<()>,
        _deadline: MonotonicInstant,
    ) -> Result<(), Status> {
        Ok(())
    }
    /// M6: stub — no waiters to wake in this crate.
    pub fn wake_single_owner(&self) {}
}
