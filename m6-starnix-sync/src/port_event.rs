// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! `PortEvent` — the waiter's wake/interrupt primitive.
//!
//! Upstream this wraps a `zx::Port` plus a futex fast-path. M6 has no Zircon
//! port; the eventual production implementation routes object-signal waits
//! through M6 notifications/endpoints (the waiter ↔ IPC seam, roadmap M3).
//!
//! This is the bring-up implementation: notifications are tracked with an
//! atomic state word so the API is faithful and `notify`/`wait` round-trip
//! correctly for the single-threaded first-light path. Object-signal
//! subscription (`object_wait_async`) is a no-op stub — blocking on external
//! Zircon-style objects is not exercised until the IPC seam lands.

use core::sync::atomic::{AtomicU8, Ordering};

const STATE_IDLE: u8 = 0;
const STATE_REGULAR: u8 = 1;
const STATE_INTERRUPT: u8 = 2;

/// The kind of notification delivered to a [`PortEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyKind {
    /// A regular wake-up (e.g. an FD became ready).
    Regular,
    /// An interrupt (e.g. a signal arrived); surfaces to userspace as `EINTR`.
    Interrupt,
}

/// The result of a [`PortEvent::wait`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortWaitResult {
    /// A futex-style notification was observed.
    Notification {
        /// Whether it was a regular wake or an interrupt.
        kind: NotifyKind,
    },
    /// A subscribed object asserted `observed` signals under `key`.
    Signal {
        /// The key associated with the wait via `object_wait_async`.
        key: u64,
        /// The asserted signals.
        observed: zx::Signals,
    },
    /// The wait reached its deadline with nothing to report.
    TimedOut,
}

impl PortWaitResult {
    /// Convenience for an interrupt notification.
    pub const NOTIFY_INTERRUPT: Self =
        PortWaitResult::Notification { kind: NotifyKind::Interrupt };
    /// Convenience for a regular notification.
    pub const NOTIFY_REGULAR: Self = PortWaitResult::Notification { kind: NotifyKind::Regular };
}

/// A wake/interrupt primitive for a single waiter.
pub struct PortEvent {
    state: AtomicU8,
}

impl Default for PortEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PortEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PortEvent").finish_non_exhaustive()
    }
}

impl PortEvent {
    /// Creates a new, idle `PortEvent`.
    pub fn new() -> Self {
        Self { state: AtomicU8::new(STATE_IDLE) }
    }

    /// Waits until notified or until `_deadline`.
    ///
    /// Bring-up semantics: consumes any pending notification and returns it;
    /// otherwise reports `TimedOut` (there is no blocking object-signal path
    /// yet — see the module note). Interrupts take priority over regular wakes.
    pub fn wait(&self, _deadline: zx::MonotonicInstant) -> PortWaitResult {
        match self.state.swap(STATE_IDLE, Ordering::AcqRel) {
            STATE_INTERRUPT => PortWaitResult::NOTIFY_INTERRUPT,
            STATE_REGULAR => PortWaitResult::NOTIFY_REGULAR,
            _ => PortWaitResult::TimedOut,
        }
    }

    /// Subscribes to `_signals` on `_handle`, reported under `_key`.
    ///
    /// Stub: M6 object-signal subscription is not yet wired (roadmap M3). Always
    /// succeeds so callers proceed; the corresponding `Signal` result is never
    /// produced by `wait` until the seam is implemented.
    pub fn object_wait_async(
        &self,
        _handle: &dyn zx::AsHandleRef,
        _key: u64,
        _signals: zx::Signals,
        _opts: zx::WaitAsyncOpts,
    ) -> Result<(), zx::Status> {
        Ok(())
    }

    /// Cancels a previously established `object_wait_async` for `_key`. No-op
    /// in the bring-up implementation.
    pub fn cancel(&self, _key: u64) {}

    /// Delivers a notification, waking a concurrent or subsequent `wait`.
    pub fn notify(&self, kind: NotifyKind) {
        let new = match kind {
            NotifyKind::Regular => STATE_REGULAR,
            NotifyKind::Interrupt => STATE_INTERRUPT,
        };
        // Interrupts must not be downgraded to a regular wake.
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if current == STATE_INTERRUPT {
                return;
            }
            match self.state.compare_exchange_weak(
                current,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}
