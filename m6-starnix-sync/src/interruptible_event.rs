//! A blocking object that can either be notified normally or interrupted.
//!
//! M6: port of Fuchsia's `interruptible_event.rs`. Upstream backed this with a
//! `zx::Futex`; M6's `zx` shim does not (yet) expose a futex, so we provide a
//! self-contained `no_std` implementation backed by a `spin` mutex + atomic
//! state machine. The public surface (`InterruptibleEvent`, `EventWaitGuard`,
//! `WakeReason`, `begin_wait`, `block_until`, `notify`, `interrupt`) matches
//! upstream so the Starnix core compiles unchanged.
//!
//! `block_until` is generic over the owner and deadline arguments so callers can
//! keep passing `Option<&zx::Thread>` / `zx::MonotonicInstant` without this
//! crate depending on those `zx` types. The owner argument is ignored (no
//! priority-inheritance futex), and the deadline is currently treated as
//! "infinite" — M6: a real implementation will need a timer-backed wait.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

/// The initial state. Transitions to `WAITING` after `begin_wait`.
const READY: i32 = 0;
/// Waiting for a notification or interruption.
const WAITING: i32 = 1;
/// Notified; `block_until` will return `Ok`.
const NOTIFIED: i32 = 2;
/// Interrupted; `block_until` will return `Err(Interrupted)`.
const INTERRUPTED: i32 = 3;

/// A blocking object that can be notified normally or interrupted.
///
/// Use [`InterruptibleEvent::begin_wait`] to enter the waiting state, then
/// [`EventWaitGuard::block_until`] to block. `notify`/`interrupt` may be called
/// at any time and are safe across threads.
#[derive(Debug)]
pub struct InterruptibleEvent {
    state: AtomicI32,
}

/// A description of why a `block_until` returned without a normal notification.
#[derive(Debug, PartialEq, Eq)]
pub enum WakeReason {
    /// Another thread interrupted the wait via `interrupt`.
    Interrupted,
    /// The given deadline expired.
    DeadlineExpired,
}

/// A guard enforcing that clients call `begin_wait` before `block_until`.
#[must_use = "call block_until to advance the event state machine"]
pub struct EventWaitGuard<'a> {
    event: &'a Arc<InterruptibleEvent>,
}

impl<'a> EventWaitGuard<'a> {
    /// The underlying event associated with this guard.
    pub fn event(&self) -> &'a Arc<InterruptibleEvent> {
        self.event
    }

    /// Block the current thread until the event is notified or interrupted.
    ///
    /// M6: `new_owner` (priority-inheritance hint) and `deadline` are accepted
    /// for API parity but the owner is ignored and the deadline is not yet
    /// honoured — this spins until a `notify`/`interrupt` arrives.
    pub fn block_until<D>(
        self,
        _new_owner: Option<&zx::Thread>,
        _deadline: D,
    ) -> Result<(), WakeReason> {
        self.event.block_until()
    }
}

impl InterruptibleEvent {
    pub fn new() -> Arc<Self> {
        Arc::new(InterruptibleEvent {
            state: AtomicI32::new(READY),
        })
    }

    /// Initiate a wait. Calls to `notify`/`interrupt` after this returns will
    /// wake the event; calls before are ignored.
    ///
    /// Panics if called again before the matching `block_until` returns.
    pub fn begin_wait<'a>(self: &'a Arc<Self>) -> EventWaitGuard<'a> {
        self.state
            .compare_exchange(READY, WAITING, Ordering::Relaxed, Ordering::Relaxed)
            .expect("Tried to begin waiting on an event when not ready.");
        EventWaitGuard { event: self }
    }

    fn block_until(&self) -> Result<(), WakeReason> {
        // M6: busy-wait on the state machine. A timer-backed sleep should
        // replace this once the zx shim exposes a futex/timer wait.
        loop {
            match self.state.load(Ordering::Acquire) {
                WAITING => core::hint::spin_loop(),
                NOTIFIED => {
                    self.state.store(READY, Ordering::Relaxed);
                    return Ok(());
                }
                INTERRUPTED => {
                    self.state.store(READY, Ordering::Relaxed);
                    return Err(WakeReason::Interrupted);
                }
                other => panic!("Unexpected event state: {other}"),
            }
        }
    }

    /// Wake the event normally. Ignored if called before `begin_wait`.
    pub fn notify(&self) {
        self.wake(NOTIFIED);
    }

    /// Wake the event because of an interruption. Ignored if called before
    /// `begin_wait`.
    pub fn interrupt(&self) {
        self.wake(INTERRUPTED);
    }

    fn wake(&self, new_state: i32) {
        let _ = self.state.compare_exchange(
            WAITING,
            new_state,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}
