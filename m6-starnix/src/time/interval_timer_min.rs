// Minimal always-on interval-timer types for the M6 minimal core.
//
// The real `interval_timer` engine (hr_timer-backed POSIX timers, arming via
// the Fuchsia async executor + zx::Clock) is gated. But `TimerTable` and the
// `ClockId`/`TimerId` types in `time::timers` — used by the kept `clock_*`
// syscalls — reference `IntervalTimer`/`IntervalTimerHandle`. This module
// supplies those types with inert behaviour so the core compiles: timers can be
// created and tracked but never fire (arming is a no-op). Real arming/firing
// returns with the clock-object model (M5).

#[allow(unused_imports)]
use m6_starnix_std::prelude::*;
use crate::signals::SignalEvent;
use crate::task::CurrentTask;
use crate::time::{Timeline, TimerId, TimerWakeup};
use starnix_types::time::timespec_from_duration;
use starnix_uapi::errors::Errno;
use starnix_uapi::itimerspec;
use m6_starnix_std::sync::Arc;

/// Remaining time on a timer. Mirrors the gated engine's type.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerRemaining {
    /// Remaining time until the next expiration.
    pub remainder: zx::SyntheticDuration,
    /// Interval for a periodic timer.
    pub interval: zx::SyntheticDuration,
}

/// A POSIX interval timer (inert in the minimal core).
pub struct IntervalTimer {
    /// The timer id (`timer_create`).
    pub timer_id: TimerId,
    /// The signal delivered on expiry.
    pub signal_event: SignalEvent,
}

impl core::fmt::Debug for IntervalTimer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntervalTimer").field("timer_id", &self.timer_id).finish_non_exhaustive()
    }
}

/// A reference-counted handle to an [`IntervalTimer`].
pub type IntervalTimerHandle = Arc<IntervalTimer>;

impl IntervalTimer {
    /// Creates a new (inert) interval timer.
    pub fn new(
        timer_id: TimerId,
        _timeline: Timeline,
        _wakeup_type: TimerWakeup,
        signal_event: SignalEvent,
    ) -> Result<IntervalTimerHandle, Errno> {
        Ok(Arc::new(Self { timer_id, signal_event }))
    }

    /// Arms the timer. No-op: the minimal core has no firing mechanism.
    pub fn arm(
        self: &IntervalTimerHandle,
        _current_task: &CurrentTask,
        _new_value: itimerspec,
        _is_absolute: bool,
    ) -> Result<(), Errno> {
        Ok(())
    }

    /// Disarms the timer. No-op.
    pub fn disarm(&self, _current_task: &CurrentTask) -> Result<(), Errno> {
        Ok(())
    }

    /// Returns the remaining time. Always zero (inert).
    pub fn time_remaining(&self) -> TimerRemaining {
        TimerRemaining::default()
    }

    /// Current overrun count. Always zero (timer never fires).
    pub fn overrun_cur(&self) -> i32 {
        0
    }

    /// Last overrun count. Always zero.
    pub fn overrun_last(&self) -> i32 {
        0
    }

    /// Notifies the timer that its signal was delivered. No-op.
    pub fn on_signal_delivered(self: &IntervalTimerHandle) {}
}

impl PartialEq for IntervalTimer {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}
impl Eq for IntervalTimer {}

impl From<TimerRemaining> for itimerspec {
    fn from(value: TimerRemaining) -> Self {
        Self {
            it_interval: timespec_from_duration(value.interval),
            it_value: timespec_from_duration(value.remainder),
        }
    }
}
