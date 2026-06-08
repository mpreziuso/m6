//! Time measurement and timers
//!
//! Provides types for measuring time using ARM64's generic timer.
//!
//! Two clocks are offered:
//! - [`Instant`] — a monotonic clock read directly from the generic timer
//!   counter; ideal for measuring elapsed time. It never goes backwards but
//!   bears no relation to real-world time.
//! - [`SystemTime`] — the system wall clock (real / UTC time), obtained from
//!   the kernel via the GetTime syscall. It tracks calendar time but may jump
//!   when a time service adjusts it, and is only available once such a service
//!   has set it.

pub use core::time::Duration;

use m6_syscall::error::SyscallError;
use m6_syscall::invoke::{get_time, set_time};

/// A measurement of a monotonically nondecreasing clock.
///
/// Similar to std::time::Instant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Instant {
    ticks: u64,
}

impl Instant {
    /// Returns an instant corresponding to "now".
    #[inline]
    pub fn now() -> Self {
        let ticks: u64;
        // SAFETY: Reading CNTPCT_EL0 is safe from EL0
        unsafe {
            core::arch::asm!(
                "mrs {}, cntpct_el0",
                out(reg) ticks,
                options(nomem, nostack)
            );
        }
        Self { ticks }
    }

    /// Returns the amount of time elapsed since this instant.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    /// Returns the amount of time elapsed from another instant to this one.
    ///
    /// Returns zero if `earlier` is actually later than self.
    #[inline]
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        let freq = timer_frequency();
        let ticks = self.ticks.saturating_sub(earlier.ticks);

        if freq == 0 {
            return Duration::ZERO;
        }

        // Convert ticks to nanoseconds: ticks * 1_000_000_000 / freq
        // Use u128 to avoid overflow
        let nanos = (ticks as u128 * 1_000_000_000) / freq as u128;

        Duration::from_nanos(nanos as u64)
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or None if `earlier` is later than self.
    #[inline]
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        if self.ticks >= earlier.ticks {
            Some(self.duration_since(earlier))
        } else {
            None
        }
    }

    /// Returns `Some(t)` where `t` is the instant representing `self + duration`
    /// if the computation does not overflow, otherwise returns `None`.
    #[inline]
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        let freq = timer_frequency();
        if freq == 0 {
            return None;
        }

        // Convert duration to ticks: nanos * freq / 1_000_000_000
        let nanos = duration.as_nanos();
        let ticks = (nanos * freq as u128 / 1_000_000_000) as u64;

        self.ticks.checked_add(ticks).map(|t| Instant { ticks: t })
    }

    /// Returns `Some(t)` where `t` is the instant representing `self - duration`
    /// if the computation does not underflow, otherwise returns `None`.
    #[inline]
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        let freq = timer_frequency();
        if freq == 0 {
            return None;
        }

        let nanos = duration.as_nanos();
        let ticks = (nanos * freq as u128 / 1_000_000_000) as u64;

        self.ticks.checked_sub(ticks).map(|t| Instant { ticks: t })
    }

    /// Returns the raw tick count.
    ///
    /// This is useful for low-level timing operations.
    #[inline]
    pub fn as_ticks(&self) -> u64 {
        self.ticks
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        self.checked_add(other)
            .expect("overflow when adding duration to instant")
    }
}

impl core::ops::AddAssign<Duration> for Instant {
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        self.checked_sub(other)
            .expect("overflow when subtracting duration from instant")
    }
}

impl core::ops::SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl core::ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

/// Get the timer frequency in Hz.
///
/// This reads CNTFRQ_EL0 which contains the frequency of the system counter.
#[inline]
fn timer_frequency() -> u64 {
    let freq: u64;
    // SAFETY: Reading CNTFRQ_EL0 is safe from EL0
    unsafe {
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack)
        );
    }
    freq
}

/// A measurement of the system wall clock (real / UTC time).
///
/// Unlike [`Instant`], which is monotonic and counts from an arbitrary origin,
/// `SystemTime` measures real-world time as reported by the kernel wall clock.
/// It may jump forwards or backwards if a time service adjusts the clock, so it
/// is unsuitable for measuring elapsed durations — use [`Instant`] for that.
///
/// The kernel wall clock must first be established by a userspace time service
/// (RTC or NTP policy) via [`set`](SystemTime::set); until then
/// [`now`](SystemTime::now) returns [`SyscallError::InvalidState`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SystemTime {
    /// Nanoseconds since the Unix epoch.
    nanos: u64,
}

/// An anchor in time corresponding to 1970-01-01 00:00:00 UTC (the Unix epoch).
///
/// Mirrors `std::time::UNIX_EPOCH`. Use with
/// [`SystemTime::duration_since`] to obtain a Unix timestamp.
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0 };

impl SystemTime {
    /// The Unix epoch (1970-01-01 00:00:00 UTC). Equal to [`UNIX_EPOCH`].
    pub const UNIX_EPOCH: SystemTime = UNIX_EPOCH;

    /// Returns the current system wall-clock time.
    ///
    /// # Errors
    ///
    /// Returns [`SyscallError::InvalidState`] if no time service has set the
    /// wall clock yet.
    #[inline]
    pub fn now() -> Result<SystemTime, SyscallError> {
        get_time().map(|nanos| SystemTime { nanos })
    }

    /// Establishes the system wall clock for the whole system.
    ///
    /// This is a privileged operation: `timer_control` must be a capability
    /// pointer to the TimerControl object (the timekeeping authority). It is
    /// intended for a userspace time service that owns a real-time source.
    ///
    /// # Errors
    ///
    /// Returns an error if `timer_control` is not a TimerControl capability
    /// with write authority.
    #[inline]
    pub fn set(timer_control: u64, time: SystemTime) -> Result<(), SyscallError> {
        set_time(timer_control, time.nanos).map(|_| ())
    }

    /// Returns the amount of time elapsed from an earlier point in time.
    ///
    /// Returns `Ok(duration)` if `earlier` is not later than `self`, otherwise
    /// `Err(duration)` where the duration is how far `earlier` is ahead of
    /// `self` (mirroring `std::time::SystemTime::duration_since`).
    #[inline]
    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, Duration> {
        if self.nanos >= earlier.nanos {
            Ok(Duration::from_nanos(self.nanos - earlier.nanos))
        } else {
            Err(Duration::from_nanos(earlier.nanos - self.nanos))
        }
    }

    /// Returns the duration since the Unix epoch.
    ///
    /// Equivalent to `self.duration_since(UNIX_EPOCH)`, but infallible since the
    /// wall clock is always at or after the epoch.
    #[inline]
    pub fn duration_since_epoch(&self) -> Duration {
        Duration::from_nanos(self.nanos)
    }

    /// Returns the raw wall-clock value in nanoseconds since the Unix epoch.
    #[inline]
    pub fn as_unix_nanos(&self) -> u64 {
        self.nanos
    }

    /// Constructs a `SystemTime` from nanoseconds since the Unix epoch.
    #[inline]
    pub const fn from_unix_nanos(nanos: u64) -> SystemTime {
        SystemTime { nanos }
    }

    /// Returns `Some(t)` where `t` is `self + duration`, or `None` on overflow.
    #[inline]
    pub fn checked_add(&self, duration: Duration) -> Option<SystemTime> {
        let nanos = u64::try_from(duration.as_nanos()).ok()?;
        self.nanos.checked_add(nanos).map(|nanos| SystemTime { nanos })
    }

    /// Returns `Some(t)` where `t` is `self - duration`, or `None` on underflow.
    #[inline]
    pub fn checked_sub(&self, duration: Duration) -> Option<SystemTime> {
        let nanos = u64::try_from(duration.as_nanos()).ok()?;
        self.nanos.checked_sub(nanos).map(|nanos| SystemTime { nanos })
    }
}

impl core::ops::Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, other: Duration) -> SystemTime {
        self.checked_add(other)
            .expect("overflow when adding duration to system time")
    }
}

impl core::ops::Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, other: Duration) -> SystemTime {
        self.checked_sub(other)
            .expect("underflow when subtracting duration from system time")
    }
}
