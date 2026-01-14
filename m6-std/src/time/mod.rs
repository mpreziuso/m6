//! Time measurement and timers
//!
//! Provides types for measuring time using ARM64's generic timer.

pub use core::time::Duration;

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
