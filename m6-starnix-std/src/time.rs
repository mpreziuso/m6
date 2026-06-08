//! Time types
//!
//! Re-exports `core::time::Duration` and provides a minimal `Instant`.

pub use core::time::Duration;

/// A measurement of a monotonically non-decreasing clock.
///
/// In the Starnix context this is used for timeouts and elapsed time.
/// The underlying counter uses the ARM generic timer via CNTVCT_EL0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// Returns an instant corresponding to "now".
    ///
    /// In the M6 userspace context, this reads the virtual counter.
    pub fn now() -> Self {
        // Read ARM generic timer virtual count
        let count: u64;
        // SAFETY: CNTVCT_EL0 is readable from EL0 when CNTKCTL_EL1.EL0VCTEN=1.
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nostack, nomem));
        }
        // Read timer frequency
        let freq: u64;
        // SAFETY: CNTFRQ_EL0 is always readable.
        unsafe {
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack, nomem));
        }
        // Convert to nanoseconds
        let nanos = count
            .saturating_mul(1_000_000_000)
            .checked_div(freq)
            .unwrap_or(0);
        Self { nanos }
    }

    pub fn duration_since(&self, earlier: Self) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.nanos
            .checked_add(duration.as_nanos() as u64)
            .map(|nanos| Self { nanos })
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        self.nanos
            .checked_sub(duration.as_nanos() as u64)
            .map(|nanos| Self { nanos })
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Self;
    fn add(self, rhs: Duration) -> Self {
        self.checked_add(rhs)
            .expect("overflow when adding duration to instant")
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Self;
    fn sub(self, rhs: Duration) -> Self {
        self.checked_sub(rhs)
            .expect("overflow when subtracting duration from instant")
    }
}

impl core::ops::Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, rhs: Instant) -> Duration {
        self.duration_since(rhs)
    }
}

/// The point at which `SystemTime` measurements begin (the Unix epoch).
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0 };

/// A measurement of the system clock (wall-clock time), mirroring
/// `std::time::SystemTime`.
///
/// M6 does not yet have a real-time clock wired here, so this is anchored to the
/// monotonic counter; `now()` returns time since boot rather than since the Unix
/// epoch. The API surface matches std so forked code compiles; absolute wall
/// time becomes correct once an RTC is plumbed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime {
    nanos: u64,
}

/// Error returned from `SystemTime::duration_since` when the argument is later
/// than `self`.
#[derive(Debug, Clone)]
pub struct SystemTimeError(Duration);

impl SystemTimeError {
    /// Returns the positive duration by which the times differ.
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl SystemTime {
    /// The Unix epoch, i.e. 1970-01-01 00:00:00 UTC.
    pub const UNIX_EPOCH: SystemTime = UNIX_EPOCH;

    /// Returns the system time corresponding to "now".
    pub fn now() -> Self {
        Self { nanos: Instant::now().nanos }
    }

    /// Returns the duration elapsed from `earlier` to `self`, or an error if
    /// `earlier` is later than `self`.
    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, SystemTimeError> {
        if self.nanos >= earlier.nanos {
            Ok(Duration::from_nanos(self.nanos - earlier.nanos))
        } else {
            Err(SystemTimeError(Duration::from_nanos(earlier.nanos - self.nanos)))
        }
    }

    /// Returns the amount of time elapsed since this `SystemTime`.
    pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
        Self::now().duration_since(*self)
    }

    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.nanos.checked_add(duration.as_nanos() as u64).map(|nanos| Self { nanos })
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        self.nanos.checked_sub(duration.as_nanos() as u64).map(|nanos| Self { nanos })
    }
}

impl core::ops::Add<Duration> for SystemTime {
    type Output = Self;
    fn add(self, rhs: Duration) -> Self {
        self.checked_add(rhs).expect("overflow when adding duration to system time")
    }
}

impl core::ops::Sub<Duration> for SystemTime {
    type Output = Self;
    fn sub(self, rhs: Duration) -> Self {
        self.checked_sub(rhs).expect("overflow when subtracting duration from system time")
    }
}
