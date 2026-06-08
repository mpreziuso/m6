//! Zircon time types (timelines, instants and durations)
//!
//! Mirrors the upstream Fuchsia `zx` time model so forked Starnix code compiles
//! unchanged. Instants and durations are generic over a [`Timeline`] marker
//! (monotonic, boot, synthetic) and a [`TimeUnit`] marker (nanoseconds or
//! ticks). All values are plain `i64` nanosecond/tick counts — these are pure
//! data types and are implemented faithfully.

use core::marker::PhantomData;
use core::ops;

// -- Timeline markers

/// Marker trait preventing accidental comparison between different timelines.
pub trait Timeline: Default + Copy + Clone + PartialEq + Eq {}

/// The system monotonic timeline; pauses during suspend.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MonotonicTimeline;
impl Timeline for MonotonicTimeline {}

/// The system boot timeline; continues running during suspend.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BootTimeline;
impl Timeline for BootTimeline {}

/// A synthetic timeline defined by a kernel clock object.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SyntheticTimeline;
impl Timeline for SyntheticTimeline {}

/// The UTC timeline. Upstream this lives in `fuchsia_runtime`; M6 keeps it here
/// so the generic instant/duration machinery applies uniformly.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UtcTimeline;
impl Timeline for UtcTimeline {}

// -- Unit markers

/// Marker trait preventing comparison between different units.
pub trait TimeUnit {}

/// Nanoseconds unit marker.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NsUnit;
impl TimeUnit for NsUnit {}

/// System ticks unit marker.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TicksUnit;
impl TimeUnit for TicksUnit {}

// -- Sentinel values (Zircon encoding)

const ZX_TIME_INFINITE: i64 = i64::MAX;
const ZX_TIME_INFINITE_PAST: i64 = i64::MIN;

// -- Instant

/// A timestamp from the kernel, generic over its timeline and unit.
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Instant<T, U = NsUnit>(i64, PhantomData<(T, U)>);

impl<T, U> core::fmt::Debug for Instant<T, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Instant").field(&self.0).finish()
    }
}

impl<T: Timeline, U: TimeUnit> Instant<T, U> {
    /// The zero instant on this timeline.
    pub const ZERO: Instant<T, U> = Instant(0, PhantomData);
}

impl<T: Timeline> Instant<T> {
    /// The maximum representable instant ("infinite" deadline).
    pub const INFINITE: Instant<T, NsUnit> = Instant(ZX_TIME_INFINITE, PhantomData);
    /// The minimum representable instant ("infinite past").
    pub const INFINITE_PAST: Instant<T, NsUnit> = Instant(ZX_TIME_INFINITE_PAST, PhantomData);

    /// Returns the number of nanoseconds contained by this instant.
    pub const fn into_nanos(self) -> i64 {
        self.0
    }

    /// Builds a strongly-typed instant from a raw nanosecond count.
    pub const fn from_nanos(nanos: i64) -> Self {
        Instant(nanos, PhantomData)
    }

    /// Returns the duration between this instant and `rhs`.
    ///
    /// Always `Some` for matching timelines; returns `Option` to mirror the
    /// upstream signature used by forked code.
    pub fn delta(&self, rhs: &Self) -> Option<Duration<T, NsUnit>> {
        Some(Duration::from_nanos(self.0.saturating_sub(rhs.0)))
    }
}

impl MonotonicInstant {
    /// Returns the current monotonic time.
    ///
    /// Backed by the ARM generic timer virtual counter (CNTVCT_EL0), matching
    /// the M6 userspace monotonic primitive in `m6-starnix-std`.
    pub fn get() -> Self {
        Self::from_nanos(monotonic_nanos())
    }

    /// Computes a deadline `duration` in the future from now.
    pub fn after(duration: MonotonicDuration) -> Self {
        Self::from_nanos(monotonic_nanos().saturating_add(duration.0))
    }
}

impl BootInstant {
    /// Returns the current boot time.
    ///
    /// M6 does not yet expose a separate suspend-aware boot clock, so this is
    /// backed by the same monotonic counter as [`MonotonicInstant::get`].
    pub fn get() -> Self {
        Self::from_nanos(monotonic_nanos())
    }

    /// Computes a deadline `duration` in the future from now.
    pub fn after(duration: BootDuration) -> Self {
        Self::from_nanos(monotonic_nanos().saturating_add(duration.0))
    }
}

impl<T: Timeline, U: TimeUnit> ops::Add<Duration<T, U>> for Instant<T, U> {
    type Output = Instant<T, U>;
    fn add(self, dur: Duration<T, U>) -> Self::Output {
        Self(self.0.saturating_add(dur.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::Sub<Duration<T, U>> for Instant<T, U> {
    type Output = Instant<T, U>;
    fn sub(self, dur: Duration<T, U>) -> Self::Output {
        Self(self.0.saturating_sub(dur.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::Sub<Instant<T, U>> for Instant<T, U> {
    type Output = Duration<T, U>;
    fn sub(self, rhs: Instant<T, U>) -> Self::Output {
        Duration(self.0.saturating_sub(rhs.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::AddAssign<Duration<T, U>> for Instant<T, U> {
    fn add_assign(&mut self, dur: Duration<T, U>) {
        self.0 = self.0.saturating_add(dur.0);
    }
}

impl<T: Timeline, U: TimeUnit> ops::SubAssign<Duration<T, U>> for Instant<T, U> {
    fn sub_assign(&mut self, dur: Duration<T, U>) {
        self.0 = self.0.saturating_sub(dur.0);
    }
}

// -- Duration

/// A duration from the kernel, generic over its timeline and unit.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Duration<T, U = NsUnit>(i64, PhantomData<(T, U)>);

impl<T: Timeline> Duration<T, NsUnit> {
    /// The maximum representable duration.
    pub const INFINITE: Duration<T> = Duration(i64::MAX, PhantomData);
    /// The minimum representable duration.
    pub const INFINITE_PAST: Duration<T> = Duration(i64::MIN, PhantomData);
    /// The zero duration.
    pub const ZERO: Duration<T> = Duration(0, PhantomData);

    /// Returns the number of nanoseconds contained by this duration.
    pub const fn into_nanos(self) -> i64 {
        self.0
    }

    /// Returns the whole microseconds contained by this duration.
    pub const fn into_micros(self) -> i64 {
        self.0 / 1_000
    }

    /// Returns the whole milliseconds contained by this duration.
    pub const fn into_millis(self) -> i64 {
        self.into_micros() / 1_000
    }

    /// Returns the whole seconds contained by this duration.
    pub const fn into_seconds(self) -> i64 {
        self.into_millis() / 1_000
    }

    /// Returns the number of seconds contained by this duration as `f64`.
    pub fn into_seconds_f64(self) -> f64 {
        self.into_nanos() as f64 / 1_000_000_000_f64
    }

    /// Returns the whole minutes contained by this duration.
    pub const fn into_minutes(self) -> i64 {
        self.into_seconds() / 60
    }

    /// Returns the whole hours contained by this duration.
    pub const fn into_hours(self) -> i64 {
        self.into_minutes() / 60
    }

    /// Builds a duration from a raw nanosecond count.
    pub const fn from_nanos(nanos: i64) -> Self {
        Duration(nanos, PhantomData)
    }

    /// Builds a duration from a microsecond count.
    pub const fn from_micros(micros: i64) -> Self {
        Duration(micros.saturating_mul(1_000), PhantomData)
    }

    /// Builds a duration from a millisecond count.
    pub const fn from_millis(millis: i64) -> Self {
        Duration::from_micros(millis.saturating_mul(1_000))
    }

    /// Builds a duration from a second count.
    pub const fn from_seconds(secs: i64) -> Self {
        Duration::from_millis(secs.saturating_mul(1_000))
    }

    /// Builds a duration from a minute count.
    pub const fn from_minutes(min: i64) -> Self {
        Duration::from_seconds(min.saturating_mul(60))
    }

    /// Builds a duration from an hour count.
    pub const fn from_hours(hours: i64) -> Self {
        Duration::from_minutes(hours.saturating_mul(60))
    }
}

impl<T: Timeline, U: TimeUnit> ops::Add<Instant<T, U>> for Duration<T, U> {
    type Output = Instant<T, U>;
    fn add(self, time: Instant<T, U>) -> Self::Output {
        Instant(self.0.saturating_add(time.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::Add for Duration<T, U> {
    type Output = Duration<T, U>;
    fn add(self, rhs: Duration<T, U>) -> Self::Output {
        Self(self.0.saturating_add(rhs.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::Sub for Duration<T, U> {
    type Output = Duration<T, U>;
    fn sub(self, rhs: Duration<T, U>) -> Duration<T, U> {
        Self(self.0.saturating_sub(rhs.0), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::AddAssign for Duration<T, U> {
    fn add_assign(&mut self, rhs: Duration<T, U>) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

impl<T: Timeline, U: TimeUnit> ops::SubAssign for Duration<T, U> {
    fn sub_assign(&mut self, rhs: Duration<T, U>) {
        self.0 = self.0.saturating_sub(rhs.0);
    }
}

impl<T: Timeline, S: Into<i64>, U: TimeUnit> ops::Mul<S> for Duration<T, U> {
    type Output = Self;
    fn mul(self, mul: S) -> Self {
        Self(self.0.saturating_mul(mul.into()), PhantomData)
    }
}

impl<S: Into<i64>, T: Timeline, U: TimeUnit> ops::Div<S> for Duration<T, U> {
    type Output = Self;
    fn div(self, div: S) -> Self {
        Self(self.0.saturating_div(div.into()), PhantomData)
    }
}

impl<T: Timeline, U: TimeUnit> ops::Neg for Duration<T, U> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.saturating_neg(), PhantomData)
    }
}

// -- Type aliases mirroring upstream

/// A monotonic-timeline instant in nanoseconds.
pub type MonotonicInstant = Instant<MonotonicTimeline, NsUnit>;
/// A synthetic-timeline instant in nanoseconds.
pub type SyntheticInstant = Instant<SyntheticTimeline, NsUnit>;
/// A boot-timeline instant in nanoseconds.
pub type BootInstant = Instant<BootTimeline, NsUnit>;
/// A UTC-timeline instant in nanoseconds.
pub type UtcInstant = Instant<UtcTimeline, NsUnit>;
/// A ticks timestamp on a given timeline.
pub type Ticks<T> = Instant<T, TicksUnit>;
/// A monotonic-timeline ticks timestamp.
pub type MonotonicTicks = Instant<MonotonicTimeline, TicksUnit>;
/// A boot-timeline ticks timestamp.
pub type BootTicks = Instant<BootTimeline, TicksUnit>;

/// A monotonic-timeline duration in nanoseconds.
pub type MonotonicDuration = Duration<MonotonicTimeline, NsUnit>;
/// A boot-timeline duration in nanoseconds.
pub type BootDuration = Duration<BootTimeline, NsUnit>;
/// A synthetic-timeline duration in nanoseconds.
pub type SyntheticDuration = Duration<SyntheticTimeline, NsUnit>;
/// A UTC-timeline duration in nanoseconds.
pub type UtcDuration = Duration<UtcTimeline, NsUnit>;
/// A monotonic-timeline ticks duration.
pub type MonotonicDurationTicks = Duration<MonotonicTimeline, TicksUnit>;
/// A boot-timeline ticks duration.
pub type BootDurationTicks = Duration<BootTimeline, TicksUnit>;

// -- Backing monotonic clock

/// Reads the current monotonic time in nanoseconds.
///
/// Uses the ARM generic timer virtual counter, matching the M6 userspace
/// monotonic primitive. Returns `0` if the frequency reads as zero.
fn monotonic_nanos() -> i64 {
    let count: u64;
    // SAFETY: CNTVCT_EL0 is readable from EL0 when CNTKCTL_EL1.EL0VCTEN=1, which
    // M6 configures for userspace. The read has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nostack, nomem));
    }
    let freq: u64;
    // SAFETY: CNTFRQ_EL0 is always readable and has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack, nomem));
    }
    let nanos = count
        .saturating_mul(1_000_000_000)
        .checked_div(freq)
        .unwrap_or(0);
    nanos.min(i64::MAX as u64) as i64
}
