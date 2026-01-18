//! ARM Generic Timer Support
//!
//! Provides access to the ARM architectural timer for:
//! - Time measurement
//! - Periodic interrupts for preemption

use core::sync::atomic::{AtomicU64, Ordering};

use aarch64_cpu::registers::{CNTFRQ_EL0, CNTV_CTL_EL0, CNTV_CVAL_EL0, CNTVCT_EL0};
use tock_registers::interfaces::{Readable, Writeable};

/// Timer frequency (will be read from CNTFRQ_EL0)
/// Stored as atomic since it's set once at init and read frequently from logging.
static TIMER_FREQ: AtomicU64 = AtomicU64::new(0);

/// Read the counter frequency
fn read_cntfrq() -> u64 {
    CNTFRQ_EL0.get()
}

/// Read the virtual counter
pub fn read_counter() -> u64 {
    CNTVCT_EL0.get()
}

/// Read the virtual timer compare value
#[allow(dead_code)]
fn read_cntv_cval() -> u64 {
    CNTV_CVAL_EL0.get()
}

/// Write the virtual timer compare value
fn write_cntv_cval(cval: u64) {
    CNTV_CVAL_EL0.set(cval);
}

/// Read the virtual timer control register
fn read_cntv_ctl() -> u64 {
    CNTV_CTL_EL0.get()
}

/// Write the virtual timer control register
fn write_cntv_ctl(ctl: u64) {
    CNTV_CTL_EL0.set(ctl);
}

/// Timer control register bits
mod ctl {
    /// Timer enabled
    pub const ENABLE: u64 = 1 << 0;
    /// Interrupt masked
    pub const IMASK: u64 = 1 << 1;
    /// Interrupt status (condition met)
    pub const ISTATUS: u64 = 1 << 2;
}

/// Initialise the timer subsystem
pub fn init() {
    let freq = read_cntfrq();
    TIMER_FREQ.store(freq, Ordering::Relaxed);

    // Disable timer initially
    write_cntv_ctl(0);
}

/// Get the timer frequency in Hz
pub fn frequency() -> u64 {
    TIMER_FREQ.load(Ordering::Relaxed)
}

/// Get current time in nanoseconds since boot
pub fn now_ns() -> u64 {
    let count = read_counter();
    let freq = TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }

    // Calculate nanoseconds: (count * 1_000_000_000) / freq
    // To avoid overflow, we use: (count / freq) * 1e9 + ((count % freq) * 1e9) / freq
    let secs = count / freq;
    let frac = count % freq;
    secs * 1_000_000_000 + (frac * 1_000_000_000) / freq
}

/// Get current time in microseconds since boot
pub fn now_us() -> u64 {
    let count = read_counter();
    let freq = TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }

    let secs = count / freq;
    let frac = count % freq;
    secs * 1_000_000 + (frac * 1_000_000) / freq
}

/// Get current time in milliseconds since boot
pub fn now_ms() -> u64 {
    let count = read_counter();
    let freq = TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }

    let secs = count / freq;
    let frac = count % freq;
    secs * 1_000 + (frac * 1_000) / freq
}

/// Set the timer to fire after a given number of ticks
pub fn set_timer_ticks(ticks: u64) {
    let current = read_counter();
    let target = current.wrapping_add(ticks);

    write_cntv_cval(target);
    write_cntv_ctl(ctl::ENABLE);
}

/// Set the timer to fire after a given number of microseconds
pub fn set_timer_us(us: u64) {
    let freq = TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        return;
    }

    let ticks = (us * freq) / 1_000_000;
    set_timer_ticks(ticks);
}

/// Set the timer to fire after a given number of milliseconds
pub fn set_timer_ms(ms: u64) {
    set_timer_us(ms * 1000);
}

/// Clear the timer interrupt
pub fn clear_timer() {
    // Disable the timer to clear the interrupt
    write_cntv_ctl(ctl::IMASK);
}

/// Check if the timer interrupt is pending
pub fn is_timer_pending() -> bool {
    (read_cntv_ctl() & ctl::ISTATUS) != 0
}

/// Enable the timer interrupt
pub fn enable_timer() {
    let ctl = read_cntv_ctl();
    write_cntv_ctl((ctl | ctl::ENABLE) & !ctl::IMASK);
}

/// Disable the timer interrupt
pub fn disable_timer() {
    let ctl = read_cntv_ctl();
    write_cntv_ctl(ctl | ctl::IMASK);
}

/// Spin delay for a given number of microseconds
pub fn delay_us(us: u64) {
    let freq = TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        // Fallback to busy loop
        for _ in 0..us * 100 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (us * freq) / 1_000_000;
    let start = read_counter();
    let _target = start.wrapping_add(ticks);

    while read_counter().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Spin delay for a given number of milliseconds
pub fn delay_ms(ms: u64) {
    delay_us(ms * 1000);
}

/// Duration type for timer operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    /// Duration in nanoseconds
    nanos: u64,
}

impl Duration {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self {
            nanos: micros * 1000,
        }
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self {
            nanos: millis * 1_000_000,
        }
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self {
            nanos: secs * 1_000_000_000,
        }
    }

    pub const fn as_nanos(&self) -> u64 {
        self.nanos
    }

    pub const fn as_micros(&self) -> u64 {
        self.nanos / 1000
    }

    pub const fn as_millis(&self) -> u64 {
        self.nanos / 1_000_000
    }

    pub const fn as_secs(&self) -> u64 {
        self.nanos / 1_000_000_000
    }

    pub fn as_ticks(&self) -> u64 {
        let freq = TIMER_FREQ.load(Ordering::Relaxed);
        if freq == 0 {
            return 0;
        }
        (self.nanos * freq) / 1_000_000_000
    }
}

/// Instant in time (for measuring elapsed time)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instant {
    ticks: u64,
}

impl Instant {
    pub fn now() -> Self {
        Self {
            ticks: read_counter(),
        }
    }

    pub const fn from_ticks(ticks: u64) -> Self {
        Self { ticks }
    }

    pub fn try_now() -> Option<Self> {
        let freq = TIMER_FREQ.load(Ordering::Relaxed);
        if freq == 0 { None } else { Some(Self::now()) }
    }

    pub fn elapsed(&self) -> Duration {
        let now = read_counter();
        let elapsed_ticks = now.wrapping_sub(self.ticks);
        let freq = TIMER_FREQ.load(Ordering::Relaxed);
        if freq == 0 {
            return Duration::from_nanos(0);
        }
        Duration::from_nanos((elapsed_ticks * 1_000_000_000) / freq)
    }

    pub fn has_elapsed(&self, duration: Duration) -> bool {
        self.elapsed() >= duration
    }

    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        if self.ticks >= earlier.ticks {
            let elapsed_ticks = self.ticks - earlier.ticks;
            let freq = TIMER_FREQ.load(Ordering::Relaxed);
            if freq == 0 {
                return Some(Duration::from_nanos(0));
            }
            Some(Duration::from_nanos((elapsed_ticks * 1_000_000_000) / freq))
        } else {
            None
        }
    }

    pub fn ticks(&self) -> u64 {
        self.ticks
    }
}

impl PartialOrd for Instant {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Instant {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.ticks.cmp(&other.ticks)
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, duration: Duration) -> Self::Output {
        let freq = TIMER_FREQ.load(Ordering::Relaxed);
        let ticks = if freq == 0 {
            0
        } else {
            (duration.as_nanos() * freq) / 1_000_000_000
        };
        Instant {
            ticks: self.ticks.wrapping_add(ticks),
        }
    }
}

impl core::ops::Sub for Instant {
    type Output = Duration;

    fn sub(self, other: Instant) -> Self::Output {
        self.checked_duration_since(other)
            .unwrap_or(Duration::from_nanos(0))
    }
}
