//! Zircon object signals
//!
//! Bitflags describing the assertable state bits on Zircon kernel objects.
//! Values mirror the upstream `zx::Signals` encoding for the bits the fork
//! actually references.

use bitflags::bitflags;

bitflags! {
    /// Assertable signals on a Zircon kernel object.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Signals: u32 {
        const USER_0 = 1 << 24;
        const USER_1 = 1 << 25;
        const USER_2 = 1 << 26;
        const USER_3 = 1 << 27;

        // -- Object-specific signals
        const EVENT_SIGNALED = 1 << 3;
        const EVENTPAIR_SIGNALED = 1 << 3;
        const EVENTPAIR_PEER_CLOSED = 1 << 2;
        const TIMER_SIGNALED = 1 << 3;
        const CHANNEL_READABLE = 1 << 0;
        const CHANNEL_WRITABLE = 1 << 1;
        const CHANNEL_PEER_CLOSED = 1 << 2;
        const CLOCK_UPDATED = 1 << 4;
        const COUNTER_POSITIVE = 1 << 5;
        const COUNTER_NON_POSITIVE = 1 << 6;

        // -- Process / task signals
        const PROCESS_TERMINATED = 1 << 3;
        const TASK_TERMINATED = 1 << 3;
    }
}

impl Signals {
    /// No signals asserted.
    pub const NONE: Self = Self::empty();

    /// Builds a `Signals` from a raw bit pattern (alias for `from_bits_retain`
    /// covering the common upstream constructor name).
    pub const fn new(bits: u32) -> Self {
        Self::from_bits_retain(bits)
    }
}
