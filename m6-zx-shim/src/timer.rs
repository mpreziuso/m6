//! Timer shim (wraps M6 Timer capability)

use crate::Status;

/// A timer handle wrapping an M6 Timer capability.
#[allow(dead_code)]
pub struct Timer {
    /// Timer capability pointer
    pub(crate) timer_cptr: u64,
}

impl Timer {
    /// Create a new timer handle.
    pub fn new(timer_cptr: u64) -> Self {
        Self { timer_cptr }
    }

    /// Set the timer to fire at the given deadline (nanoseconds since boot).
    pub fn set(&self, _deadline: i64, _slack: i64) -> Result<(), Status> {
        // TODO: Invoke timer::ARM
        Ok(())
    }

    /// Cancel the timer.
    pub fn cancel(&self) -> Result<(), Status> {
        // TODO: Invoke timer::CANCEL
        Ok(())
    }
}
