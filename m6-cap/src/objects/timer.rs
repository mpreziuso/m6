//! Timer management capabilities
//!
//! The timer system has two capability types:
//!
//! - **TimerControl**: Singleton capability to create timers
//! - **Timer**: Binds a time expiry to a notification
//!
//! # Timer Flow
//!
//! 1. Userspace arms timer with duration or absolute time
//! 2. Timer is inserted into kernel's timer queue
//! 3. Hardware timer interrupt fires when time elapses
//! 4. Kernel signals the bound notification with the configured badge
//! 5. Userspace receives the notification
//! 6. For periodic timers, the timer is automatically re-armed

use crate::Badge;
use crate::slot::ObjectRef;

/// Timer state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TimerState {
    /// Timer is not armed.
    #[default]
    Inactive = 0,
    /// Timer is armed and waiting to expire.
    Armed = 1,
}

/// Timer object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct TimerObject {
    /// Current state.
    pub state: TimerState,
    /// Bound notification object.
    pub notification: ObjectRef,
    /// Badge to use when signalling.
    pub badge: Badge,
    /// Whether this is a periodic timer.
    pub is_periodic: bool,
    /// Period in nanoseconds (for re-arming periodic timers).
    pub period_ns: u64,
}

impl TimerObject {
    /// Create a new timer object.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TimerState::Inactive,
            notification: ObjectRef::NULL,
            badge: Badge::NONE,
            is_periodic: false,
            period_ns: 0,
        }
    }

    /// Check if the timer is bound to a notification.
    #[inline]
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.notification.is_valid()
    }

    /// Check if the timer is currently armed.
    #[inline]
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        matches!(self.state, TimerState::Armed)
    }

    /// Bind to a notification.
    #[inline]
    pub fn bind(&mut self, notification: ObjectRef, badge: Badge) {
        self.notification = notification;
        self.badge = badge;
    }

    /// Unbind from the notification.
    #[inline]
    pub fn unbind(&mut self) {
        self.notification = ObjectRef::NULL;
        self.badge = Badge::NONE;
        self.state = TimerState::Inactive;
        self.is_periodic = false;
        self.period_ns = 0;
    }

    /// Arm the timer (set it to active state).
    ///
    /// # Arguments
    ///
    /// - `is_periodic`: Whether this is a periodic timer
    /// - `period_ns`: Period in nanoseconds (used for re-arming)
    #[inline]
    pub fn arm(&mut self, is_periodic: bool, period_ns: u64) {
        self.state = TimerState::Armed;
        self.is_periodic = is_periodic;
        self.period_ns = period_ns;
    }

    /// Disarm the timer (deactivate).
    #[inline]
    pub fn disarm(&mut self) {
        self.state = TimerState::Inactive;
    }
}

/// Timer control object metadata.
///
/// There is exactly one TimerControl capability in the system,
/// given to the root task at boot.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct TimerControlObject {
    // No tracking needed since we don't impose limits on timer creation
    _reserved: u32,
}

impl TimerControlObject {
    /// Create a new timer control object.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { _reserved: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_object() {
        let mut timer = TimerObject::new();
        assert!(!timer.is_bound());
        assert!(!timer.is_armed());

        timer.bind(ObjectRef::from_index(1), Badge::new(0x01));
        assert!(timer.is_bound());
        assert!(!timer.is_armed());

        timer.arm(false, 0);
        assert!(timer.is_armed());

        timer.disarm();
        assert!(!timer.is_armed());
    }

    #[test]
    fn test_periodic_timer() {
        let mut timer = TimerObject::new();
        timer.bind(ObjectRef::from_index(1), Badge::new(0x01));
        timer.arm(true, 1_000_000); // 1ms period

        assert!(timer.is_armed());
        assert!(timer.is_periodic);
        assert_eq!(timer.period_ns, 1_000_000);
    }

    #[test]
    fn test_timer_unbind() {
        let mut timer = TimerObject::new();
        timer.bind(ObjectRef::from_index(1), Badge::new(0x01));
        timer.arm(true, 1_000_000);

        timer.unbind();
        assert!(!timer.is_bound());
        assert!(!timer.is_armed());
        assert!(!timer.is_periodic);
        assert_eq!(timer.period_ns, 0);
    }

    #[test]
    fn test_timer_control() {
        let _ctrl = TimerControlObject::new();
        // TimerControl has no behaviour to test (no quota tracking)
    }
}
