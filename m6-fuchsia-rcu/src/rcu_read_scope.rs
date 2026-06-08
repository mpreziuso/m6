// RCU read-scope guard.

use crate::state_machine::{rcu_read_lock, rcu_read_unlock};
use core::marker::PhantomData;

/// A scope that holds a read lock on the RCU state machine.
///
/// References handed out by RCU containers are bound to the lifetime of an
/// `RcuReadScope`, ensuring that the referenced object remains valid until the
/// scope is dropped.
///
/// As in the upstream crate, an `RcuReadScope` is deliberately `!Send`: the
/// read lock must be acquired and released on the same thread.
pub struct RcuReadScope {
    // We need to call `rcu_read_lock` and `rcu_read_unlock` from the same
    // thread, so we make `RcuReadScope` non-Send.
    _marker: PhantomData<*const ()>,
}

impl RcuReadScope {
    /// Create a new read scope.
    ///
    /// This acquires a read lock on the RCU state machine which is held until
    /// the scope is dropped.
    pub fn new() -> Self {
        rcu_read_lock();
        Self {
            _marker: PhantomData,
        }
    }
}

impl Default for RcuReadScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RcuReadScope {
    fn drop(&mut self) {
        rcu_read_unlock();
    }
}
