// Minimal-core RCU state machine for the M6 Starnix bring-up shim.
//
// The upstream `fuchsia_rcu` implements a full lock-free, generation-counter
// RCU grace-period state machine. A faithful lock-free RCU is out of scope for
// the M6 single-CPU bring-up. Instead, this module provides the same public
// surface (`rcu_drop`, `rcu_run_callbacks`, `rcu_synchronize`) but with greatly
// simplified semantics:
//
//   * Read-side critical sections are no-ops (`rcu_read_lock` /
//     `rcu_read_unlock` do nothing).
//   * `rcu_drop` defers the destructor of a replaced value by leaking it. On a
//     single CPU this keeps any outstanding `&'a T` reference (handed out via an
//     `RcuReadScope`) valid for as long as the scope lives, which is exactly the
//     guarantee the call sites rely on. The cost is that updated values are not
//     reclaimed; this is acceptable for bring-up.
//   * `rcu_run_callbacks` and `rcu_synchronize` are no-ops because there is no
//     grace period to advance and no callbacks are ever queued.
//
// SIMPLIFICATION: this trades memory reclamation for soundness simplicity. It is
// adequate for single-CPU bring-up only and must be replaced with a real RCU
// implementation before relying on it under concurrency.

use core::sync::atomic::{AtomicPtr, Ordering};

// -- Read-side critical section (no-op)

/// Enter a read-side critical section.
///
/// No-op in the bring-up shim.
#[inline]
pub fn rcu_read_lock() {}

/// Leave a read-side critical section.
///
/// No-op in the bring-up shim.
#[inline]
pub fn rcu_read_unlock() {}

// -- Pointer helpers

/// Read a pointer published by a writer.
#[inline]
pub fn rcu_read_pointer<T>(ptr: &AtomicPtr<T>) -> *mut T {
    ptr.load(Ordering::Acquire)
}

/// Publish a new pointer value.
#[inline]
pub fn rcu_assign_pointer<T>(ptr: &AtomicPtr<T>, value: *mut T) {
    ptr.store(value, Ordering::Release);
}

/// Atomically replace a pointer value, returning the previous one.
#[inline]
pub fn rcu_replace_pointer<T>(ptr: &AtomicPtr<T>, value: *mut T) -> *mut T {
    ptr.swap(value, Ordering::AcqRel)
}

// -- Deferred reclamation

/// Defer the destruction of `value` until the next grace period.
///
/// In the bring-up shim there is no grace period: we simply leak the value so
/// that any reference handed out to a concurrent reader remains valid. See the
/// module-level note about the simplification this entails.
#[inline]
pub fn rcu_drop<T: Send + 'static>(value: T) {
    core::mem::forget(value);
}

/// Run any callbacks queued for the current grace period.
///
/// No-op in the bring-up shim: no callbacks are ever queued.
#[inline]
pub fn rcu_run_callbacks() {}

/// Wait until all currently in-flight read operations have completed.
///
/// No-op in the bring-up shim: read sections never block reclamation.
#[inline]
pub fn rcu_synchronize() {}
