//! Task-based Waker implementation
//!
//! This waker modifies task state directly:
//! - Sleeping → Runnable (normal wakeup)
//! - Running → Woken (handles race between Poll::Pending and waker)

use core::task::{RawWaker, RawWakerVTable, Waker};

use m6_cap::ObjectRef;

use super::TaskId;

/// RawWaker vtable for task-based wakers.
static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// Clone the waker (just copy the task ID pointer).
unsafe fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

/// Wake the task (consumes the waker).
///
/// This is the core of the waker pattern:
/// - If task is Sleeping → mark as Runnable
/// - If task is Running → mark as Woken (prevents lost wakeup)
unsafe fn waker_wake(data: *const ()) {
    // SAFETY: data is a valid TaskId encoded as pointer
    unsafe { waker_wake_by_ref(data) };
}

/// Wake the task by reference.
///
/// # State Transitions
///
/// - `Sleeping` → `Runnable`: Normal case, task was blocked and is now ready
/// - `Running` → `Woken`: Race condition guard. If waker fires while task is
///   still being polled (between returning Poll::Pending and setting state to
///   Sleeping), we mark it as Woken so the scheduler knows not to actually
///   put it to sleep.
///
/// # Safety
///
/// This function requires the TaskId to be looked up in the scheduler's
/// data structures. The actual state modification happens through the
/// scheduler module.
unsafe fn waker_wake_by_ref(data: *const ()) {
    let task_id = TaskId::from_ptr(data);
    // Delegate to scheduler to perform the actual wakeup
    crate::sched::wake_task_by_id(task_id);
}

/// Drop the waker (no-op, we don't allocate).
unsafe fn waker_drop(_data: *const ()) {
    // Nothing to do - TaskId is just a u64, no allocation
}

/// Create a Waker for the given task ID.
///
/// The waker holds the task ID encoded as a pointer. When woken, it looks up
/// the task and modifies its state.
pub fn create_waker(task_id: TaskId) -> Waker {
    let raw_waker = RawWaker::new(task_id.to_ptr(), &VTABLE);
    // SAFETY: We've correctly implemented the vtable functions
    unsafe { Waker::from_raw(raw_waker) }
}

/// Create a Waker for a task identified by ObjectRef.
///
/// This is a convenience function when working with the object table.
pub fn create_waker_for_tcb(tcb_ref: ObjectRef) -> Waker {
    // Use the ObjectRef index as task ID
    let task_id = TaskId(tcb_ref.index() as u64);
    create_waker(task_id)
}
