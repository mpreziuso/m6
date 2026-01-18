//! TCB kernel storage
//!
//! The full TCB includes both the capability metadata from `m6-cap` and
//! the register save area for context switching.

extern crate alloc;

use core::alloc::Layout;
use core::ptr::NonNull;

use m6_arch::exceptions::ExceptionContext;
use m6_cap::objects::TcbObject;
use m6_cap::{CapError, CapResult, ObjectRef};

use crate::task::TaskContext;

/// Full TCB including register context.
///
/// This structure is heap-allocated and contains everything needed
/// for thread management:
/// - Basic TCB metadata (from `m6-cap`)
/// - Register save area (from `m6-arch`)
/// - EEVDF scheduling fields
/// - Scheduler queue links
/// - IPC queue links
#[repr(C, align(64))]
pub struct TcbFull {
    /// TCB metadata from m6-cap.
    pub tcb: TcbObject,
    /// Saved register context (288 bytes).
    pub context: ExceptionContext,
    /// Kernel stack pointer for this thread.
    pub kernel_sp: u64,

    // EEVDF scheduling fields (65.63 fixed-point for virtual time)
    /// Virtual runtime consumed by this thread.
    pub v_runtime: u128,
    /// Virtual time when this thread becomes eligible to run.
    pub v_eligible: u128,
    /// Virtual deadline for scheduling decisions.
    pub v_deadline: u128,
    /// Tick count when execution started (for time accounting).
    pub exec_start_ticks: u64,
    /// Tick count when this thread last ran (tie-breaker).
    pub last_run_ticks: u64,

    /// Next TCB in scheduler run queue.
    pub sched_next: ObjectRef,
    /// Previous TCB in scheduler run queue.
    pub sched_prev: ObjectRef,
    /// Next TCB in IPC wait queue.
    pub ipc_next: ObjectRef,
    /// Previous TCB in IPC wait queue.
    pub ipc_prev: ObjectRef,

    /// Pending IPC message registers (5 words) for blocked sender.
    pub ipc_message: [u64; 5],
    /// Badge to deliver with pending message.
    pub ipc_badge: u64,
    /// Object we're blocked on (endpoint/notification).
    pub ipc_blocked_on: ObjectRef,

    /// Async work context (signal_work, kernel_work futures).
    pub task_ctx: TaskContext,
}

impl TcbFull {
    /// Create a new default TCB.
    ///
    /// Note: ExceptionContext is zeroed, which is a valid initial state.
    pub fn new() -> Self {
        Self {
            tcb: TcbObject::new(),
            // SAFETY: ExceptionContext is repr(C) with only integer fields,
            // so zeroed memory is a valid representation.
            context: unsafe { core::mem::zeroed() },
            kernel_sp: 0,
            // EEVDF fields - all start at zero
            v_runtime: 0,
            v_eligible: 0,
            v_deadline: 0,
            exec_start_ticks: 0,
            last_run_ticks: 0,
            // Queue links
            sched_next: ObjectRef::NULL,
            sched_prev: ObjectRef::NULL,
            ipc_next: ObjectRef::NULL,
            ipc_prev: ObjectRef::NULL,
            // IPC state
            ipc_message: [0; 5],
            ipc_badge: 0,
            ipc_blocked_on: ObjectRef::NULL,
            // Async work context
            task_ctx: TaskContext::new(),
        }
    }

    /// Allocate a new TCB on the heap.
    pub fn alloc() -> Option<NonNull<Self>> {
        let layout = Layout::new::<Self>();

        // SAFETY: Layout is valid and non-zero size.
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            log::error!("TcbFull::alloc: allocation failed (out of memory)");
            return None;
        }

        let tcb = ptr as *mut TcbFull;

        // Initialise TCB metadata (context is already zeroed from alloc_zeroed)
        // SAFETY: We just allocated this memory with alloc_zeroed.
        unsafe {
            (*tcb).tcb = TcbObject::new();
            // context is already zeroed - valid initial state
            (*tcb).kernel_sp = 0;
            // EEVDF fields are already zeroed from alloc_zeroed
            (*tcb).v_runtime = 0;
            (*tcb).v_eligible = 0;
            (*tcb).v_deadline = 0;
            (*tcb).exec_start_ticks = 0;
            (*tcb).last_run_ticks = 0;
            // Queue links
            (*tcb).sched_next = ObjectRef::NULL;
            (*tcb).sched_prev = ObjectRef::NULL;
            (*tcb).ipc_next = ObjectRef::NULL;
            (*tcb).ipc_prev = ObjectRef::NULL;
            // IPC state (already zeroed from alloc_zeroed)
            (*tcb).ipc_message = [0; 5];
            (*tcb).ipc_badge = 0;
            (*tcb).ipc_blocked_on = ObjectRef::NULL;
            // Async work context
            (*tcb).task_ctx = TaskContext::new();
        }

        NonNull::new(tcb)
    }

    /// Deallocate a TCB.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated by [`alloc`](Self::alloc) and
    /// must not be used after this call.
    pub unsafe fn dealloc(ptr: *mut Self) {
        if ptr.is_null() {
            return;
        }

        let layout = Layout::new::<Self>();
        // SAFETY: Caller guarantees ptr was allocated by alloc().
        unsafe { alloc::alloc::dealloc(ptr as *mut u8, layout) };
    }

    /// Check if this TCB is in an IPC queue.
    #[inline]
    pub fn is_in_ipc_queue(&self) -> bool {
        self.ipc_next.is_valid() || self.ipc_prev.is_valid()
    }

    /// Check if this TCB is in the scheduler queue.
    #[inline]
    pub fn is_in_sched_queue(&self) -> bool {
        self.sched_next.is_valid() || self.sched_prev.is_valid()
    }

    /// Remove this TCB from IPC queue links.
    pub fn clear_ipc_links(&mut self) {
        self.ipc_next = ObjectRef::NULL;
        self.ipc_prev = ObjectRef::NULL;
    }

    /// Clear all IPC state (message, badge, blocked_on, links).
    pub fn clear_ipc_state(&mut self) {
        self.ipc_message = [0; 5];
        self.ipc_badge = 0;
        self.ipc_blocked_on = ObjectRef::NULL;
        self.clear_ipc_links();
    }

    /// Remove this TCB from scheduler queue links.
    pub fn clear_sched_links(&mut self) {
        self.sched_next = ObjectRef::NULL;
        self.sched_prev = ObjectRef::NULL;
    }
}

impl Default for TcbFull {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a new TCB and return a raw pointer.
///
/// This is a convenience function for the object table.
pub fn create_tcb() -> CapResult<*mut TcbFull> {
    TcbFull::alloc()
        .map(|ptr| ptr.as_ptr())
        .ok_or(CapError::OutOfMemory)
}

/// Destroy a TCB and free its memory.
///
/// # Safety
///
/// The pointer must have been allocated by [`create_tcb`] and must not
/// be used after this call.
pub unsafe fn destroy_tcb(ptr: *mut TcbFull) {
    // SAFETY: Caller guarantees validity.
    unsafe { TcbFull::dealloc(ptr) }
}
