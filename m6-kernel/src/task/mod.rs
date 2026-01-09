//! Task management for the kernel
//!
//! This module implements an async-first execution model where each task
//! holds its own async futures (`kernel_work`, `signal_work`).

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};

use m6_arch::exceptions::ExceptionContext;

pub mod waker;

// -- Task ID

/// Unique task identifier.
///
/// Task IDs are monotonically increasing and never reused within a boot cycle.
/// ID 0 is reserved for the idle task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(u64);

impl TaskId {
    /// Create a new unique task ID.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Create a task ID for the idle task (ID 0).
    #[inline]
    pub const fn idle() -> Self {
        TaskId(0)
    }

    /// Get the raw value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Check if this is the idle task ID.
    #[inline]
    pub const fn is_idle(self) -> bool {
        self.0 == 0
    }

    /// Convert to a pointer (for waker data).
    #[inline]
    pub fn to_ptr(self) -> *const () {
        self.0 as *const ()
    }

    /// Convert from a pointer (for waker data).
    #[inline]
    pub fn from_ptr(ptr: *const ()) -> Self {
        TaskId(ptr as u64)
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

// -- Task State

/// Task state machine for async dispatch.
///
/// The `Woken` state is critical for handling the race condition between
/// a future returning `Poll::Pending` and a waker being called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is currently executing on a CPU.
    Running,
    /// Task is ready to run (in run queue).
    Runnable,
    /// Task was woken between Poll::Pending and state change to Sleeping.
    /// This prevents lost wakeups.
    Woken,
    /// Task is blocked waiting for an event.
    Sleeping,
    /// Task has finished execution.
    Finished,
}

impl TaskState {
    /// Check if the task has finished.
    #[inline]
    pub const fn is_finished(self) -> bool {
        matches!(self, Self::Finished)
    }

    /// Check if the task is schedulable.
    #[inline]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Running | Self::Runnable | Self::Woken)
    }
}

// -- Task Context (holds futures)

/// Type alias for kernel work future.
pub type KernelWork = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Type alias for signal work future (returns new user context on success).
pub type SignalWork = Pin<Box<dyn Future<Output = Result<ExceptionContext, ()>> + Send>>;

/// User context type (exception frame).
pub type UserCtx = ExceptionContext;

/// Context for a task, including pending async work.
///
/// This structure holds the user-mode register state and any pending
/// async operations that need to complete before returning to userspace.
pub struct TaskContext {
    /// Signal delivery work (async signal handler).
    signal_work: Option<SignalWork>,
    /// Kernel work (async syscall, etc.).
    kernel_work: Option<KernelWork>,
    /// Saved user-mode context (registers).
    user: UserCtx,
}

impl TaskContext {
    /// Create a new task context from user context.
    pub fn from_user_ctx(user_ctx: UserCtx) -> Self {
        Self {
            signal_work: None,
            kernel_work: None,
            user: user_ctx,
        }
    }

    /// Create a new empty task context.
    pub fn new() -> Self {
        Self {
            signal_work: None,
            kernel_work: None,
            // SAFETY: ExceptionContext is repr(C) with only integer fields.
            user: unsafe { core::mem::zeroed() },
        }
    }

    /// Get reference to user context.
    #[inline]
    pub fn user(&self) -> &UserCtx {
        &self.user
    }

    /// Get mutable reference to user context.
    #[inline]
    pub fn user_mut(&mut self) -> &mut UserCtx {
        &mut self.user
    }

    /// Save user context from exception frame.
    pub fn save_user_ctx(&mut self, ctx: &UserCtx) {
        self.user = ctx.clone();
    }

    /// Restore user context to exception frame.
    pub fn restore_user_ctx(&self, ctx: &mut UserCtx) {
        *ctx = self.user.clone();
    }

    /// Put signal work (async signal delivery).
    pub fn put_signal_work(&mut self, work: SignalWork) {
        debug_assert!(self.signal_work.is_none(), "double-scheduled signal work");
        self.signal_work = Some(work);
    }

    /// Take signal work.
    pub fn take_signal_work(&mut self) -> Option<SignalWork> {
        self.signal_work.take()
    }

    /// Put kernel work (async syscall, etc.).
    pub fn put_kernel_work(&mut self, work: KernelWork) {
        debug_assert!(self.kernel_work.is_none(), "double-scheduled kernel work");
        self.kernel_work = Some(work);
    }

    /// Take kernel work.
    pub fn take_kernel_work(&mut self) -> Option<KernelWork> {
        self.kernel_work.take()
    }

    /// Check if there is any pending work.
    #[inline]
    pub fn has_pending_work(&self) -> bool {
        self.signal_work.is_some() || self.kernel_work.is_some()
    }
}

impl Default for TaskContext {
    fn default() -> Self {
        Self::new()
    }
}

// -- Scheduler Weight Constants

/// Scheduler base weight to ensure tasks always have a strictly positive
/// scheduling weight. Added to priority to get effective weight.
pub const SCHED_WEIGHT_BASE: i32 = 1024;

/// Default time-slice in milliseconds assigned to runnable tasks.
pub const DEFAULT_TIME_SLICE_MS: u64 = 4;

/// Calculate scheduling weight from priority.
///
/// weight = priority + SCHED_WEIGHT_BASE (minimum 1)
#[inline]
pub fn priority_to_weight(priority: i8) -> u32 {
    let w = priority as i32 + SCHED_WEIGHT_BASE;
    if w <= 0 { 1 } else { w as u32 }
}
