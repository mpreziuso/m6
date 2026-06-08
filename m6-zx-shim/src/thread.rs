//! Thread handle (wraps M6 TCB)

use crate::flags::RaiseExceptionOptions;
use crate::object::{AsHandleRef, HandleBased, HandleRef, NullableHandle};
use crate::sys::zx_handle_t;
use crate::time::MonotonicDuration;
use crate::Status;

/// Statistics about a thread, mirroring `zx_info_thread_stats_t`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ThreadStats {
    /// Total accumulated running time of the thread.
    pub total_runtime: MonotonicDuration,
    /// The CPU this thread was last scheduled on, or running on.
    pub last_scheduled_cpu: u32,
}

/// Runtime statistics for a task (thread/process/job), mirroring
/// `zx_info_task_runtime_t`. Times are in nanoseconds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TaskRuntimeInfo {
    /// Total accumulated running time.
    pub cpu_time: i64,
    /// Total accumulated time spent ready to run but not running.
    pub queue_time: i64,
    /// Total accumulated time spent handling page faults.
    pub page_fault_time: i64,
    /// Total accumulated time spent contending on locks.
    pub lock_contention_time: i64,
}

/// A thread handle.
pub struct Thread {
    /// Opaque thread handle.
    handle: NullableHandle,
    /// TCB capability pointer (M6 native path; 0 if unused).
    pub(crate) tcb_cptr: u64,
}

impl Thread {
    /// Create a thread handle from an M6 TCB capability pointer.
    pub fn new(tcb_cptr: u64) -> Self {
        Self {
            handle: NullableHandle::invalid(),
            tcb_cptr,
        }
    }

    /// Get the TCB capability pointer.
    pub fn tcb_cptr(&self) -> u64 {
        self.tcb_cptr
    }

    /// Returns accumulated runtime statistics for this thread.
    ///
    /// Stub: M6 does not yet expose per-thread runtime accounting, so zeroes are
    /// reported. Wire to the scheduler's accounting when available.
    pub fn get_runtime_info(&self) -> Result<TaskRuntimeInfo, Status> {
        Ok(TaskRuntimeInfo::default())
    }

    /// Returns scheduling statistics for this thread.
    ///
    /// Mirrors `zx::Thread::stats`. Stub: M6 does not yet expose per-thread
    /// scheduler accounting, so zeroes (and CPU 0) are reported.
    pub fn stats(&self) -> Result<ThreadStats, Status> {
        Ok(ThreadStats::default())
    }

    /// Suspend the thread. Stub.
    pub fn suspend(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Resume the thread. Stub.
    pub fn resume(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Kill the thread. Stub.
    pub fn kill(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Raises a user-generated exception on the current thread. Stub.
    pub fn raise_user_exception(
        _options: RaiseExceptionOptions,
        _code: u32,
        _data: u32,
    ) -> Result<(), Status> {
        Ok(())
    }
}

impl From<NullableHandle> for Thread {
    fn from(handle: NullableHandle) -> Self {
        Self {
            handle,
            tcb_cptr: 0,
        }
    }
}

impl AsHandleRef for Thread {
    fn as_handle_ref(&self) -> HandleRef<'_> {
        self.handle.as_handle_ref()
    }
    fn raw_handle(&self) -> zx_handle_t {
        self.handle.raw()
    }
}
impl HandleBased for Thread {}
