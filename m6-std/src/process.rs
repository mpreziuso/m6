//! Process management
//!
//! Provides functions for process termination and control.

use m6_syscall::invoke::{sched_yield, tcb_exit};

/// Exit code type.
pub type ExitCode = i32;

/// Exit code indicating success.
pub const EXIT_SUCCESS: ExitCode = 0;

/// Exit code indicating failure.
pub const EXIT_FAILURE: ExitCode = 1;

/// Terminate the current process with an exit code.
///
/// This function never returns. The process is removed from the scheduler
/// and its exit code is stored in the TCB. If the process has a bound
/// notification, it will be signalled.
///
/// # Arguments
///
/// * `code` - Exit code (0 = success, non-zero = failure by convention)
///
/// # Example
///
/// ```ignore
/// use m6_std::process;
///
/// fn main() -> i32 {
///     // Do some work...
///     if error_occurred {
///         process::exit(1);
///     }
///     0
/// }
/// ```
pub fn exit(code: ExitCode) -> ! {
    tcb_exit(code)
}

/// Abort the process abnormally.
///
/// This triggers a debug breakpoint exception which will be delivered
/// to the fault handler (if configured) or terminate the thread.
///
/// This function never returns.
pub fn abort() -> ! {
    // Trigger a BRK instruction with a distinctive immediate value
    // SAFETY: This is intentionally triggering an exception
    unsafe {
        core::arch::asm!("brk #0xDEAD", options(noreturn));
    }
}

/// Yield execution to the scheduler.
///
/// Voluntarily gives up the current time slice, allowing other tasks to run.
/// The calling task remains runnable and will be scheduled again.
pub fn yield_now() {
    sched_yield();
}
