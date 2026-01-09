//! Task Dispatch Loop
//!
//! This is the core of the async-first execution model.
//! The dispatch loop polls futures during return-to-userspace.
//!
//! # Flow
//!
//! 1. `schedule()` picks a task via EEVDF
//! 2. Poll any pending `signal_work` or `kernel_work`
//! 3. If `Poll::Pending`:
//!    - If state is `Running` → set to `Sleeping`
//!    - If state is `Woken` → set to `Running` (waker fired during poll)
//!    - Go to step 1
//! 4. If `Poll::Ready` → handle result, may loop or return
//! 5. No pending work → restore user context and return

use core::task::{Context, Poll};

use m6_cap::ObjectRef;

use super::{current_task, schedule, remove_task};
use super::run_queue::with_tcb_mut;
use crate::task::{TaskId, UserCtx, KernelWork, SignalWork};
use crate::task::waker::create_waker;

/// State machine for the dispatch loop.
enum State {
    /// Pick a new task to run.
    PickNewTask,
    /// Process any pending async work.
    ProcessWork,
    /// Return to userspace.
    ReturnToUserspace,
}

/// Dispatch loop: the heart of the async-first kernel.
///
/// This function is the primary gateway for transitioning from kernel context
/// (after syscall, interrupt, or fault) back to userspace. It ensures a task
/// is in a valid state to resume execution, handling any pending async work.
///
/// # Arguments
///
/// * `ctx` - Mutable pointer to the exception context on stack. This will be
///   populated with the user register state for the task being returned to.
///
/// # Guarantees
///
/// - This function always returns (does not diverge unless panic)
/// - Upon return, `ctx` contains valid userspace register state
pub fn dispatch_task(ctx: &mut UserCtx) {
    let mut state = State::PickNewTask;

    loop {
        match state {
            State::PickNewTask => {
                // Pick a new task (may context switch)
                schedule();
                state = State::ProcessWork;
            }

            State::ProcessWork => {
                let tcb_ref = match current_task() {
                    Some(r) => r,
                    None => {
                        state = State::PickNewTask;
                        continue;
                    }
                };

                // Check if this is the idle task
                let is_idle = is_idle_task(tcb_ref);
                if is_idle {
                    // Idle task doesn't have async work
                    state = State::ReturnToUserspace;
                    continue;
                }

                // --- Poll signal work first (if any) ---
                if let Some(result) = poll_signal_work(tcb_ref, ctx) {
                    match result {
                        PollResult::Ready(new_ctx) => {
                            // Signal handling complete, use returned context
                            *ctx = new_ctx;
                            return;
                        }
                        PollResult::Error => {
                            // Signal delivery failed - terminate task
                            log::error!("Signal delivery failed for task {:?}", tcb_ref);
                            mark_finished(tcb_ref);
                            remove_task(tcb_ref);
                            state = State::PickNewTask;
                            continue;
                        }
                        PollResult::Pending => {
                            // Put work back and handle state transition
                            handle_pending(tcb_ref);
                            state = State::PickNewTask;
                            continue;
                        }
                    }
                }

                // --- Poll kernel work (if any) ---
                if let Some(result) = poll_kernel_work(tcb_ref) {
                    match result {
                        KernelPollResult::Ready => {
                            // Kernel work finished
                            if is_finished(tcb_ref) {
                                // Task exited during kernel work
                                remove_task(tcb_ref);
                                state = State::PickNewTask;
                                continue;
                            }
                            // Check for more work (e.g., signal raised)
                            state = State::ProcessWork;
                            continue;
                        }
                        KernelPollResult::Pending => {
                            // Put work back and handle state transition
                            handle_pending(tcb_ref);
                            state = State::PickNewTask;
                            continue;
                        }
                    }
                }

                // No pending work - ready to return to userspace
                state = State::ReturnToUserspace;
            }

            State::ReturnToUserspace => {
                // Restore user context and return
                let tcb_ref = match current_task() {
                    Some(r) => r,
                    None => return,
                };

                restore_context(tcb_ref, ctx);
                return;
            }
        }
    }
}

/// Result of polling signal work.
#[allow(dead_code)]
enum PollResult {
    Ready(UserCtx),
    Error,
    Pending,
}

/// Result of polling kernel work.
#[allow(dead_code)]
enum KernelPollResult {
    Ready,
    Pending,
}

/// Poll signal work for a task.
fn poll_signal_work(tcb_ref: ObjectRef, _ctx: &mut UserCtx) -> Option<PollResult> {
    // Take signal work from TCB
    let mut signal_work: Option<SignalWork> = None;
    with_tcb_mut(tcb_ref, |tcb| {
        signal_work = tcb.task_ctx.take_signal_work();
    });

    let mut work = signal_work?;

    // Create waker for this task
    let task_id = TaskId::from_ptr(tcb_ref.index() as *const ());
    let waker = create_waker(task_id);
    let mut poll_ctx = Context::from_waker(&waker);

    // Poll the future
    match work.as_mut().poll(&mut poll_ctx) {
        Poll::Ready(Ok(new_ctx)) => Some(PollResult::Ready(new_ctx)),
        Poll::Ready(Err(())) => Some(PollResult::Error),
        Poll::Pending => {
            // Put work back
            with_tcb_mut(tcb_ref, |tcb| {
                tcb.task_ctx.put_signal_work(work);
            });
            Some(PollResult::Pending)
        }
    }
}

/// Poll kernel work for a task.
fn poll_kernel_work(tcb_ref: ObjectRef) -> Option<KernelPollResult> {
    // Take kernel work from TCB
    let mut kernel_work: Option<KernelWork> = None;
    with_tcb_mut(tcb_ref, |tcb| {
        kernel_work = tcb.task_ctx.take_kernel_work();
    });

    let mut work = kernel_work?;

    // Create waker for this task
    let task_id = TaskId::from_ptr(tcb_ref.index() as *const ());
    let waker = create_waker(task_id);
    let mut poll_ctx = Context::from_waker(&waker);

    // Poll the future
    match work.as_mut().poll(&mut poll_ctx) {
        Poll::Ready(()) => Some(KernelPollResult::Ready),
        Poll::Pending => {
            // Put work back
            with_tcb_mut(tcb_ref, |tcb| {
                tcb.task_ctx.put_kernel_work(work);
            });
            Some(KernelPollResult::Pending)
        }
    }
}

/// Handle a future returning Poll::Pending.
///
/// This is where the `Woken` state is critical:
/// - If state is `Running` → set to `Sleeping` (normal case)
/// - If state is `Woken` → set to `Running` (waker fired during poll)
fn handle_pending(tcb_ref: ObjectRef) {
    use m6_cap::objects::ThreadState;

    with_tcb_mut(tcb_ref, |tcb| {
        match tcb.tcb.state {
            ThreadState::Running => {
                // Normal path: task goes to sleep (blocked on async work)
                tcb.tcb.state = ThreadState::BlockedOnNotification; // Using this for async waiting
            }
            // Other states - task was woken while we were processing
            // Keep it runnable
            _ => {}
        }
    });
}

/// Mark a task as finished.
fn mark_finished(tcb_ref: ObjectRef) {
    use m6_cap::objects::ThreadState;

    with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::Inactive;
    });
}

/// Check if a task is finished.
fn is_finished(tcb_ref: ObjectRef) -> bool {
    use m6_cap::objects::ThreadState;

    super::run_queue::with_tcb(tcb_ref, |tcb| {
        tcb.tcb.state == ThreadState::Inactive
    }).unwrap_or(false)
}

/// Check if a task is the idle task.
fn is_idle_task(tcb_ref: ObjectRef) -> bool {
    // Check if this is the idle task by comparing with the current CPU's idle task
    // For now, we check if the TCB has the idle priority (lowest)
    super::run_queue::with_tcb(tcb_ref, |tcb| {
        tcb.tcb.priority == 0
    }).unwrap_or(false)
}

/// Restore user context from TCB to exception frame.
fn restore_context(tcb_ref: ObjectRef, ctx: &mut UserCtx) {
    super::run_queue::with_tcb(tcb_ref, |tcb| {
        *ctx = tcb.context.clone();
    });
}

/// Save user context from exception frame to TCB.
pub fn save_context(tcb_ref: ObjectRef, ctx: &UserCtx) {
    with_tcb_mut(tcb_ref, |tcb| {
        tcb.context = ctx.clone();
    });
}
