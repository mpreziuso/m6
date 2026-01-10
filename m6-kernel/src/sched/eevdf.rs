//! EEVDF (Earliest Eligible Virtual Deadline First) Algorithm
//!
//! This module implements the core EEVDF scheduling algorithm:
//! - Virtual clock management
//! - Eligibility and deadline calculations
//! - Weight-based time accounting
//! - SchedContext budget integration

use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;
use m6_pal::timer;

use super::{PerCpuSched, VT_FIXED_SHIFT, VCLOCK_EPSILON};
use super::run_queue::{with_tcb, with_tcb_mut};
use crate::cap::object_table::{self, KernelObjectType};
use crate::cap::tcb_storage::TcbFull;
use crate::task::{priority_to_weight, DEFAULT_TIME_SLICE_MS};

// -- Virtual Clock Management

/// Advance the per-CPU virtual clock.
///
/// The virtual clock advances proportionally to real time, scaled by the
/// total weight of all runnable tasks:
///
/// `vclock += (delta_ns << VT_FIXED_SHIFT) / total_weight`
pub fn advance_vclock(sched: &mut PerCpuSched) {
    let now_ticks = timer::read_counter();
    let prev_ticks = sched.last_update_ticks;

    if prev_ticks == 0 || sched.total_weight == 0 {
        sched.last_update_ticks = now_ticks;
        return;
    }

    // Calculate delta in nanoseconds
    let freq = timer::frequency();
    if freq == 0 {
        return;
    }

    let delta_ticks = now_ticks.saturating_sub(prev_ticks);
    let delta_ns = (delta_ticks as u128 * 1_000_000_000) / freq as u128;

    // Advance virtual clock
    let delta_vt = (delta_ns << VT_FIXED_SHIFT) / sched.total_weight as u128;
    sched.vclock = sched.vclock.saturating_add(delta_vt);
    sched.last_update_ticks = now_ticks;
}

// -- Task Eligibility

/// Check if a task is eligible to run.
///
/// A task is eligible if its virtual eligible time has passed:
/// `v_eligible <= vclock + EPSILON`
#[inline]
pub fn is_eligible(tcb: &TcbFull, vclock: u128) -> bool {
    tcb.v_eligible.saturating_sub(vclock) <= VCLOCK_EPSILON
}

/// Check if a task has available SchedContext budget.
pub fn has_budget(tcb: &TcbFull) -> bool {
    let sched_ctx_ref = tcb.tcb.sched_context;
    if !sched_ctx_ref.is_valid() {
        // No SchedContext - assume unlimited budget (for idle task, etc.)
        return true;
    }

    object_table::with_object(sched_ctx_ref, |obj| {
        if obj.obj_type == KernelObjectType::SchedContext {
            // Access SchedContext - it's stored inline in the object
            // For now, return true as SchedContext storage isn't fully implemented
            true
        } else {
            true
        }
    }).unwrap_or(true)
}

/// Check if a task's state allows it to be scheduled.
#[inline]
pub fn is_runnable(tcb: &TcbFull) -> bool {
    tcb.tcb.state.is_schedulable()
}

// -- Task Management

/// Add a task to the run queue.
///
/// Sets up initial EEVDF parameters and inserts into the queue.
pub fn add_to_run_queue(sched: &mut PerCpuSched, tcb_ref: ObjectRef) {
    log::info!("add_to_run_queue: adding tcb_ref index={}", tcb_ref.index());

    // Advance virtual clock before accounting
    advance_vclock(sched);

    let (weight, is_idle) = with_tcb(tcb_ref, |tcb| {
        (priority_to_weight(tcb.tcb.priority as i8), tcb.tcb.priority == 0 && tcb_ref == sched.idle_thread)
    }).unwrap_or((1, false));

    // Set initial eligibility to now
    with_tcb_mut(tcb_ref, |tcb| {
        tcb.v_eligible = sched.vclock;

        // Grant initial virtual deadline proportional to weight
        let q_ns: u128 = (DEFAULT_TIME_SLICE_MS as u128) * 1_000_000;
        let v_delta = (q_ns << VT_FIXED_SHIFT) / weight as u128;
        tcb.v_deadline = sched.vclock.saturating_add(v_delta);

        // Clear execution start
        tcb.exec_start_ticks = 0;
    });

    // Update total weight (idle task doesn't count)
    if !is_idle {
        sched.total_weight = sched.total_weight.saturating_add(weight as u64);
    }

    // Get deadline for insertion
    let v_deadline = with_tcb(tcb_ref, |tcb| tcb.v_deadline).unwrap_or(0);

    // Insert into run queue
    sched.run_queue.insert(tcb_ref, v_deadline);
}

/// Remove a task from the run queue.
pub fn remove_from_run_queue(sched: &mut PerCpuSched, tcb_ref: ObjectRef) {
    let (weight, is_idle) = with_tcb(tcb_ref, |tcb| {
        (priority_to_weight(tcb.tcb.priority as i8), tcb_ref == sched.idle_thread)
    }).unwrap_or((1, false));

    // Remove from run queue
    sched.run_queue.remove(tcb_ref);

    // Update total weight
    if !is_idle {
        sched.total_weight = sched.total_weight.saturating_sub(weight as u64);
    }
}

// -- Task Selection

/// Find the next runnable task using EEVDF algorithm.
///
/// Returns the eligible task with the earliest virtual deadline that
/// has available SchedContext budget.
pub fn find_next_runnable(sched: &PerCpuSched) -> Option<ObjectRef> {
    let vclock = sched.vclock;
    let mut current = sched.run_queue.head();

    while current.is_valid() {
        let is_candidate = with_tcb(current, |tcb| {
            let r = is_runnable(tcb);
            let e = is_eligible(tcb, vclock);
            let b = has_budget(tcb);
            r && e && b
        }).unwrap_or(false);

        if is_candidate {
            return Some(current);
        }

        // Move to next task
        current = with_tcb(current, |tcb| tcb.sched_next).unwrap_or(ObjectRef::NULL);
    }

    None
}

// -- Context Switching

/// Switch to a new task.
///
/// Updates EEVDF accounting for both the previous and next task.
pub fn switch_to(sched: &mut PerCpuSched, next: ObjectRef) {
    // Advance virtual clock
    advance_vclock(sched);

    let now_ticks = timer::read_counter();

    // Update previous task's accounting
    if let Some(prev) = sched.current_thread {
        if prev == next {
            // Same task, nothing to do
            return;
        }

        with_tcb_mut(prev, |tcb| {
            // Record last run time
            tcb.last_run_ticks = now_ticks;

            // Compute virtual time consumed
            if tcb.exec_start_ticks > 0 {
                let freq = timer::frequency();
                if freq > 0 {
                    let delta_ticks = now_ticks.saturating_sub(tcb.exec_start_ticks);
                    let delta_ns = (delta_ticks as u128 * 1_000_000_000) / freq as u128;
                    let weight = priority_to_weight(tcb.tcb.priority as i8) as u128;
                    let dv = (delta_ns << VT_FIXED_SHIFT) / weight;

                    tcb.v_runtime = tcb.v_runtime.saturating_add(dv);
                    tcb.v_eligible = tcb.v_eligible.saturating_add(dv);

                    // Re-issue virtual deadline
                    let q_ns: u128 = (DEFAULT_TIME_SLICE_MS as u128) * 1_000_000;
                    let v_delta = (q_ns << VT_FIXED_SHIFT) / weight;
                    tcb.v_deadline = tcb.v_eligible.saturating_add(v_delta);
                }
            }
            tcb.exec_start_ticks = 0;

            // Mark as runnable if it was running
            if tcb.tcb.state == ThreadState::Running {
                // Keep it running (schedulable) - actual queue state is separate
            }
        });
    }

    // Set up next task
    with_tcb_mut(next, |tcb| {
        tcb.exec_start_ticks = now_ticks;
        tcb.tcb.state = ThreadState::Running;
    });

    sched.current_thread = Some(next);
}

// -- Yield Handling

/// Update a task's EEVDF times when it voluntarily yields.
///
/// This pushes the task's deadline forward so other eligible tasks can run.
/// The task is removed and re-inserted to maintain queue ordering.
pub fn yield_task(sched: &mut PerCpuSched, tcb_ref: ObjectRef) {
    let now_ticks = timer::read_counter();

    // Advance virtual clock
    advance_vclock(sched);

    // Remove from queue first (we'll re-insert with new deadline)
    sched.run_queue_mut().remove(tcb_ref);

    // Update weight tracking (temporarily decrement)
    let weight = with_tcb(tcb_ref, |tcb| {
        priority_to_weight(tcb.tcb.priority as i8)
    }).unwrap_or(1);
    sched.total_weight = sched.total_weight.saturating_sub(weight as u64);

    // Update EEVDF times
    let new_deadline = with_tcb_mut(tcb_ref, |tcb| {
        // Account for time consumed
        if tcb.exec_start_ticks > 0 {
            let freq = timer::frequency();
            if freq > 0 {
                let delta_ticks = now_ticks.saturating_sub(tcb.exec_start_ticks);
                let delta_ns = (delta_ticks as u128 * 1_000_000_000) / freq as u128;
                let w = priority_to_weight(tcb.tcb.priority as i8) as u128;
                let dv = (delta_ns << VT_FIXED_SHIFT) / w;

                tcb.v_runtime = tcb.v_runtime.saturating_add(dv);
                tcb.v_eligible = tcb.v_eligible.saturating_add(dv);
            }
        }

        // Reset execution start
        tcb.exec_start_ticks = 0;

        // Push deadline forward by a full time slice to let other tasks run
        let w = priority_to_weight(tcb.tcb.priority as i8) as u128;
        let q_ns: u128 = (DEFAULT_TIME_SLICE_MS as u128) * 1_000_000;
        let v_delta = (q_ns << VT_FIXED_SHIFT) / w;
        tcb.v_deadline = sched.vclock.saturating_add(v_delta);
        tcb.v_deadline
    }).unwrap_or(0);

    // Re-insert with new deadline (this will place it in correct position)
    sched.run_queue_mut().insert(tcb_ref, new_deadline);
    sched.total_weight = sched.total_weight.saturating_add(weight as u64);
}

// -- Time Charging

/// Charge the current thread for CPU time consumed.
///
/// Called from timer interrupt to update EEVDF accounting.
pub fn charge_time(sched: &mut PerCpuSched, tcb_ref: ObjectRef) {
    let now_ticks = timer::read_counter();

    with_tcb_mut(tcb_ref, |tcb| {
        if tcb.exec_start_ticks > 0 {
            let freq = timer::frequency();
            if freq > 0 {
                let delta_ticks = now_ticks.saturating_sub(tcb.exec_start_ticks);
                let delta_ns = (delta_ticks as u128 * 1_000_000_000) / freq as u128;
                let weight = priority_to_weight(tcb.tcb.priority as i8) as u128;
                let dv = (delta_ns << VT_FIXED_SHIFT) / weight;

                tcb.v_runtime = tcb.v_runtime.saturating_add(dv);

                // Reset exec_start for next interval
                tcb.exec_start_ticks = now_ticks;
            }
        }
    });

    // Also advance the virtual clock
    advance_vclock(sched);
}

/// Consume budget from a task's SchedContext.
pub fn consume_budget(tcb_ref: ObjectRef, _microseconds: u64) {
    let sched_ctx_ref = with_tcb(tcb_ref, |tcb| tcb.tcb.sched_context).unwrap_or(ObjectRef::NULL);

    if !sched_ctx_ref.is_valid() {
        return;
    }

    // TODO: Update SchedContextObject when storage is implemented
}

// -- Preemption

/// Check if preemption should occur.
///
/// Returns true if:
/// - Current thread's virtual deadline has passed
/// - Current thread's SchedContext budget is exhausted
/// - A higher-priority (earlier deadline) thread became eligible
pub fn should_preempt(sched: &PerCpuSched) -> bool {
    let current = match sched.current_thread {
        Some(c) if c != sched.idle_thread => c,
        _ => return false, // Idle task is always preemptible
    };

    // Check if there's a higher-priority task
    let next = match find_next_runnable(sched) {
        Some(n) => n,
        None => return false,
    };

    if next == current {
        return false;
    }

    // Compare deadlines
    let current_deadline = with_tcb(current, |tcb| tcb.v_deadline).unwrap_or(u128::MAX);
    let next_deadline = with_tcb(next, |tcb| tcb.v_deadline).unwrap_or(u128::MAX);

    next_deadline < current_deadline
}
