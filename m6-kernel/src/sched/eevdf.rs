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

use super::run_queue::{with_tcb, with_tcb_mut};
use super::{PerCpuSched, VCLOCK_EPSILON, VT_FIXED_SHIFT};
use crate::cap::object_table;
use crate::cap::tcb_storage::TcbFull;
use crate::task::{DEFAULT_TIME_SLICE_MS, priority_to_weight};

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

/// Convert a counter delta into microseconds using the timer frequency.
#[inline]
fn ticks_to_us(delta_ticks: u64) -> u64 {
    let freq = timer::frequency();
    if freq == 0 {
        return 0;
    }
    ((delta_ticks as u128 * 1_000_000) / freq as u128) as u64
}

/// Check (and lazily replenish) the CPU budget of a SchedContext (MCS).
///
/// Returns true if the thread bound to `sched_ctx` is allowed to run. A
/// NULL/invalid context means "no budget limit" — this covers the idle thread,
/// kernel-internal threads, and any task not placed under a budget, so existing
/// behaviour is preserved and budgets are opt-in per thread.
///
/// When the context's period has elapsed since the last replenishment, the
/// budget is refilled before the check. This bounds a bound thread's CPU share
/// to `budget/period`, providing the §1 DoS-isolation guarantee.
///
/// IMPORTANT: this acquires the object-table lock to reach the SchedContext, so
/// it MUST be called OUTSIDE any `with_tcb`/`with_object` closure (the lock is
/// non-reentrant and would otherwise deadlock).
pub fn has_budget_for(sched_ctx: ObjectRef) -> bool {
    if !sched_ctx.is_valid() {
        return true;
    }
    let now = timer::read_counter();
    object_table::with_sched_context_mut(sched_ctx, |ctx| {
        if ctx.period > 0 {
            if ctx.period_start == 0 {
                // First evaluation since bind/configure: start the period now.
                ctx.remaining = ctx.budget;
                ctx.period_start = now;
            } else if ticks_to_us(now.saturating_sub(ctx.period_start)) >= ctx.period {
                ctx.replenish(now);
            }
        }
        ctx.has_budget()
    })
    // If the context object is gone (freed/reused), don't wedge the thread.
    .unwrap_or(true)
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
    // Advance virtual clock before accounting
    advance_vclock(sched);

    let (weight, is_idle) = with_tcb(tcb_ref, |tcb| {
        (
            priority_to_weight(tcb.tcb.priority as i8),
            tcb.tcb.priority == 0 && tcb_ref == sched.idle_thread,
        )
    })
    .unwrap_or((1, false));

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
        (
            priority_to_weight(tcb.tcb.priority as i8),
            tcb_ref == sched.idle_thread,
        )
    })
    .unwrap_or((1, false));

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
        // Read schedulability and the bound SchedContext under the TCB lock,
        // then release it before checking the budget (has_budget_for locks the
        // SchedContext object, so it must not run nested inside with_tcb).
        let (runnable_eligible, sched_ctx, next) = with_tcb(current, |tcb| {
            (
                is_runnable(tcb) && is_eligible(tcb, vclock),
                tcb.tcb.sched_context,
                tcb.sched_next,
            )
        })
        .unwrap_or((false, ObjectRef::NULL, ObjectRef::NULL));

        if runnable_eligible && has_budget_for(sched_ctx) {
            return Some(current);
        }

        current = next;
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

        // Capture the bound SchedContext and consumed microseconds so the MCS
        // budget can be charged after the TCB lock is released.
        let (prev_ctx, prev_charged_us) = with_tcb_mut(prev, |tcb| {
            // Record last run time
            tcb.last_run_ticks = now_ticks;

            // Compute virtual time consumed
            let mut charged_us = 0u64;
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

                    charged_us = ((delta_ticks as u128 * 1_000_000) / freq as u128) as u64;
                }
            }
            tcb.exec_start_ticks = 0;

            (tcb.tcb.sched_context, charged_us)
        })
        .unwrap_or((ObjectRef::NULL, 0));

        if prev_charged_us > 0 {
            consume_budget(prev_ctx, prev_charged_us);
        }
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
    let weight = with_tcb(tcb_ref, |tcb| priority_to_weight(tcb.tcb.priority as i8)).unwrap_or(1);
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
    })
    .unwrap_or(0);

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

    // Update virtual runtime and report (a) the bound SchedContext and (b) the
    // microseconds consumed this interval, so the budget can be charged AFTER
    // the TCB lock is released (consume_budget locks the SchedContext object).
    let (sched_ctx, charged_us) = with_tcb_mut(tcb_ref, |tcb| {
        let mut charged_us = 0u64;
        if tcb.exec_start_ticks > 0 {
            let freq = timer::frequency();
            if freq > 0 {
                let delta_ticks = now_ticks.saturating_sub(tcb.exec_start_ticks);
                let delta_ns = (delta_ticks as u128 * 1_000_000_000) / freq as u128;
                let weight = priority_to_weight(tcb.tcb.priority as i8) as u128;
                let dv = (delta_ns << VT_FIXED_SHIFT) / weight;

                tcb.v_runtime = tcb.v_runtime.saturating_add(dv);
                charged_us = ((delta_ticks as u128 * 1_000_000) / freq as u128) as u64;

                // Reset exec_start for next interval
                tcb.exec_start_ticks = now_ticks;
            }
        }
        (tcb.tcb.sched_context, charged_us)
    })
    .unwrap_or((ObjectRef::NULL, 0));

    // Charge the MCS budget outside the TCB lock.
    if charged_us > 0 {
        consume_budget(sched_ctx, charged_us);
    }

    // Also advance the virtual clock
    advance_vclock(sched);
}

/// Consume `microseconds` of CPU time from a SchedContext's budget (MCS).
///
/// No-op for a NULL/invalid context. MUST be called OUTSIDE any
/// `with_tcb`/`with_object` closure (it locks the SchedContext object).
pub fn consume_budget(sched_ctx: ObjectRef, microseconds: u64) {
    if !sched_ctx.is_valid() {
        return;
    }
    object_table::with_sched_context_mut(sched_ctx, |ctx| {
        ctx.consume(microseconds);
    });
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
        _ => {
            // Idle task: any runnable task in the queue should preempt it
            return find_next_runnable(sched).is_some();
        }
    };

    // MCS: if the current thread has exhausted its CPU budget, preempt it so a
    // different (or idle) thread can run until its budget replenishes.
    let cur_ctx = with_tcb(current, |tcb| tcb.tcb.sched_context).unwrap_or(ObjectRef::NULL);
    if !has_budget_for(cur_ctx) {
        return true;
    }

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
