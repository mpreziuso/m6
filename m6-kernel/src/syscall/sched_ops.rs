//! SchedControl / SchedContext invocation handlers (MCS CPU budgets).
//!
//! These give the design's §1 SchedContext/SchedControl capability types — and
//! the "prevent denial-of-service through CPU exhaustion" guarantee — real
//! enforcement. The lifecycle is seL4 MCS-shaped:
//!
//! - `SchedControl.Configure(sched_context, budget_us, period_us)` — set a
//!   context's CPU-time budget and replenishment period (requires the
//!   SchedControl authority).
//! - `SchedContext.Bind(tcb)` — attach a configured context to a thread. The
//!   scheduler then charges the thread's run time against the budget and stops
//!   scheduling it once the budget is exhausted, until the period replenishes.
//! - `SchedContext.Unbind()` — detach the context, removing enforcement.
//!
//! A thread with no bound SchedContext runs without a budget limit (idle
//! thread, kernel-internal threads, and any task not yet placed under a
//! budget), so existing behaviour is preserved — budgets are opt-in per thread.
//! The scheduler-side enforcement lives in [`crate::sched::eevdf`].

use m6_cap::objects::SchedContextObject;
use m6_cap::{CapRights, ObjectRef, ObjectType};
use m6_pal::timer;

use crate::cap::object_table;
use crate::ipc;
use crate::syscall::SyscallArgs;
use crate::syscall::error::{SyscallError, SyscallResult};

/// Handle `SchedControl.Configure(sched_context, budget_us, period_us)`.
///
/// Sets the CPU-time budget and period (microseconds) of a SchedContext. The
/// SchedControl capability is the authority required to mint budgets, so this
/// is the gate that decides which contexts may be granted CPU time.
pub fn handle_sched_control_configure(args: &SyscallArgs) -> SyscallResult {
    let sched_control_cptr = args.arg0;
    let sched_context_cptr = args.arg1;
    let budget_us = args.arg2;
    let period_us = args.arg3;

    // SchedControl is a singleton control authority: require full rights.
    let ctrl_cap = ipc::lookup_cap(sched_control_cptr, ObjectType::SchedControl, CapRights::ALL)?;
    let ctx_cap = ipc::lookup_cap(sched_context_cptr, ObjectType::SchedContext, CapRights::WRITE)?;
    let ctrl_ref = ctrl_cap.obj_ref;
    let ctx_ref = ctx_cap.obj_ref;

    // Validate the requested parameters against the object's invariants
    // (budget >= MIN_BUDGET, period >= MIN_PERIOD, budget <= period).
    let requested = SchedContextObject::new(budget_us, period_us);
    if !requested.is_valid() {
        return Err(SyscallError::InvalidArg);
    }
    let new_util = requested.utilisation_ppm();

    // -- Admission control.
    //
    // The SchedControl authority bounds the aggregate CPU utilisation of every
    // context configured through it. This is what makes the "prevent denial of
    // service through CPU exhaustion / time partitioning" guarantee real across
    // multiple contexts, not just per-context. Accounting is in utilisation
    // (ppm), so budgets with different periods compose correctly.

    // What this context currently contributes, and to which control.
    let (cur_ctrl, cur_util) =
        object_table::with_sched_context(ctx_ref, |c| (c.admitting_control, c.admitted_ppm))
            .ok_or(SyscallError::InvalidCap)?;

    let already_here = cur_ctrl == ctrl_ref;
    // Utilisation this context already counts for against *this* control (0 if
    // it was unadmitted or admitted against a different control).
    let prev_util = if already_here { cur_util } else { 0 };

    // Apply the admission decision atomically under the object-table lock:
    // reject if growing the utilisation would exceed the control's capacity.
    let admitted = object_table::with_sched_control_mut(ctrl_ref, |ctrl| {
        if new_util > prev_util && !ctrl.can_admit(new_util - prev_util) {
            return false;
        }
        if already_here {
            ctrl.reconfigure(prev_util, new_util);
        } else {
            ctrl.admit(new_util);
        }
        true
    })
    .ok_or(SyscallError::InvalidCap)?;
    if !admitted {
        return Err(SyscallError::QuotaExceeded);
    }

    // Admission to this control succeeded. If the context had been admitted
    // against a *different* control (only possible with multiple SchedControls;
    // defensive for the current singleton), release it there now — never before
    // the new admission is granted, so a denial leaves all totals untouched.
    if cur_ctrl.is_valid() && !already_here {
        object_table::with_sched_control_mut(cur_ctrl, |ctrl| ctrl.release(cur_util));
    }

    object_table::with_sched_context_mut(ctx_ref, |ctx| {
        ctx.budget = budget_us;
        ctx.period = period_us;
        ctx.remaining = budget_us;
        ctx.extra_budget = 0;
        // Period starts when the context is next bound/replenished.
        ctx.period_start = 0;
        // Record what we just admitted so reconfigure/destroy adjust by the
        // right delta.
        ctx.admitted_ppm = new_util;
        ctx.admitting_control = ctrl_ref;
    })
    .ok_or(SyscallError::InvalidCap)?;

    Ok(0)
}

/// Handle `SchedContext.Bind(tcb)`.
///
/// Attaches a configured SchedContext to a TCB. After this, the scheduler
/// enforces the context's CPU budget on that thread.
pub fn handle_sched_context_bind(args: &SyscallArgs) -> SyscallResult {
    let sched_context_cptr = args.arg0;
    let tcb_cptr = args.arg1;

    let ctx_cap = ipc::lookup_cap(sched_context_cptr, ObjectType::SchedContext, CapRights::WRITE)?;
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    // The context must be configured (valid budget/period) before binding.
    let configured = object_table::with_sched_context(ctx_cap.obj_ref, |ctx| ctx.is_valid())
        .ok_or(SyscallError::InvalidCap)?;
    if !configured {
        return Err(SyscallError::InvalidState);
    }

    // The context must not already be bound to a different TCB.
    let ctx_bound = object_table::with_sched_context(ctx_cap.obj_ref, |ctx| ctx.bound_tcb)
        .ok_or(SyscallError::InvalidCap)?;
    if ctx_bound.is_valid() && ctx_bound != tcb_cap.obj_ref {
        return Err(SyscallError::InvalidState);
    }

    // The TCB must not already hold a different context.
    let tcb_ctx = object_table::with_tcb(tcb_cap.obj_ref, |tcb| tcb.tcb.sched_context);
    if tcb_ctx.is_valid() && tcb_ctx != ctx_cap.obj_ref {
        return Err(SyscallError::InvalidState);
    }

    // Replenish and start the budget period at bind time.
    let now = timer::read_counter();
    object_table::with_sched_context_mut(ctx_cap.obj_ref, |ctx| {
        ctx.bound_tcb = tcb_cap.obj_ref;
        ctx.is_active = true;
        ctx.remaining = ctx.budget;
        ctx.period_start = now;
    });
    object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb| {
        tcb.tcb.sched_context = ctx_cap.obj_ref;
    });

    Ok(0)
}

/// Handle `SchedContext.Unbind()`.
///
/// Detaches a SchedContext from its TCB, removing CPU-budget enforcement.
pub fn handle_sched_context_unbind(args: &SyscallArgs) -> SyscallResult {
    let sched_context_cptr = args.arg0;

    let ctx_cap = ipc::lookup_cap(sched_context_cptr, ObjectType::SchedContext, CapRights::WRITE)?;

    let bound_tcb = object_table::with_sched_context(ctx_cap.obj_ref, |ctx| ctx.bound_tcb)
        .ok_or(SyscallError::InvalidCap)?;

    if bound_tcb.is_valid() {
        object_table::with_tcb_mut(bound_tcb, |tcb| {
            if tcb.tcb.sched_context == ctx_cap.obj_ref {
                tcb.tcb.sched_context = ObjectRef::NULL;
            }
        });
    }

    object_table::with_sched_context_mut(ctx_cap.obj_ref, |ctx| {
        ctx.bound_tcb = ObjectRef::NULL;
        ctx.is_active = false;
    });

    Ok(0)
}
