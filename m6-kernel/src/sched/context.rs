//! Context Switching
//!
//! Handles the low-level details of switching between tasks:
//! - Register save/restore via ExceptionContext
//! - VSpace (TTBR0) switching
//! - ASID management

use m6_arch::exceptions::ExceptionContext;
use m6_arch::mmu::mmu;
use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;

use super::run_queue::{with_tcb, with_tcb_mut};
use super::{eevdf, PerCpuSched};
use crate::cap::object_table::{self, KernelObjectType};

/// Perform a context switch.
///
/// This is the core preemption mechanism:
/// 1. Saves current task's context from the exception frame
/// 2. Picks the next task via EEVDF
/// 3. Switches TTBR0 if address spaces differ
/// 4. Restores next task's context to the exception frame
///
/// When the IRQ handler returns via `eret`, the CPU will resume
/// executing the NEW task.
pub fn context_switch(sched: &mut PerCpuSched, ctx: &mut ExceptionContext) {
    // Save current task's context from exception frame
    if let Some(current_ref) = sched.current() {
        with_tcb_mut(current_ref, |tcb| {
            tcb.context = ctx.clone();

            // Mark as runnable (unless it's sleeping or finished)
            if tcb.tcb.state == ThreadState::Running {
                // Keep it as Running - the state will be used for scheduling
            }
        });
    }

    // Get VSpace of current task (if any)
    let prev_vspace = sched.current()
        .and_then(|tcb_ref| with_tcb(tcb_ref, |tcb| tcb.tcb.vspace));

    // Find next task using EEVDF (or idle task as fallback)
    let next = eevdf::find_next_runnable(sched)
        .unwrap_or(sched.idle_thread);

    if !next.is_valid() {
        log::error!("No runnable task and no idle task!");
        return;
    }

    // Get VSpace of next task
    let next_vspace = with_tcb(next, |tcb| tcb.tcb.vspace);

    // Switch TTBR0 if address spaces differ
    if prev_vspace != next_vspace {
        switch_vspace(next_vspace);
    }

    // Update EEVDF accounting and set as running
    eevdf::switch_to(sched, next);

    // Restore next task's context to exception frame
    // When eret executes, CPU will resume this task
    with_tcb(next, |tcb| {
        *ctx = tcb.context.clone();
    });
}

/// Switch to a new virtual address space.
fn switch_vspace(vspace_ref: Option<ObjectRef>) {
    let vspace_ref = match vspace_ref {
        Some(r) if r.is_valid() => r,
        _ => return, // No VSpace or invalid - stay in current
    };

    object_table::with_object(vspace_ref, |obj| {
        if obj.obj_type == KernelObjectType::VSpace {
            // Get TTBR0 value from VSpace
            // SAFETY: We verified the type.
            let vspace = unsafe { &*core::ptr::addr_of!(obj.data.vspace) };

            // The VSpace stores the physical address of the L0 page table
            let ttbr0 = vspace.root_table.as_u64();
            let asid = vspace.asid.value() as u64;

            // Combine ASID and table base
            // TTBR0_EL1 format: [ASID:16][BADDR:48]
            let ttbr0_with_asid = (asid << 48) | (ttbr0 & 0x0000_FFFF_FFFF_FFFF);

            mmu().set_ttbr0(ttbr0_with_asid);

            // TLB invalidation strategy:
            // - All user page table entries have the NG (Not Global) bit set
            // - Different ASIDs cannot share TLB entries when NG=1
            // - We may need to invalidate if ASID was reused
            // For now, do a full TLB invalidate to be safe
            mmu().invalidate_tlb_all();
        }
    });
}

/// Perform a context switch from the timer interrupt handler.
///
/// This is called when the reschedule flag is set.
pub fn timer_context_switch(ctx: &mut ExceptionContext) {
    let cpu_id = super::current_cpu_id();
    let sched_state = super::get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    context_switch(&mut sched, ctx);
}

/// Switch to a specific task (used for initial task startup).
pub fn switch_to_task(sched: &mut PerCpuSched, tcb_ref: ObjectRef, ctx: &mut ExceptionContext) {
    // Set up the task
    eevdf::switch_to(sched, tcb_ref);

    // Restore context
    with_tcb(tcb_ref, |tcb| {
        *ctx = tcb.context.clone();
    });

    // Switch VSpace
    let vspace_ref = with_tcb(tcb_ref, |tcb| tcb.tcb.vspace);
    switch_vspace(vspace_ref);
}
