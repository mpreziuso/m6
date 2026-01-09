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

/// Enter userspace for the first time.
///
/// This function is used during kernel initialisation to jump to the first
/// userspace task. It performs the initial TTBR0 switch and `eret`.
///
/// # Safety
///
/// - The current task must have a valid VSpace and context configured
/// - This function does not return
pub fn enter_userspace() -> ! {
    let cpu_id = super::current_cpu_id();
    let sched_state = super::get_sched_state();
    let sched = sched_state[cpu_id].lock();

    let tcb_ref = sched.current().expect("No current task to enter");

    // Get the task's VSpace and switch TTBR0
    let vspace_ref = with_tcb(tcb_ref, |tcb| tcb.tcb.vspace);
    drop(sched); // Release lock before switching

    switch_vspace(vspace_ref);

    // Get context and perform eret
    let (elr, sp, spsr, x0) = with_tcb(tcb_ref, |tcb| {
        (tcb.context.elr, tcb.context.sp, tcb.context.spsr, tcb.context.gpr[0])
    }).expect("Failed to read task context");

    log::debug!(
        "Entering userspace: ELR={:#x} SP={:#x} SPSR={:#x} x0={:#x}",
        elr, sp, spsr, x0
    );

    // SAFETY: We've set up a valid user context. This function won't return.
    unsafe {
        initial_eret(elr, sp, spsr, x0);
    }
}

/// Perform the initial eret to userspace.
///
/// # Safety
///
/// All parameters must form a valid userspace execution context.
#[inline(never)]
unsafe fn initial_eret(elr: u64, sp: u64, spsr: u64, x0: u64) -> ! {
    // SAFETY: Setting up EL0 execution context and performing eret.
    unsafe {
        core::arch::asm!(
            // Set up system registers for return to EL0
            "msr elr_el1, {elr}",
            "msr sp_el0, {sp}",
            "msr spsr_el1, {spsr}",
            // Clear all other GPRs for security (except x0 which has boot info)
            "mov x1, #0",
            "mov x2, #0",
            "mov x3, #0",
            "mov x4, #0",
            "mov x5, #0",
            "mov x6, #0",
            "mov x7, #0",
            "mov x8, #0",
            "mov x9, #0",
            "mov x10, #0",
            "mov x11, #0",
            "mov x12, #0",
            "mov x13, #0",
            "mov x14, #0",
            "mov x15, #0",
            "mov x16, #0",
            "mov x17, #0",
            "mov x18, #0",
            "mov x19, #0",
            "mov x20, #0",
            "mov x21, #0",
            "mov x22, #0",
            "mov x23, #0",
            "mov x24, #0",
            "mov x25, #0",
            "mov x26, #0",
            "mov x27, #0",
            "mov x28, #0",
            "mov x29, #0",
            "mov x30, #0",
            // Return to userspace
            "eret",
            elr = in(reg) elr,
            sp = in(reg) sp,
            spsr = in(reg) spsr,
            in("x0") x0,
            options(noreturn)
        );
    }
}
