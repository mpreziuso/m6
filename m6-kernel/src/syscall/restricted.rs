//! Restricted mode handlers for Starnix (Linux binary emulation)
//!
//! A Starnix thread enters restricted mode to run Linux code at EL0 in a
//! separate VSpace. When the Linux code executes `svc #0`, the kernel
//! intercepts it and returns control to the Starnix thread rather than
//! dispatching a normal M6 syscall.
//!
//! State frame layout (4KB page, mapped in the Starnix process):
//! - offset 0:   ExceptionContext (832 bytes) — Linux register state
//! - offset 832: u64 exit_reason
//! - offset 840: reserved

use m6_arch::exceptions::ExceptionContext;
use m6_cap::{CapRights, ObjectRef, ObjectType};

use crate::cap::object_table;
use crate::ipc;
use crate::memory::translate::phys_to_virt;
use crate::sched;
use crate::sched::context::switch_vspace;

use super::SyscallArgs;
use super::error::{IPC_MESSAGE_DELIVERED, SyscallError, SyscallResult};

/// Offset of the exit_reason field within the state frame.
const STATE_FRAME_EXIT_REASON_OFFSET: usize = core::mem::size_of::<ExceptionContext>();

// -- Bind

/// Bind a state frame to the current thread (self-invocation).
///
/// After binding, the thread can enter restricted mode via `RestrictedEnter`.
///
/// # ABI (repacked as self-invocation args)
///
/// - arg0: Frame capability pointer for the state frame
pub fn handle_restricted_bind(args: &SyscallArgs) -> SyscallResult {
    let frame_cptr = args.arg0;

    // Look up Frame capability — caller must own it with WRITE right.
    let frame_cap = ipc::lookup_cap(frame_cptr, ObjectType::Frame, CapRights::WRITE)?;

    // Get the physical address from the frame object.
    let phys_addr = object_table::with_frame_mut(frame_cap.obj_ref, |frame| {
        frame.phys_addr.as_u64()
    })
    .ok_or(SyscallError::TypeMismatch)?;

    if phys_addr == 0 {
        return Err(SyscallError::InvalidArg);
    }

    // Store in current thread's TCB.
    let tcb_ref = sched::current_task().ok_or(SyscallError::InvalidState)?;
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.restricted_state_phys = phys_addr;
    });

    log::debug!(
        "restricted_bind: thread {:?} bound state frame phys={:#x}",
        tcb_ref,
        phys_addr
    );

    Ok(0)
}

// -- Enter

/// Enter restricted mode (fast-path syscall 10).
///
/// Saves the Starnix (normal-mode) context, loads the Linux context from the
/// state frame, switches to the target VSpace, and returns via eret into
/// the Linux code at EL0.
///
/// # ABI
///
/// - x0: VSpace capability pointer for the restricted address space
///
/// Returns the exit reason in x0 when restricted mode exits.
pub fn handle_restricted_enter(args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let vspace_cptr = args.arg0;

    let tcb_ref = sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Read restricted state from TCB.
    let state_phys = object_table::with_tcb(tcb_ref, |tcb| tcb.restricted_state_phys);
    if state_phys == 0 {
        return Err(SyscallError::InvalidState);
    }

    // Validate the VSpace capability.
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::NONE)?;

    // Save Starnix context and set restricted mode fields.
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.restricted_normal_ctx = ctx.clone();
        // Save the thread's normal VSpace so we can restore it on exit.
        let vspace = tcb.tcb.vspace;
        tcb.restricted_normal_vspace = if vspace.is_valid() {
            vspace
        } else {
            ObjectRef::NULL
        };
        tcb.restricted_mode = true;
    });

    // Load Linux context from state frame.
    let state_virt = phys_to_virt(state_phys);
    // SAFETY: The state frame physical address was validated during bind and
    // maps to a valid kernel virtual address via the direct physical map.
    // The ExceptionContext at offset 0 was written by userspace (Starnix).
    let state_ctx = unsafe { &*(state_virt as *const ExceptionContext) };
    *ctx = state_ctx.clone();

    // Force SPSR to EL0t (0x0) — security: prevent privilege escalation.
    ctx.spsr = 0;

    // Switch to the restricted VSpace.
    switch_vspace(Some(vspace_cap.obj_ref));

    // Return IPC_MESSAGE_DELIVERED to prevent the dispatcher from overwriting
    // x0 — the eret continuation will resume Linux code with the state frame's
    // register values.
    Ok(IPC_MESSAGE_DELIVERED)
}

// -- Exit

/// Exit restricted mode (called from SVC/fault handlers when restricted_mode is true).
///
/// Saves Linux context back to the state frame, restores the Starnix context,
/// switches VSpace back, and sets the exit reason as the return value.
pub fn restricted_exit(ctx: &mut ExceptionContext, reason: u64) {
    let tcb_ref = match sched::current_task() {
        Some(r) => r,
        None => return,
    };

    // Read state frame physical address.
    let state_phys = object_table::with_tcb(tcb_ref, |tcb| tcb.restricted_state_phys);
    if state_phys == 0 {
        log::error!("restricted_exit: no state frame bound");
        return;
    }

    let state_virt = phys_to_virt(state_phys);

    // Write Linux context (current exception frame) to state frame.
    // SAFETY: state_virt points to a valid 4KB frame in the direct physical map.
    unsafe {
        let dst = state_virt as *mut ExceptionContext;
        core::ptr::write(dst, ctx.clone());
    }

    // Write exit reason at offset 832.
    // SAFETY: STATE_FRAME_EXIT_REASON_OFFSET is within the 4KB frame.
    unsafe {
        let reason_ptr = (state_virt as usize + STATE_FRAME_EXIT_REASON_OFFSET) as *mut u64;
        core::ptr::write_volatile(reason_ptr, reason);
    }

    // Restore normal-mode context and VSpace.
    let normal_vspace: Option<ObjectRef> = object_table::with_tcb_mut(tcb_ref, |tcb| {
        let vspace = tcb.restricted_normal_vspace;
        *ctx = tcb.restricted_normal_ctx.clone();
        tcb.restricted_mode = false;
        tcb.restricted_kick_pending = false;
        Some(vspace)
    });

    // Set exit reason as the return value for the Starnix thread's
    // restricted_enter() call.
    ctx.gpr[0] = reason;

    // Switch back to the Starnix VSpace.
    if let Some(vspace) = normal_vspace
        && vspace.is_valid()
    {
        switch_vspace(Some(vspace));
    }

    log::trace!(
        "restricted_exit: reason={} for {:?}",
        reason,
        tcb_ref
    );
}

// -- Kick

/// Kick a restricted-mode thread, forcing it to exit restricted mode.
///
/// Sets a pending flag. The next timer tick or syscall from the restricted
/// thread will check this flag and exit with REASON_KICK.
///
/// # ABI (TCB invocation)
///
/// - arg0: TCB capability pointer
pub fn handle_restricted_kick(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;

    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    let was_restricted = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb| {
        if tcb.restricted_mode {
            tcb.restricted_kick_pending = true;
            true
        } else {
            false
        }
    });

    if !was_restricted {
        return Err(SyscallError::InvalidState);
    }

    Ok(0)
}

// -- Query helpers

/// Check if the current thread is in restricted mode.
#[inline]
pub fn is_current_restricted() -> bool {
    sched::current_task()
        .map(|tcb_ref| {
            object_table::with_tcb(tcb_ref, |tcb| tcb.restricted_mode)
        })
        .unwrap_or(false)
}

/// Check if the current thread has a kick pending.
#[inline]
pub fn is_restricted_kick_pending() -> bool {
    sched::current_task()
        .map(|tcb_ref| {
            object_table::with_tcb(tcb_ref, |tcb| {
                tcb.restricted_mode && tcb.restricted_kick_pending
            })
        })
        .unwrap_or(false)
}
