//! TCB syscall handlers
//!
//! This module implements syscalls for thread control block management:
//! - TcbConfigure: Configure a TCB with CSpace, VSpace, IPC buffer, fault endpoint
//! - TcbWriteRegisters: Write registers to a TCB's saved context
//! - TcbReadRegisters: Read registers from a TCB's saved context
//! - TcbResume: Resume a suspended/inactive thread
//! - TcbSuspend: Suspend a running thread
//! - TcbSetPriority: Set thread scheduling priority
//! - TcbBindNotification: Bind a notification to a TCB

use m6_arch::exceptions::ExceptionContext;
use m6_cap::objects::ThreadState;
use m6_cap::{CapRights, ObjectType};
use m6_common::{PhysAddr, VirtAddr};

use crate::cap::object_table;
use crate::ipc;
use crate::sched;

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};

// -- User address space boundary
const USER_SPACE_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

// -- Maximum number of registers (x0-x30, sp, pc, spsr)
const MAX_REGISTERS: u64 = 34;

/// Handle TcbConfigure syscall.
///
/// Configures a TCB with CSpace root, VSpace, IPC buffer, and fault endpoint.
///
/// # ABI
///
/// - x0: TCB capability pointer
/// - x1: Fault endpoint capability pointer (0 = none)
/// - x2: CSpace root CNode capability pointer
/// - x3: VSpace capability pointer
/// - x4: IPC buffer virtual address
/// - x5: IPC buffer frame capability pointer (0 = none)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_configure(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;
    let fault_ep_cptr = args.arg1;
    let cspace_root_cptr = args.arg2;
    let vspace_cptr = args.arg3;
    let ipc_buffer_addr = args.arg4;
    let ipc_buffer_cptr = args.arg5;

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    // Look up CSpace root (required)
    let cspace_cap = ipc::lookup_cap(cspace_root_cptr, ObjectType::CNode, CapRights::NONE)?;

    // Look up VSpace (required)
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::NONE)?;

    // Look up fault endpoint (optional)
    let fault_ep_ref = if fault_ep_cptr != 0 {
        let cap = ipc::lookup_cap(fault_ep_cptr, ObjectType::Endpoint, CapRights::GRANT_REPLY)?;
        Some(cap.obj_ref)
    } else {
        None
    };

    // Look up IPC buffer frame (optional)
    let ipc_buffer_ref = if ipc_buffer_cptr != 0 {
        let cap = ipc::lookup_cap(ipc_buffer_cptr, ObjectType::Frame, CapRights::RW)?;
        Some(cap.obj_ref)
    } else {
        None
    };

    // Validate IPC buffer address if provided
    if ipc_buffer_cptr != 0 {
        if ipc_buffer_addr > USER_SPACE_MAX {
            return Err(SyscallError::Range);
        }
        // Must be page-aligned
        if ipc_buffer_addr & 0xFFF != 0 {
            return Err(SyscallError::Alignment);
        }
    }

    // Check TCB state first (must be Inactive to configure)
    let state = object_table::with_tcb(tcb_cap.obj_ref, |tcb_full| tcb_full.tcb.state);
    if state != ThreadState::Inactive {
        return Err(SyscallError::InvalidState);
    }

    // Extract IPC buffer physical address BEFORE taking the TCB lock
    // (to avoid deadlock with nested object table locks)
    let ipc_buffer_phys = if let Some(ref buf_ref) = ipc_buffer_ref {
        object_table::with_frame_mut(*buf_ref, |frame| frame.phys_addr).unwrap_or(PhysAddr::new(0))
    } else {
        PhysAddr::new(0)
    };

    // Configure the TCB
    let _: () = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb_full| {
        // Set CSpace root
        tcb_full.tcb.cspace_root = cspace_cap.obj_ref;

        // Set VSpace
        tcb_full.tcb.vspace = vspace_cap.obj_ref;

        // Set fault endpoint
        if let Some(ref ep_ref) = fault_ep_ref {
            tcb_full.tcb.fault_endpoint = *ep_ref;
        } else {
            tcb_full.tcb.fault_endpoint = m6_cap::ObjectRef::NULL;
        }

        // Set IPC buffer
        if let Some(ref buf_ref) = ipc_buffer_ref {
            tcb_full.tcb.ipc_buffer = *buf_ref;
            tcb_full.tcb.ipc_buffer_addr = VirtAddr::new(ipc_buffer_addr);
            tcb_full.tcb.ipc_buffer_phys = ipc_buffer_phys;
        } else {
            tcb_full.tcb.ipc_buffer = m6_cap::ObjectRef::NULL;
            tcb_full.tcb.ipc_buffer_addr = VirtAddr::new(0);
            tcb_full.tcb.ipc_buffer_phys = PhysAddr::new(0);
        }
    });

    Ok(0)
}

/// Handle TcbWriteRegisters syscall.
///
/// Writes register values to a TCB's saved context.
///
/// # ABI
///
/// - x0: TCB capability pointer
/// - x1: Resume flag (0 = don't resume, 1 = resume after writing)
/// - x2: Architecture flags (reserved, must be 0)
/// - x3: Number of registers to write
/// - x4: User buffer address containing register values
///
/// Register buffer format: [x0..x30, sp, pc, spsr] as u64 array
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_write_registers(args: &SyscallArgs, _ctx: &ExceptionContext) -> SyscallResult {
    let tcb_cptr = args.arg0;
    let resume = args.arg1 != 0;
    let _arch_flags = args.arg2;
    let count = args.arg3;
    let buffer_addr = args.arg4;

    // Validate count
    if count > MAX_REGISTERS {
        return Err(SyscallError::Range);
    }

    // Validate buffer address
    if buffer_addr > USER_SPACE_MAX || buffer_addr.saturating_add(count * 8) > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    // Read register values from user buffer
    // SAFETY: We've validated the buffer is in user space. Page faults will be
    // handled by the exception system.
    let buffer = buffer_addr as *const u64;

    // Check TCB state first (must be Inactive or Suspended to write registers)
    let state = object_table::with_tcb(tcb_cap.obj_ref, |tcb_full| tcb_full.tcb.state);
    match state {
        ThreadState::Inactive | ThreadState::Suspended => {}
        _ => return Err(SyscallError::InvalidState),
    }

    // Validate PC value if we're going to write it (register index 32)
    if count > 32 {
        // SAFETY: Buffer address validated above, within user space.
        let pc_value = unsafe { buffer.add(32).read_volatile() };
        if pc_value > USER_SPACE_MAX {
            return Err(SyscallError::Range);
        }
    }

    // Write registers to TCB
    let _: () = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb_full| {
        // Copy registers from user buffer
        for i in 0..count as usize {
            // SAFETY: Buffer address validated above, within user space.
            let value = unsafe { buffer.add(i).read_volatile() };

            if i < 31 {
                tcb_full.context.gpr[i] = value;
            } else if i == 31 {
                tcb_full.context.sp = value;
            } else if i == 32 {
                // PC (ELR) - validated above
                tcb_full.context.elr = value;
            } else if i == 33 {
                // SPSR - sanitise to ensure EL0 and AArch64
                tcb_full.context.spsr = sanitise_spsr(value);
            }
        }
    });

    // Resume if requested
    if resume {
        do_resume(tcb_cap.obj_ref)?;
    }

    Ok(0)
}

/// Handle TcbReadRegisters syscall.
///
/// Reads register values from a TCB's saved context.
///
/// # ABI
///
/// - x0: TCB capability pointer
/// - x1: Suspend flag (0 = don't suspend, 1 = suspend first)
/// - x2: Architecture flags (reserved, must be 0)
/// - x3: Number of registers to read
/// - x4: User buffer address to receive register values
///
/// # Returns
///
/// - Number of registers read on success
/// - Negative error code on failure
pub fn handle_tcb_read_registers(args: &SyscallArgs, _ctx: &ExceptionContext) -> SyscallResult {
    let tcb_cptr = args.arg0;
    let suspend = args.arg1 != 0;
    let _arch_flags = args.arg2;
    let count = args.arg3;
    let buffer_addr = args.arg4;

    // Validate count
    if count > MAX_REGISTERS {
        return Err(SyscallError::Range);
    }

    // Validate buffer address
    if buffer_addr > USER_SPACE_MAX || buffer_addr.saturating_add(count * 8) > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Look up TCB capability with READ right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::READ)?;

    // Suspend first if requested
    if suspend {
        // Need WRITE right to suspend
        let _ = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;
        do_suspend(tcb_cap.obj_ref)?;
    }

    // Read registers from TCB
    let buffer = buffer_addr as *mut u64;

    let _: () = object_table::with_tcb(tcb_cap.obj_ref, |tcb_full| {
        // Copy registers to user buffer
        for i in 0..count as usize {
            let value = if i < 31 {
                tcb_full.context.gpr[i]
            } else if i == 31 {
                tcb_full.context.sp
            } else if i == 32 {
                tcb_full.context.elr
            } else if i == 33 {
                tcb_full.context.spsr
            } else {
                0
            };

            // SAFETY: Buffer address validated above, within user space.
            unsafe { buffer.add(i).write_volatile(value) };
        }
    });

    Ok(count as i64)
}

/// Handle TcbResume syscall.
///
/// Resumes a suspended or inactive thread.
///
/// # ABI
///
/// - x0: TCB capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_resume(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    do_resume(tcb_cap.obj_ref)?;

    Ok(0)
}

/// Handle TcbSuspend syscall.
///
/// Suspends a running thread.
///
/// # ABI
///
/// - x0: TCB capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_suspend(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    do_suspend(tcb_cap.obj_ref)?;

    // If we suspended ourselves, trigger reschedule
    if Some(tcb_cap.obj_ref) == sched::current_task() {
        sched::request_reschedule();
    }

    Ok(0)
}

/// Handle TcbSetPriority syscall.
///
/// Sets thread scheduling priority.
///
/// # ABI
///
/// - x0: TCB capability pointer
/// - x1: Authority TCB capability pointer (0 = use current thread)
/// - x2: New priority (0-255)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_set_priority(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;
    let authority_cptr = args.arg1;
    let priority = args.arg2;

    // Validate priority range
    if priority > 255 {
        return Err(SyscallError::Range);
    }

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    // Get authority's max_priority
    let max_priority = if authority_cptr != 0 {
        // Use specified authority TCB
        let auth_cap = ipc::lookup_cap(authority_cptr, ObjectType::TCB, CapRights::NONE)?;
        object_table::with_tcb(auth_cap.obj_ref, |tcb_full| tcb_full.tcb.max_priority)
    } else {
        // Use current thread's max_priority
        let current = sched::current_task().ok_or(SyscallError::InvalidState)?;
        object_table::with_tcb(current, |tcb_full| tcb_full.tcb.max_priority)
    };

    // Validate priority against authority
    if priority as u8 > max_priority {
        return Err(SyscallError::NoRights);
    }

    // Set the priority
    let _: () = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb_full| {
        tcb_full.tcb.priority = priority as u8;
    });

    Ok(0)
}

/// Handle TcbBindNotification syscall.
///
/// Binds a notification object to a TCB for combined waiting.
///
/// # ABI
///
/// - x0: TCB capability pointer
/// - x1: Notification capability pointer (0 = unbind)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_tcb_bind_notification(args: &SyscallArgs) -> SyscallResult {
    let tcb_cptr = args.arg0;
    let notification_cptr = args.arg1;

    // Look up TCB capability with WRITE right
    let tcb_cap = ipc::lookup_cap(tcb_cptr, ObjectType::TCB, CapRights::WRITE)?;

    if notification_cptr == 0 {
        // Unbind
        let _: () = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb_full| {
            tcb_full.tcb.bound_notification = m6_cap::ObjectRef::NULL;
        });
        return Ok(0);
    }

    // Look up notification capability with READ right
    let notif_cap = ipc::lookup_cap(notification_cptr, ObjectType::Notification, CapRights::READ)?;

    // Check if already bound
    let is_bound = object_table::with_tcb(tcb_cap.obj_ref, |tcb_full| {
        tcb_full.tcb.bound_notification.is_valid()
    });
    if is_bound {
        return Err(SyscallError::InvalidState);
    }

    // Bind the notification
    let _: () = object_table::with_tcb_mut(tcb_cap.obj_ref, |tcb_full| {
        tcb_full.tcb.bound_notification = notif_cap.obj_ref;
    });

    Ok(0)
}

/// Handle TcbExit syscall.
///
/// Terminates the current thread with an exit code. The thread is set to
/// Inactive state and the exit code is stored in the TCB. If the thread
/// has a bound notification, it will be signalled with the exit code as the badge.
///
/// This syscall never returns.
///
/// # ABI
///
/// - x0: Exit code (i32)
///
/// # Returns
///
/// Never returns (triggers reschedule).
pub fn handle_tcb_exit(args: &SyscallArgs) -> SyscallResult {
    let exit_code = args.arg0 as i32;

    // Get current task
    let tcb_ref = sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Store exit code and set state to Inactive
    let bound_notification = object_table::with_tcb_mut(tcb_ref, |tcb_full| {
        tcb_full.tcb.exit_code = exit_code;
        tcb_full.tcb.state = ThreadState::Inactive;
        tcb_full.tcb.bound_notification
    });

    // Remove from scheduler
    sched::remove_task(tcb_ref);

    // Signal bound notification with exit code as badge (if any)
    if bound_notification.is_valid() {
        let _ = ipc::do_signal(bound_notification, exit_code as u64);
    }

    // Request reschedule - the kernel will switch to another task
    sched::request_reschedule();

    // This syscall never returns in practice (we're removed from scheduler)
    // but we need to return something for the type system
    Ok(0)
}

/// Handle TcbSleep syscall.
///
/// Puts the current thread to sleep for a specified duration. The thread is
/// set to Sleeping state and added to the sleep queue. The kernel's timer
/// system will wake the thread after the specified time has elapsed.
///
/// # ABI
///
/// - x0: Duration to sleep in nanoseconds
///
/// # Returns
///
/// - 0 on success (after wakeup)
/// - Negative error code on failure
pub fn handle_tcb_sleep(args: &SyscallArgs) -> SyscallResult {
    let nanoseconds = args.arg0;

    // Get current task
    let tcb_ref = sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Zero sleep is a no-op (just yield)
    if nanoseconds == 0 {
        sched::request_reschedule();
        return Ok(0);
    }

    // Set state to Sleeping and remove from run queue
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb_full| {
        tcb_full.tcb.state = ThreadState::Sleeping;
    });

    // Remove from scheduler run queue
    sched::remove_task(tcb_ref);

    // Add to sleep queue
    sched::sleep::sleep_for(tcb_ref, nanoseconds);

    // Request reschedule to switch to another task
    sched::request_reschedule();

    // Return success - this will be the return value when the thread wakes up
    Ok(0)
}

// -- Helper functions

/// Resume a TCB (internal helper).
fn do_resume(tcb_ref: m6_cap::ObjectRef) -> Result<(), SyscallError> {
    // Check TCB state and configuration first
    let (state, is_configured) = object_table::with_tcb(tcb_ref, |tcb_full| {
        (tcb_full.tcb.state, tcb_full.tcb.is_configured())
    });

    // TCB must be Inactive or Suspended to resume
    match state {
        ThreadState::Inactive | ThreadState::Suspended => {}
        _ => return Err(SyscallError::InvalidState),
    }

    // TCB must be configured
    if !is_configured {
        return Err(SyscallError::InvalidState);
    }

    // Set state to Running
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb_full| {
        tcb_full.tcb.state = ThreadState::Running;
    });

    // Add to scheduler run queue
    sched::insert_task(tcb_ref);

    Ok(())
}

/// Suspend a TCB (internal helper).
fn do_suspend(tcb_ref: m6_cap::ObjectRef) -> Result<(), SyscallError> {
    // Check state first (can only suspend Running threads)
    let state = object_table::with_tcb(tcb_ref, |tcb_full| tcb_full.tcb.state);
    if state != ThreadState::Running {
        return Err(SyscallError::InvalidState);
    }

    // Set state to Suspended
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb_full| {
        tcb_full.tcb.state = ThreadState::Suspended;
    });

    // Remove from scheduler run queue
    sched::remove_task(tcb_ref);

    Ok(())
}

/// Sanitise SPSR to ensure safe values.
///
/// - Must be EL0 (user mode)
/// - Must be AArch64 (not AArch32)
/// - Clear reserved bits
fn sanitise_spsr(spsr: u64) -> u64 {
    // EL0 = 0b00, AArch64 mode
    // NZCV flags (bits 28-31) are preserved
    // DAIF bits (bits 6-9) are cleared (interrupts enabled)
    // Mode bits (0-4) forced to EL0

    const NZCV_MASK: u64 = 0xF << 28; // Preserve NZCV flags
    const EL0_AARCH64: u64 = 0; // EL0, AArch64

    (spsr & NZCV_MASK) | EL0_AARCH64
}
