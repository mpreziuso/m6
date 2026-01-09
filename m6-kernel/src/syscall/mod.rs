//! Syscall interface
//!
//! This module implements the syscall dispatcher for the M6 microkernel.
//!
//! # ABI
//!
//! Following seL4 conventions for ARM64:
//! - x7: syscall number
//! - x0-x5: arguments
//! - x0: return value (negative = error)
//!
//! # Entry Point
//!
//! Syscalls enter the kernel via SVC instruction from EL0. The exception
//! vector routes to [`handle_syscall`], which extracts arguments and
//! dispatches to the appropriate handler.

pub mod cap_ops;
pub mod error;
pub mod iommu_ops;
pub mod irq_ops;
pub mod mem_ops;
pub mod numbers;
pub mod tcb_ops;

use m6_arch::exceptions::ExceptionContext;
use m6_arch::registers::{esr, spsr};
use m6_cap::{CapRights, ObjectType};
use m6_pal::console;

use error::{SyscallError, SyscallResult, to_return_value};
use numbers::Syscall;

use crate::ipc::{self, IpcMessage};

/// Handle a syscall from userspace.
///
/// This is called from the synchronous exception handler when an SVC
/// instruction is executed from EL0.
///
/// # Arguments
///
/// * `ctx` - Exception context with saved registers
///
/// # Returns
///
/// The return value is placed in x0 of the context before returning.
pub fn handle_syscall(ctx: &mut ExceptionContext) {
    // Extract syscall number from x7
    let syscall_num = ctx.gpr[7];

    // Extract arguments from x0-x5
    let args = SyscallArgs {
        arg0: ctx.gpr[0],
        arg1: ctx.gpr[1],
        arg2: ctx.gpr[2],
        arg3: ctx.gpr[3],
        arg4: ctx.gpr[4],
        arg5: ctx.gpr[5],
    };

    // Dispatch and get result
    let result = dispatch_syscall(syscall_num, &args, ctx);

    // Store result in x0
    ctx.gpr[0] = to_return_value(result) as u64;
}

/// Syscall arguments extracted from registers.
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

/// Dispatch a syscall to its handler.
fn dispatch_syscall(
    num: u64,
    args: &SyscallArgs,
    ctx: &mut ExceptionContext,
) -> SyscallResult {
    let syscall = match Syscall::from_number(num) {
        Some(s) => s,
        None => {
            log::warn!("Invalid syscall number: {}", num);
            return Err(SyscallError::InvalidSyscall);
        }
    };

    log::trace!(
        "Syscall: {} (x0={:#x}, x1={:#x}, x2={:#x})",
        syscall.name(),
        args.arg0,
        args.arg1,
        args.arg2
    );

    match syscall {
        // IPC operations
        Syscall::Send => handle_send(args, ctx, true),
        Syscall::Recv => handle_recv(args, ctx, true),
        Syscall::Call => handle_call(args, ctx),
        Syscall::ReplyRecv => handle_reply_recv(args, ctx),
        Syscall::NBSend => handle_send(args, ctx, false),
        Syscall::NBRecv => handle_recv(args, ctx, false),
        Syscall::Yield => {
            // Check if there's another task to run
            let dominated = {
                let current = crate::sched::current_task();
                let cpu_id = 0; // TODO: get actual CPU ID
                let sched_state = crate::sched::get_sched_state();
                let sched = sched_state[cpu_id].lock();
                let next = crate::sched::eevdf::find_next_runnable(&sched);
                next.is_none() || next == current
            };

            if dominated {
                // No other task - wait for interrupt before returning
                // This prevents busy-looping when we're the only task
                // Must enable interrupts first or WFI returns immediately
                m6_arch::cpu::enable_interrupts();
                m6_arch::wait_for_interrupt();
                // Note: interrupt handler will run, then we continue here
            }

            // Yield to scheduler
            crate::sched::yield_current();
            Ok(0)
        }

        // Notification operations
        Syscall::Signal => handle_signal(args),
        Syscall::Wait => handle_wait(args, ctx),
        Syscall::Poll => handle_poll(args, ctx),

        // Capability operations
        Syscall::CapCopy => cap_ops::handle_cap_copy(args),
        Syscall::CapMove => cap_ops::handle_cap_move(args),
        Syscall::CapMint => cap_ops::handle_cap_mint(args),
        Syscall::CapDelete => cap_ops::handle_cap_delete(args),
        Syscall::CapRevoke => cap_ops::handle_cap_revoke(args),
        Syscall::CapMutate => cap_ops::handle_cap_mutate(args),
        Syscall::CapRotate => cap_ops::handle_cap_rotate(args),

        // Object invocation (stub)
        Syscall::Invoke => todo_syscall("Invoke"),

        // Memory operations
        Syscall::Retype => mem_ops::handle_retype(args),
        Syscall::MapFrame => mem_ops::handle_map_frame(args),
        Syscall::UnmapFrame => mem_ops::handle_unmap_frame(args),
        Syscall::MapPageTable => mem_ops::handle_map_page_table(args),

        // TCB operations
        Syscall::TcbConfigure => tcb_ops::handle_tcb_configure(args),
        Syscall::TcbWriteRegisters => tcb_ops::handle_tcb_write_registers(args, ctx),
        Syscall::TcbReadRegisters => tcb_ops::handle_tcb_read_registers(args, ctx),
        Syscall::TcbResume => tcb_ops::handle_tcb_resume(args),
        Syscall::TcbSuspend => tcb_ops::handle_tcb_suspend(args),
        Syscall::TcbSetPriority => tcb_ops::handle_tcb_set_priority(args),
        Syscall::TcbBindNotification => tcb_ops::handle_tcb_bind_notification(args),

        // IRQ operations
        Syscall::IrqAck => irq_ops::handle_irq_ack(args),
        Syscall::IrqSetHandler => irq_ops::handle_irq_set_handler(args),
        Syscall::IrqClearHandler => irq_ops::handle_irq_clear_handler(args),

        // IOMMU operations
        Syscall::IOSpaceCreate => iommu_ops::handle_iospace_create(args),
        Syscall::IOSpaceMapFrame => iommu_ops::handle_iospace_map_frame(args),
        Syscall::IOSpaceUnmapFrame => iommu_ops::handle_iospace_unmap_frame(args),
        Syscall::IOSpaceBindStream => iommu_ops::handle_iospace_bind_stream(args),
        Syscall::IOSpaceUnbindStream => iommu_ops::handle_iospace_unbind_stream(args),
        Syscall::DmaPoolCreate => iommu_ops::handle_dma_pool_create(args),
        Syscall::DmaPoolAlloc => iommu_ops::handle_dma_pool_alloc(args),
        Syscall::DmaPoolFree => iommu_ops::handle_dma_pool_free(args),

        // Debug syscall
        Syscall::DebugPutChar => {
            let c = args.arg0 as u8;
            console::putc(c);
            Ok(0)
        }
    }
}

/// Placeholder for unimplemented syscalls.
fn todo_syscall(name: &str) -> SyscallResult {
    log::warn!("Syscall {} not yet implemented", name);
    Err(SyscallError::NotSupported)
}

// -- IPC syscall handlers

/// Handle Send/NBSend syscall.
///
/// x0: endpoint capability pointer
/// x1-x5: message payload
fn handle_send(args: &SyscallArgs, ctx: &ExceptionContext, blocking: bool) -> SyscallResult {
    let cptr = args.arg0;
    let msg = IpcMessage::from_context(ctx);

    // Look up endpoint capability with WRITE right
    let cap = ipc::lookup_cap(cptr, ObjectType::Endpoint, CapRights::WRITE)?;

    // Get current task
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Perform send
    match ipc::do_send(current, cap.obj_ref, cap.badge, &msg, blocking) {
        Ok(_) => Ok(0),
        Err(SyscallError::WouldBlock) if !blocking => Err(SyscallError::WouldBlock),
        Err(e) => Err(e),
    }
}

/// Handle Recv/NBRecv syscall.
///
/// x0: endpoint capability pointer
/// Returns: x0-x5 = message, x6 = badge
fn handle_recv(
    args: &SyscallArgs,
    ctx: &mut ExceptionContext,
    blocking: bool,
) -> SyscallResult {
    let cptr = args.arg0;

    // Look up endpoint capability with READ right
    let cap = ipc::lookup_cap(cptr, ObjectType::Endpoint, CapRights::READ)?;

    // Get current task
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Perform receive
    match ipc::do_recv(current, cap.obj_ref, blocking)? {
        Some((badge, msg)) => {
            // Message received - write to context
            msg.to_context(ctx);
            ctx.gpr[6] = badge;
            Ok(0)
        }
        None => {
            // Blocked - will be delivered when sender arrives
            Ok(0)
        }
    }
}

/// Handle Call syscall (Send + wait for reply).
///
/// x0: endpoint capability pointer
/// x1-x5: message payload
/// Returns: x0-x5 = reply message
fn handle_call(args: &SyscallArgs, ctx: &ExceptionContext) -> SyscallResult {
    let cptr = args.arg0;
    let msg = IpcMessage::from_context(ctx);

    // Look up endpoint with WRITE + GRANT_REPLY rights
    let required = CapRights::WRITE | CapRights::GRANT_REPLY;
    let cap = ipc::lookup_cap(cptr, ObjectType::Endpoint, required)?;

    // Get current task
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Perform call (send + block waiting for reply)
    ipc::do_call(current, cap.obj_ref, cap.badge, &msg)?;

    // Reply will be delivered directly to our context when it arrives
    Ok(0)
}

/// Handle ReplyRecv syscall.
///
/// x0: endpoint capability pointer
/// x1-x5: reply message payload
/// Returns: x0-x5 = new request message, x6 = badge
fn handle_reply_recv(args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let cptr = args.arg0;
    let reply_msg = IpcMessage::from_context(ctx);

    // Look up endpoint with READ + WRITE rights
    let cap = ipc::lookup_cap(cptr, ObjectType::Endpoint, CapRights::RW)?;

    // Get current task
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Reply to previous caller (if any) and receive next message
    match ipc::do_reply_recv(current, cap.obj_ref, &reply_msg)? {
        Some((badge, msg)) => {
            msg.to_context(ctx);
            ctx.gpr[6] = badge;
            Ok(0)
        }
        None => {
            // Blocked waiting for next request
            Ok(0)
        }
    }
}

/// Handle Signal syscall.
///
/// x0: notification capability pointer
fn handle_signal(args: &SyscallArgs) -> SyscallResult {
    let cptr = args.arg0;

    // Look up notification with WRITE right
    let cap = ipc::lookup_cap(cptr, ObjectType::Notification, CapRights::WRITE)?;

    // Perform signal
    ipc::do_signal(cap.obj_ref, cap.badge)?;

    Ok(0)
}

/// Handle Wait syscall.
///
/// x0: notification capability pointer
/// Returns: x0 = signal word
fn handle_wait(args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let cptr = args.arg0;

    // Look up notification with READ right
    let cap = ipc::lookup_cap(cptr, ObjectType::Notification, CapRights::READ)?;

    // Get current task
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    // Perform wait
    match ipc::do_wait(current, cap.obj_ref)? {
        Some(word) => {
            ctx.gpr[0] = word;
            Ok(0)
        }
        None => {
            // Blocked - signal word will be delivered when we're woken
            Ok(0)
        }
    }
}

/// Handle Poll syscall.
///
/// x0: notification capability pointer
/// Returns: x0 = signal word (0 if no signals)
fn handle_poll(args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let cptr = args.arg0;

    // Look up notification with READ right
    let cap = ipc::lookup_cap(cptr, ObjectType::Notification, CapRights::READ)?;

    // Perform poll
    let word = ipc::do_poll(cap.obj_ref)?;
    ctx.gpr[0] = word;

    Ok(0)
}

/// Install the syscall handler.
///
/// This hooks the synchronous exception handler to dispatch syscalls.
pub fn init() {
    m6_arch::exceptions::set_sync_handler(sync_exception_handler);
    log::info!("Syscall handler installed");
}

/// ANSI colour codes for terminal output
mod colour {
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RESET: &str = "\x1b[0m";
}

/// Dump full exception context for debugging.
///
/// Provides detailed information about the exception state including:
/// - Exception type and ESR breakdown
/// - ELR, FAR, and SPSR with decoded fields
/// - Detailed fault information for abort exceptions
/// - Full register dump
fn dump_exception_context(ctx: &ExceptionContext) {
    let ec = esr::exception_class(ctx.esr);
    let il = esr::instruction_length(ctx.esr);
    let iss = esr::iss(ctx.esr);

    // Exception type header
    console::puts(colour::RED);
    console::puts("\nException: ");
    console::puts(esr::ec_name(ec));
    console::puts(colour::RESET);
    console::puts("\n\n");

    // ESR breakdown
    log::error!(
        "ESR:   {:#018x} [EC={:#04x} IL={} ISS={:#07x}]",
        ctx.esr,
        ec,
        u8::from(il),
        iss
    );

    // ELR and FAR
    log::error!("ELR:   {:#018x}", ctx.elr);
    log::error!("FAR:   {:#018x}", ctx.far);

    // SPSR with decoded fields
    let (n, z, c, v) = spsr::nzcv(ctx.spsr);
    let (d, a, i, f) = spsr::daif(ctx.spsr);
    log::error!(
        "SPSR:  {:#018x} [NZCV={}{}{}{} {} D={} A={} I={} F={}]",
        ctx.spsr,
        u8::from(n),
        u8::from(z),
        u8::from(c),
        u8::from(v),
        spsr::el_name(ctx.spsr),
        u8::from(d),
        u8::from(a),
        u8::from(i),
        u8::from(f)
    );

    // For abort exceptions, print detailed fault info
    if matches!(
        ec,
        esr::ec::DATA_ABORT_LOWER
            | esr::ec::DATA_ABORT_SAME
            | esr::ec::INSTRUCTION_ABORT_LOWER
            | esr::ec::INSTRUCTION_ABORT_SAME
    ) {
        dump_abort_details(ec, iss);
    }

    // Register dump
    dump_registers(ctx);
}

/// Dump detailed abort exception information.
fn dump_abort_details(ec: u8, iss: u32) {
    let dfsc = esr::abort::dfsc(iss);
    let wnr = esr::abort::wnr(iss);
    let fnv = esr::abort::fnv(iss);
    let s1ptw = esr::abort::s1ptw(iss);
    let cm = esr::abort::cm(iss);

    console::puts("\n");
    console::puts(colour::YELLOW);
    console::puts("Fault Details:\n");
    console::puts(colour::RESET);

    log::error!("  Status: {}", esr::abort::dfsc_name(dfsc));

    // Print access type based on exception class
    if matches!(ec, esr::ec::DATA_ABORT_LOWER | esr::ec::DATA_ABORT_SAME) {
        log::error!(
            "  Access: {} | FAR: {}{}{}",
            if wnr { "Write" } else { "Read" },
            if fnv { "invalid" } else { "valid" },
            if s1ptw { " | S1 table walk" } else { "" },
            if cm { " | cache maintenance" } else { "" }
        );
    } else {
        log::error!(
            "  Access: Instruction fetch | FAR: {}{}",
            if fnv { "invalid" } else { "valid" },
            if s1ptw { " | S1 table walk" } else { "" }
        );
    }
}

/// Dump all general-purpose registers in a formatted layout.
fn dump_registers(ctx: &ExceptionContext) {
    console::puts("\n");
    console::puts(colour::YELLOW);
    console::puts("Registers:\n");
    console::puts(colour::RESET);

    // Print GPRs in 2-column format
    for i in (0..30).step_by(2) {
        log::error!(
            "  X{:02}: {:#018x}    X{:02}: {:#018x}",
            i,
            ctx.gpr[i],
            i + 1,
            ctx.gpr[i + 1]
        );
    }
    log::error!(
        "  X30: {:#018x}     SP: {:#018x}",
        ctx.gpr[30],
        ctx.sp
    );
}

/// Synchronous exception handler that dispatches syscalls and handles faults.
fn sync_exception_handler(ctx: &mut ExceptionContext) {
    let ec = ctx.exception_class();

    match ec {
        // System calls
        esr::ec::SVC_AARCH64 => {
            if ctx.from_el0() {
                handle_syscall(ctx);
                // Check if we need to reschedule (yield was called or timer requested it)
                if crate::sched::reschedule_pending() {
                    // Save current context (including syscall return value) before switching
                    if let Some(tcb_ref) = crate::sched::current_task() {
                        crate::sched::dispatch::save_context(tcb_ref, ctx);
                    }
                    crate::sched::dispatch::dispatch_task(ctx);
                }
                // Otherwise, just return to the same task with the syscall result
            } else {
                dump_exception_context(ctx);
                panic!("SVC from kernel mode is not supported");
            }
        }

        // Data aborts
        esr::ec::DATA_ABORT_LOWER => {
            dump_exception_context(ctx);
            // TODO: Deliver fault to thread's fault endpoint
            panic!("Unhandled user data abort");
        }

        esr::ec::DATA_ABORT_SAME => {
            dump_exception_context(ctx);
            panic!("Kernel data abort - this is a kernel bug");
        }

        // Instruction aborts
        esr::ec::INSTRUCTION_ABORT_LOWER => {
            dump_exception_context(ctx);
            // TODO: Deliver fault to thread's fault endpoint
            panic!("Unhandled user instruction abort");
        }

        esr::ec::INSTRUCTION_ABORT_SAME => {
            dump_exception_context(ctx);
            panic!("Kernel instruction abort - this is a kernel bug");
        }

        // Alignment faults
        esr::ec::PC_ALIGNMENT => {
            dump_exception_context(ctx);
            panic!("PC alignment fault at {:#x}", ctx.elr);
        }

        esr::ec::SP_ALIGNMENT => {
            dump_exception_context(ctx);
            panic!("SP alignment fault at {:#x}", ctx.elr);
        }

        // Debug exceptions
        esr::ec::BRK_AARCH64 => {
            let imm = esr::iss(ctx.esr) & 0xFFFF;
            dump_exception_context(ctx);
            panic!("BRK #{} at {:#x}", imm, ctx.elr);
        }

        esr::ec::BREAKPOINT_LOWER | esr::ec::BREAKPOINT_SAME => {
            dump_exception_context(ctx);
            panic!("Hardware breakpoint at {:#x}", ctx.elr);
        }

        esr::ec::WATCHPOINT_LOWER | esr::ec::WATCHPOINT_SAME => {
            dump_exception_context(ctx);
            panic!("Watchpoint hit, FAR={:#x}", ctx.far);
        }

        esr::ec::SOFTWARE_STEP_LOWER | esr::ec::SOFTWARE_STEP_SAME => {
            dump_exception_context(ctx);
            panic!("Software step exception at {:#x}", ctx.elr);
        }

        // Other exceptions
        esr::ec::ILLEGAL_EXECUTION => {
            dump_exception_context(ctx);
            panic!("Illegal execution state at {:#x}", ctx.elr);
        }

        esr::ec::FP_EXCEPTION => {
            dump_exception_context(ctx);
            panic!("Floating-point exception at {:#x}", ctx.elr);
        }

        esr::ec::SVE_SIMD_FP => {
            dump_exception_context(ctx);
            panic!("SVE/SIMD/FP access trapped at {:#x}", ctx.elr);
        }

        esr::ec::UNKNOWN => {
            dump_exception_context(ctx);
            panic!("Unknown exception at {:#x}", ctx.elr);
        }

        // Catch-all
        _ => {
            dump_exception_context(ctx);
            panic!(
                "Unhandled synchronous exception: {} (EC={:#04x})",
                esr::ec_name(ec),
                ec
            );
        }
    }
}
