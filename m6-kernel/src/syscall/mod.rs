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

pub mod error;
pub mod numbers;

use m6_arch::exceptions::ExceptionContext;
use m6_arch::registers::esr;
use m6_pal::console;

use error::{SyscallError, SyscallResult, to_return_value};
use numbers::Syscall;

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
    _ctx: &mut ExceptionContext,
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
        // IPC operations (stubs for now)
        Syscall::Send => todo_syscall("Send"),
        Syscall::Recv => todo_syscall("Recv"),
        Syscall::Call => todo_syscall("Call"),
        Syscall::ReplyRecv => todo_syscall("ReplyRecv"),
        Syscall::NBSend => todo_syscall("NBSend"),
        Syscall::NBRecv => todo_syscall("NBRecv"),
        Syscall::Yield => {
            // TODO: Yield to scheduler
            Ok(0)
        }

        // Notification operations (stubs)
        Syscall::Signal => todo_syscall("Signal"),
        Syscall::Wait => todo_syscall("Wait"),
        Syscall::Poll => todo_syscall("Poll"),

        // Capability operations (stubs)
        Syscall::CapCopy => todo_syscall("CapCopy"),
        Syscall::CapMove => todo_syscall("CapMove"),
        Syscall::CapMint => todo_syscall("CapMint"),
        Syscall::CapDelete => todo_syscall("CapDelete"),
        Syscall::CapRevoke => todo_syscall("CapRevoke"),
        Syscall::CapMutate => todo_syscall("CapMutate"),
        Syscall::CapRotate => todo_syscall("CapRotate"),

        // Object invocation (stub)
        Syscall::Invoke => todo_syscall("Invoke"),

        // Memory operations (stubs)
        Syscall::Retype => todo_syscall("Retype"),
        Syscall::MapFrame => todo_syscall("MapFrame"),
        Syscall::UnmapFrame => todo_syscall("UnmapFrame"),
        Syscall::MapPageTable => todo_syscall("MapPageTable"),

        // TCB operations (stubs)
        Syscall::TcbConfigure => todo_syscall("TcbConfigure"),
        Syscall::TcbWriteRegisters => todo_syscall("TcbWriteRegisters"),
        Syscall::TcbReadRegisters => todo_syscall("TcbReadRegisters"),
        Syscall::TcbResume => todo_syscall("TcbResume"),
        Syscall::TcbSuspend => todo_syscall("TcbSuspend"),
        Syscall::TcbSetPriority => todo_syscall("TcbSetPriority"),
        Syscall::TcbBindNotification => todo_syscall("TcbBindNotification"),

        // IRQ operations (stubs)
        Syscall::IrqAck => todo_syscall("IrqAck"),
        Syscall::IrqSetHandler => todo_syscall("IrqSetHandler"),
        Syscall::IrqClearHandler => todo_syscall("IrqClearHandler"),

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

/// Install the syscall handler.
///
/// This hooks the synchronous exception handler to dispatch syscalls.
pub fn init() {
    m6_arch::exceptions::set_sync_handler(sync_exception_handler);
    log::info!("Syscall handler installed");
}

/// Synchronous exception handler that dispatches syscalls.
fn sync_exception_handler(ctx: &mut ExceptionContext) {
    let ec = ctx.exception_class();

    match ec {
        esr::ec::SVC_AARCH64 => {
            // Syscall from EL0
            if ctx.from_el0() {
                handle_syscall(ctx);
            } else {
                // SVC from kernel mode - should not happen in normal operation
                log::error!("SVC from kernel mode at ELR={:#x}", ctx.elr);
                panic!("Kernel-mode syscall not supported");
            }
        }

        esr::ec::DATA_ABORT_LOWER => {
            // Data abort from EL0
            log::error!(
                "Data abort from user at FAR={:#x}, ELR={:#x}",
                ctx.far,
                ctx.elr
            );
            // TODO: Deliver fault to fault endpoint
            panic!("Unhandled user data abort");
        }

        esr::ec::INSTRUCTION_ABORT_LOWER => {
            // Instruction abort from EL0
            log::error!(
                "Instruction abort from user at FAR={:#x}, ELR={:#x}",
                ctx.far,
                ctx.elr
            );
            // TODO: Deliver fault to fault endpoint
            panic!("Unhandled user instruction abort");
        }

        esr::ec::DATA_ABORT_SAME => {
            // Data abort from kernel
            log::error!(
                "Kernel data abort at FAR={:#x}, ELR={:#x}",
                ctx.far,
                ctx.elr
            );
            panic!("Kernel data abort");
        }

        esr::ec::INSTRUCTION_ABORT_SAME => {
            // Instruction abort from kernel
            log::error!(
                "Kernel instruction abort at FAR={:#x}, ELR={:#x}",
                ctx.far,
                ctx.elr
            );
            panic!("Kernel instruction abort");
        }

        _ => {
            log::error!(
                "Unhandled sync exception EC={:#x} at ELR={:#x}",
                ec,
                ctx.elr
            );
            panic!("Unhandled synchronous exception");
        }
    }
}
