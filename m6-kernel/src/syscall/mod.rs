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
use m6_arch::registers::{esr, spsr};
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
                crate::sched::dispatch::dispatch_task(ctx);
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
