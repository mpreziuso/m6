//! Exception Handling for ARM64
//!
//! Implements the exception vector table and handlers for:
//! - Synchronous exceptions (syscalls, faults)
//! - IRQ (interrupt requests)
//! - FIQ (fast interrupt requests)
//! - SError (system errors)

use crate::registers::{esr, write_vbar_el1};
use core::sync::atomic::{AtomicPtr, Ordering};

/// Exception context saved on the stack
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ExceptionContext {
    /// General purpose registers x0-x30
    pub gpr: [u64; 31],
    /// Stack pointer (SP_EL0 for user, current SP for kernel)
    pub sp: u64,
    /// Exception Link Register (return address)
    pub elr: u64,
    /// Saved Program Status Register
    pub spsr: u64,
    /// Exception Syndrome Register
    pub esr: u64,
    /// Fault Address Register
    pub far: u64,
}

impl ExceptionContext {
    /// Get the exception class from ESR
    #[must_use]
    pub fn exception_class(&self) -> u8 {
        esr::exception_class(self.esr)
    }

    /// Check if exception came from EL0
    #[must_use]
    pub fn from_el0(&self) -> bool {
        (self.spsr & 0x0F) == 0
    }
}

/// Exception type
///
/// These types are provided for API completeness and future use in
/// exception classification and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]  // Reserved for future exception filtering API
pub enum ExceptionType {
    /// Synchronous exception
    Sync,
    /// IRQ interrupt
    Irq,
    /// FIQ interrupt
    Fiq,
    /// System error
    SError,
}

/// Exception origin
///
/// Identifies which execution level and stack pointer the exception came from.
/// Provided for future use in exception routing and privilege checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]  // Reserved for future exception routing API
pub enum ExceptionOrigin {
    /// Same exception level, SP_EL0
    CurrentSpEl0,
    /// Same exception level, SP_ELx
    CurrentSpElx,
    /// Lower exception level, AArch64
    LowerAArch64,
    /// Lower exception level, AArch32
    LowerAArch32,
}

/// Exception handler function type
pub type ExceptionHandler = fn(&mut ExceptionContext);

/// Exception handlers using AtomicPtr for safe concurrent access
/// These are initialised with default handlers and can be updated atomically
static SYNC_HANDLER: AtomicPtr<()> = AtomicPtr::new(default_sync_handler as *mut ());
static IRQ_HANDLER: AtomicPtr<()> = AtomicPtr::new(default_irq_handler as *mut ());
static FIQ_HANDLER: AtomicPtr<()> = AtomicPtr::new(default_fiq_handler as *mut ());
static SERROR_HANDLER: AtomicPtr<()> = AtomicPtr::new(default_serror_handler as *mut ());

/// Set the synchronous exception handler
///
/// This function is safe because it uses atomic operations for the update.
/// The handler will take effect on the next synchronous exception.
pub fn set_sync_handler(handler: ExceptionHandler) {
    SYNC_HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Set the IRQ handler
///
/// This function is safe because it uses atomic operations for the update.
/// The handler will take effect on the next IRQ.
pub fn set_irq_handler(handler: ExceptionHandler) {
    IRQ_HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Set the FIQ handler
///
/// This function is safe because it uses atomic operations for the update.
/// The handler will take effect on the next FIQ.
pub fn set_fiq_handler(handler: ExceptionHandler) {
    FIQ_HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Set the SError handler
///
/// This function is safe because it uses atomic operations for the update.
/// The handler will take effect on the next SError.
pub fn set_serror_handler(handler: ExceptionHandler) {
    SERROR_HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Load an exception handler atomically
///
/// # Safety
/// The pointer must have been stored by one of the set_*_handler functions.
#[inline]
unsafe fn load_handler(handler: &AtomicPtr<()>) -> ExceptionHandler {
    let ptr = handler.load(Ordering::Acquire);
    // SAFETY: The pointer was stored as a valid function pointer
    unsafe { core::mem::transmute(ptr) }
}

/// Default synchronous exception handler
fn default_sync_handler(ctx: &mut ExceptionContext) {
    let ec = ctx.exception_class();

    match ec {
        esr::ec::SVC_AARCH64 => {
            // System call - this should be handled by a proper syscall handler
            // For now, just log it
        }
        esr::ec::DATA_ABORT_LOWER | esr::ec::DATA_ABORT_SAME => {
            // Data abort - page fault or access error
            panic!(
                "Data abort at ELR={:#x}, FAR={:#x}, ESR={:#x}",
                ctx.elr, ctx.far, ctx.esr
            );
        }
        esr::ec::INSTRUCTION_ABORT_LOWER | esr::ec::INSTRUCTION_ABORT_SAME => {
            // Instruction abort
            panic!(
                "Instruction abort at ELR={:#x}, FAR={:#x}, ESR={:#x}",
                ctx.elr, ctx.far, ctx.esr
            );
        }
        _ => {
            panic!(
                "Unhandled synchronous exception: EC={:#x}, ELR={:#x}, ESR={:#x}",
                ec, ctx.elr, ctx.esr
            );
        }
    }
}

/// Default IRQ handler
fn default_irq_handler(_ctx: &mut ExceptionContext) {
    // IRQs should be handled by the interrupt controller
    panic!("Unhandled IRQ");
}

/// Default FIQ handler
fn default_fiq_handler(_ctx: &mut ExceptionContext) {
    panic!("Unhandled FIQ");
}

/// Default SError handler
fn default_serror_handler(ctx: &mut ExceptionContext) {
    panic!("System Error at ELR={:#x}, ESR={:#x}", ctx.elr, ctx.esr);
}

/// Exception vector stub macro - fits within 128 bytes
///
/// This stub saves all context and branches to a continuation handler.
/// ARM64 exception vectors require each entry to be exactly 128 bytes.
///
/// Stack frame layout (36 * 8 = 288 bytes):
/// - x0-x30 (31 regs): offsets 0-240 (using stp pairs + str for x30)
/// - SP_EL0: offset 248 (31 * 8)
/// - ELR_EL1: offset 256 (32 * 8)
/// - SPSR_EL1: offset 264 (33 * 8)
/// - ESR_EL1: offset 272 (34 * 8)
/// - FAR_EL1: offset 280 (35 * 8)
macro_rules! exception_stub {
    ($continuation:ident) => {
        concat!(
            // Allocate 36 * 8 = 288 bytes for full exception context (1 instruction)
            "sub sp, sp, #(36 * 8)\n",
            // Save all general purpose registers (16 instructions)
            "stp x0, x1, [sp, #(0 * 16)]\n",
            "stp x2, x3, [sp, #(1 * 16)]\n",
            "stp x4, x5, [sp, #(2 * 16)]\n",
            "stp x6, x7, [sp, #(3 * 16)]\n",
            "stp x8, x9, [sp, #(4 * 16)]\n",
            "stp x10, x11, [sp, #(5 * 16)]\n",
            "stp x12, x13, [sp, #(6 * 16)]\n",
            "stp x14, x15, [sp, #(7 * 16)]\n",
            "stp x16, x17, [sp, #(8 * 16)]\n",
            "stp x18, x19, [sp, #(9 * 16)]\n",
            "stp x20, x21, [sp, #(10 * 16)]\n",
            "stp x22, x23, [sp, #(11 * 16)]\n",
            "stp x24, x25, [sp, #(12 * 16)]\n",
            "stp x26, x27, [sp, #(13 * 16)]\n",
            "stp x28, x29, [sp, #(14 * 16)]\n",
            "str x30, [sp, #(15 * 16)]\n",
            // Read system registers (5 instructions)
            "mrs x0, sp_el0\n",
            "mrs x1, elr_el1\n",
            "mrs x2, spsr_el1\n",
            "mrs x3, esr_el1\n",
            "mrs x4, far_el1\n",
            // Save system registers (3 instructions)
            "stp x0, x1, [sp, #(31 * 8)]\n",
            "stp x2, x3, [sp, #(33 * 8)]\n",
            "str x4, [sp, #(35 * 8)]\n",
            // Branch to continuation handler (1 instruction)
            // Total: 1 + 16 + 5 + 3 + 1 = 26 instructions
            "b ", stringify!($continuation), "\n",
        )
    };
}

/// Exception continuation handler macro
///
/// Called from exception_stub after context is saved.
/// Calls the Rust handler, restores context, and returns via eret.
macro_rules! exception_continuation {
    ($handler:ident) => {
        concat!(
            // Call handler with context pointer
            "mov x0, sp\n",
            "bl ", stringify!($handler), "\n",
            // Restore SP, ELR, SPSR
            "ldp x0, x1, [sp, #(31 * 8)]\n",
            "ldr x2, [sp, #(33 * 8)]\n",
            "msr sp_el0, x0\n",
            "msr elr_el1, x1\n",
            "msr spsr_el1, x2\n",
            // Restore general purpose registers
            "ldp x0, x1, [sp, #(0 * 16)]\n",
            "ldp x2, x3, [sp, #(1 * 16)]\n",
            "ldp x4, x5, [sp, #(2 * 16)]\n",
            "ldp x6, x7, [sp, #(3 * 16)]\n",
            "ldp x8, x9, [sp, #(4 * 16)]\n",
            "ldp x10, x11, [sp, #(5 * 16)]\n",
            "ldp x12, x13, [sp, #(6 * 16)]\n",
            "ldp x14, x15, [sp, #(7 * 16)]\n",
            "ldp x16, x17, [sp, #(8 * 16)]\n",
            "ldp x18, x19, [sp, #(9 * 16)]\n",
            "ldp x20, x21, [sp, #(10 * 16)]\n",
            "ldp x22, x23, [sp, #(11 * 16)]\n",
            "ldp x24, x25, [sp, #(12 * 16)]\n",
            "ldp x26, x27, [sp, #(13 * 16)]\n",
            "ldp x28, x29, [sp, #(14 * 16)]\n",
            "ldr x30, [sp, #(15 * 16)]\n",
            "add sp, sp, #(36 * 8)\n",
            "eret\n"
        )
    };
}

/// Exception handler wrappers that call the registered handlers
#[unsafe(no_mangle)]
extern "C" fn handle_sync(ctx: &mut ExceptionContext) {
    // SAFETY: Handler pointer was stored by set_sync_handler or is the default
    let handler = unsafe { load_handler(&SYNC_HANDLER) };
    handler(ctx);
}

#[unsafe(no_mangle)]
extern "C" fn handle_irq(ctx: &mut ExceptionContext) {
    // SAFETY: Handler pointer was stored by set_irq_handler or is the default
    let handler = unsafe { load_handler(&IRQ_HANDLER) };
    handler(ctx);
}

#[unsafe(no_mangle)]
extern "C" fn handle_fiq(ctx: &mut ExceptionContext) {
    // SAFETY: Handler pointer was stored by set_fiq_handler or is the default
    let handler = unsafe { load_handler(&FIQ_HANDLER) };
    handler(ctx);
}

#[unsafe(no_mangle)]
extern "C" fn handle_serror(ctx: &mut ExceptionContext) {
    // SAFETY: Handler pointer was stored by set_serror_handler or is the default
    let handler = unsafe { load_handler(&SERROR_HANDLER) };
    handler(ctx);
}

// ============================================================================
// Exception continuation handlers
//
// These are called from exception_stub after context is saved.
// They call the Rust handler, restore context, and return via eret.
// ============================================================================

/// Synchronous exception continuation handler
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __exc_sync_cont() {
    core::arch::naked_asm!(exception_continuation!(handle_sync));
}

/// IRQ continuation handler
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __exc_irq_cont() {
    core::arch::naked_asm!(exception_continuation!(handle_irq));
}

/// FIQ continuation handler
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __exc_fiq_cont() {
    core::arch::naked_asm!(exception_continuation!(handle_fiq));
}

/// SError continuation handler
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn __exc_serror_cont() {
    core::arch::naked_asm!(exception_continuation!(handle_serror));
}

/// The exception vector table
///
/// ARM64 requires the table to be 2KB aligned.
/// Each entry is 128 bytes (32 instructions).
#[repr(C, align(2048))]
pub struct ExceptionVectors {
    _data: [u8; 2048],
}

/// Exception vector table implementation
///
/// The table has 16 entries (4 exception types × 4 origin types):
/// - Current EL with SP_EL0: entries 0-3
/// - Current EL with SP_ELx: entries 4-7
/// - Lower EL (AArch64): entries 8-11
/// - Lower EL (AArch32): entries 12-15
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".vectors")]
unsafe extern "C" fn exception_vectors() {
    // SAFETY: This is a naked function that sets up the exception vector table
    core::arch::naked_asm!(
        // Align to 2KB
        ".balign 2048",

        // =====================================================
        // Current EL with SP_EL0 (not used in M6)
        // =====================================================
        // Synchronous
        ".balign 128",
        "b .",  // Hang - shouldn't happen
        // IRQ
        ".balign 128",
        "b .",
        // FIQ
        ".balign 128",
        "b .",
        // SError
        ".balign 128",
        "b .",

        // =====================================================
        // Current EL with SP_ELx (kernel mode)
        // =====================================================
        // Synchronous
        ".balign 128",
        exception_stub!(__exc_sync_cont),
        // IRQ
        ".balign 128",
        exception_stub!(__exc_irq_cont),
        // FIQ
        ".balign 128",
        exception_stub!(__exc_fiq_cont),
        // SError
        ".balign 128",
        exception_stub!(__exc_serror_cont),

        // =====================================================
        // Lower EL using AArch64 (user mode)
        // =====================================================
        // Synchronous
        ".balign 128",
        exception_stub!(__exc_sync_cont),
        // IRQ
        ".balign 128",
        exception_stub!(__exc_irq_cont),
        // FIQ
        ".balign 128",
        exception_stub!(__exc_fiq_cont),
        // SError
        ".balign 128",
        exception_stub!(__exc_serror_cont),

        // =====================================================
        // Lower EL using AArch32 (not supported)
        // =====================================================
        // Synchronous
        ".balign 128",
        "b .",
        // IRQ
        ".balign 128",
        "b .",
        // FIQ
        ".balign 128",
        "b .",
        // SError
        ".balign 128",
        "b .",
    );
}

/// Initialise the exception vector table
///
pub fn init() {
    let vectors = exception_vectors as *const () as u64;
    write_vbar_el1(vectors);
}

/// Get the current exception vector table address
#[must_use]
pub fn vector_table_address() -> u64 {
    crate::registers::read_vbar_el1()
}
