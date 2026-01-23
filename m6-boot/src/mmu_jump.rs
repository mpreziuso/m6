//! MMU enable and kernel jump routine for ARM64
//!
//! This file contains the low-level function to enable the MMU and jump to the kernel entry point.
//! Supports both EL1 (QEMU) and EL2 (Rock 5B+) boot scenarios.

use core::arch::asm;
use m6_boot::page_table::{MAIR_VALUE, tcr_value};

/// Enable MMU with the prepared page tables and jump to kernel
///
/// This function handles both EL1 and EL2 boot scenarios:
/// - On QEMU virt: UEFI leaves us at EL1, so we configure EL1 directly
/// - On Rock 5B+: UEFI leaves us at EL2, so we configure EL2 then drop to EL1
///
/// # Safety
/// This function never returns. The page tables must be correctly set up.
/// The stack_top must point to a valid, mapped kernel stack.
#[inline(never)]
pub unsafe fn enable_mmu_and_jump(
    ttbr1: u64,
    ttbr0: u64,
    kernel_entry: u64,
    boot_info: u64,
    stack_top: u64,
) -> ! {
    let current_el = m6_arch::cpu::current_el();

    if current_el == 2 {
        // Rock 5B+ path: UEFI left us at EL2
        // SAFETY: We've verified we're at EL2, page tables are set up
        unsafe {
            enable_mmu_and_jump_from_el2(ttbr1, ttbr0, kernel_entry, boot_info, stack_top);
        }
    } else {
        // QEMU virt path: UEFI left us at EL1
        // SAFETY: We're at EL1, page tables are set up
        unsafe {
            enable_mmu_and_jump_from_el1(ttbr1, ttbr0, kernel_entry, boot_info, stack_top);
        }
    }
}

/// Enable MMU and jump to kernel from EL1
///
/// This is the original path used when UEFI starts us at EL1 (QEMU virt).
///
/// # Safety
/// Must be called from EL1 with valid page tables.
#[inline(never)]
unsafe fn enable_mmu_and_jump_from_el1(
    ttbr1: u64,
    ttbr0: u64,
    kernel_entry: u64,
    boot_info: u64,
    stack_top: u64,
) -> ! {
    // Clear ASID bits from TTBR0
    let ttbr0_masked = ttbr0 & 0x0000_FFFF_FFFF_FFFF;

    // Get TCR value with correct IPS for this CPU
    let tcr = tcr_value();

    // SAFETY: This is the final step of the bootloader from EL1
    unsafe {
        asm!(
            // Disable interrupts
            "msr daifset, #0xf",

            // Set up MAIR (Memory Attribute Indirection Register)
            "msr mair_el1, {mair}",

            // Set up TCR (Translation Control Register)
            "msr tcr_el1, {tcr}",

            // Set up TTBR0 (identity mapping for transition, ASID already cleared)
            "msr ttbr0_el1, {ttbr0}",

            // Set up TTBR1 (kernel mapping)
            "msr ttbr1_el1, {ttbr1}",

            // Ensure all writes complete before proceeding
            "dsb sy",
            "isb",

            // Invalidate TLB
            "tlbi vmalle1",
            "dsb sy",
            "isb",

            // Invalidate instruction cache before enabling MMU
            "ic iallu",
            "dsb sy",
            "isb",

            // Enable MMU using x9 as temp register
            "mrs x9, sctlr_el1",
            "orr x9, x9, #1",         // M bit (MMU enable)
            "orr x9, x9, #(1 << 2)",  // C bit (data cache)
            "orr x9, x9, #(1 << 12)", // I bit (instruction cache)
            "orr x9, x9, #(1 << 26)", // UCI bit (user cache instructions)
            "msr sctlr_el1, x9",
            "isb",

            // Switch to using SP_EL1 for kernel stack
            "msr spsel, #1",

            // Set up stack pointer to kernel stack (virtual address)
            "mov sp, {stack}",

            // Set up arguments and jump to kernel
            "mov x0, {boot_info}",

            // Jump to kernel entry
            "br {entry}",

            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) tcr,
            ttbr0 = in(reg) ttbr0_masked,
            ttbr1 = in(reg) ttbr1,
            boot_info = in(reg) boot_info,
            stack = in(reg) stack_top,
            entry = in(reg) kernel_entry,
            options(noreturn)
        );
    }
}

/// Enable MMU and jump to kernel from EL2
///
/// This path is used when UEFI starts us at EL2 (Rock 5B+).
/// We configure EL2 to allow EL1 execution, set up EL1 registers,
/// then use ERET to drop to EL1 with MMU enabled.
///
/// # Safety
/// Must be called from EL2 with valid page tables.
#[inline(never)]
unsafe fn enable_mmu_and_jump_from_el2(
    ttbr1: u64,
    ttbr0: u64,
    kernel_entry: u64,
    boot_info: u64,
    stack_top: u64,
) -> ! {
    // Clear ASID bits from TTBR0
    let ttbr0_masked = ttbr0 & 0x0000_FFFF_FFFF_FFFF;

    // Get TCR value with correct IPS for this CPU
    let tcr = tcr_value();

    // SAFETY: This is the final step of the bootloader from EL2
    unsafe {
        asm!(
            // ============================================================
            // CRITICAL: Save ALL input operands to callee-saved registers
            // IMMEDIATELY, before using ANY scratch registers.
            // The compiler may allocate in(reg) operands to x9-x17.
            // ============================================================
            "mov x19, {ttbr0}",
            "mov x20, {ttbr1}",
            "mov x21, {mair}",
            "mov x22, {tcr}",
            "mov x23, {boot_info}",
            "mov x24, {stack}",
            "mov x25, {entry}",

            // Now safe to use x9-x17 as scratch registers

            // Disable interrupts at EL2
            "msr daifset, #0xf",

            // Configure HCR_EL2 to disable trapping before writing EL1 regs
            // UEFI may have TVM=1 (trap virtual memory controls) set
            "mov x9, #(1 << 31)",     // RW bit (EL1 is AArch64)
            "orr x9, x9, #(1 << 1)",  // SWIO bit
            "msr hcr_el2, x9",

            // Disable all coprocessor/sysreg trapping
            "msr cptr_el2, xzr",
            "msr hstr_el2, xzr",
            "msr mdcr_el2, xzr",
            "isb",

            // Set up EL1 MMU registers (from saved callee-saved regs)
            "msr ttbr0_el1, x19",     // TTBR0 from x19
            "msr ttbr1_el1, x20",     // TTBR1 from x20
            "msr mair_el1, x21",      // MAIR from x21
            "msr tcr_el1, x22",       // TCR from x22
            "isb",

            // Disable EL2 MMU if UEFI left it enabled
            "mrs x9, sctlr_el2",
            "bic x9, x9, #1",         // Clear M bit
            "msr sctlr_el2, x9",
            "isb",
            "dsb sy",

            // Enable EL1 timer access
            "mov x9, #3",
            "msr cnthctl_el2, x9",
            "msr cntvoff_el2, xzr",

            // Enable EL1 GIC access (ICC_SRE_EL2)
            "mov x9, #0xf",
            "msr s3_4_c12_c9_5, x9",
            "isb",

            // Enable FP/SIMD at EL1
            "mov x9, #(3 << 20)",
            "msr cpacr_el1, x9",
            "isb",

            "dsb sy",

            // Invalidate TLB
            "tlbi vmalle1",
            "dsb sy",
            "isb",

            // Invalidate I-cache
            "ic iallu",
            "dsb sy",
            "isb",

            // Set up SCTLR_EL1 with MMU enabled + RES1 bits + UCI
            "movz x9, #0x1805",
            "movk x9, #0x34C5, lsl #16",    // 0x34C5 includes UCI (bit 26)
            "msr sctlr_el1, x9",
            "isb",

            // Set up SP_EL1 from saved register
            "msr sp_el1, x24",        // stack from x24

            // -- Prepare for ERET --

            // SPSR_EL2: Return to EL1h with interrupts masked
            "mov x9, #0x3c5",
            "msr spsr_el2, x9",

            // ELR_EL2: Return address is kernel entry
            "msr elr_el2, x25",       // entry from x25

            // Set up x0 with boot_info
            "mov x0, x23",            // boot_info from x23

            // Clear other argument registers
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",

            // ERET to EL1
            "eret",

            ttbr0 = in(reg) ttbr0_masked,
            ttbr1 = in(reg) ttbr1,
            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) tcr,
            boot_info = in(reg) boot_info,
            stack = in(reg) stack_top,
            entry = in(reg) kernel_entry,
            options(noreturn)
        );
    }
}
