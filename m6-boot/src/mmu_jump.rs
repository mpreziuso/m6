//! MMU enable and kernel jump routine for ARM64
//!
//! This file contains the low-level function to enable the MMU and jump to the kernel entry point.
//! Supports both EL1 (QEMU) and EL2 (Rock 5B+) boot scenarios.

use core::arch::asm;
use m6_boot::page_table::{MAIR_VALUE, TCR_VALUE};

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
            tcr = in(reg) TCR_VALUE,
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

    // SAFETY: This is the final step of the bootloader from EL2
    unsafe {
        asm!(
            // Disable interrupts at EL2
            "msr daifset, #0xf",

            // -- Configure EL2 for EL1 execution --

            // HCR_EL2: RW=1 (EL1 is AArch64), SWIO=1 (cache ops work)
            "mov x9, #(1 << 31)",     // RW bit
            "orr x9, x9, #(1 << 1)",  // SWIO bit
            "msr hcr_el2, x9",

            // Enable EL1 timer access from EL2
            // CNTHCTL_EL2: EL1PCEN=1, EL1PCTEN=1
            "mov x9, #3",
            "msr cnthctl_el2, x9",
            // No offset between physical and virtual counters
            "msr cntvoff_el2, xzr",

            // Enable EL1 GIC access (GICv3 system registers)
            // ICC_SRE_EL2: SRE=1, Enable=1
            "mov x9, #0xf",
            "msr s3_4_c12_c9_5, x9",  // ICC_SRE_EL2 encoding
            "isb",

            // -- Configure EL1 registers (will take effect after ERET) --

            // Set up MAIR_EL1
            "msr mair_el1, {mair}",

            // Set up TCR_EL1
            "msr tcr_el1, {tcr}",

            // Set up TTBR0_EL1 (identity mapping)
            "msr ttbr0_el1, {ttbr0}",

            // Set up TTBR1_EL1 (kernel mapping)
            "msr ttbr1_el1, {ttbr1}",

            // Ensure all writes complete
            "dsb sy",
            "isb",

            // Invalidate TLB (using EL1 TLB invalidate since we're setting up EL1)
            "tlbi vmalle1",
            "dsb sy",
            "isb",

            // Invalidate instruction cache
            "ic iallu",
            "dsb sy",
            "isb",

            // Set up SCTLR_EL1 with MMU enabled
            // M=1 (MMU), C=1 (data cache), I=1 (instruction cache)
            "mov x9, #0",
            "orr x9, x9, #1",         // M bit
            "orr x9, x9, #(1 << 2)",  // C bit
            "orr x9, x9, #(1 << 12)", // I bit
            "msr sctlr_el1, x9",

            // Set up SP_EL1 for kernel stack
            "msr sp_el1, {stack}",

            // -- Prepare for ERET to EL1 --

            // SPSR_EL2: Return to EL1h with all interrupts masked
            // D=1, A=1, I=1, F=1 (bits 9,8,7,6), M=0b0101 (EL1h)
            "mov x9, #0x3c5",
            "msr spsr_el2, x9",

            // ELR_EL2: Return address is kernel entry point
            "msr elr_el2, {entry}",

            // Set up x0 with boot_info for kernel
            "mov x0, {boot_info}",

            // Clear other argument registers for cleanliness
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",

            // Return to EL1
            "eret",

            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) TCR_VALUE,
            ttbr0 = in(reg) ttbr0_masked,
            ttbr1 = in(reg) ttbr1,
            boot_info = in(reg) boot_info,
            stack = in(reg) stack_top,
            entry = in(reg) kernel_entry,
            options(noreturn)
        );
    }
}
