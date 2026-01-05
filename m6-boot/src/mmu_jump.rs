//! MMU enable and kernel jump routine for ARM64
//!
//! This file contains the low-level function to enable the MMU and jump to the kernel entry point.

use core::arch::asm;
use m6_boot::page_table::{MAIR_VALUE, TCR_VALUE};

/// Enable MMU with the prepared page tables and jump to kernel
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
    // Clear ASID bits from TTBR0 before passing to asm (can't use inout with noreturn)
    let ttbr0_masked = ttbr0 & 0x0000_FFFF_FFFF_FFFF;

    // SAFETY: This is the final step of the bootloader
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
            // DSB must come before ISB per ARM ARM
            "dsb sy",
            "isb",

            // Invalidate TLB
            "tlbi vmalle1",
            "dsb sy",
            "isb",

            // Invalidate instruction cache before enabling MMU
            // This ensures no stale instructions are executed
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

            // Set up stack pointer to kernel stack (virtual address)
            // Stack must be 16-byte aligned per AArch64 ABI
            "mov sp, {stack}",

            // Set up arguments and jump to kernel
            // x0 = boot_info pointer
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
