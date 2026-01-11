//! CPU Control and Information
//!
//! Low-level CPU operations and information retrieval.

use aarch64_cpu::registers::*;
use core::arch::asm;

/// Get the current CPU ID (MPIDR_EL1 Aff0 field)
#[must_use]
pub fn cpu_id() -> usize {
    (MPIDR_EL1.get() & 0xFF) as usize
}

/// Get the current exception level
#[must_use]
pub fn current_el() -> u8 {
    ((CurrentEL.get() >> 2) & 0x3) as u8
}

/// Halt the CPU (spin loop)
#[inline]
pub fn halt() -> ! {
    loop {
        wait_for_interrupt();
    }
}

/// Wait for interrupt (WFI instruction)
#[inline]
pub fn wait_for_interrupt() {
    // SAFETY: WFI is always safe to call
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

/// Wait for event (WFE instruction)
#[inline]
pub fn wait_for_event() {
    // SAFETY: WFE is always safe to call
    unsafe {
        asm!("wfe", options(nomem, nostack));
    }
}

/// Send event (SEV instruction)
#[inline]
pub fn send_event() {
    // SAFETY: SEV is always safe to call
    unsafe {
        asm!("sev", options(nomem, nostack));
    }
}

/// Data synchronization barrier
#[inline]
pub fn dsb_sy() {
    // SAFETY: Memory barrier is always safe
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

/// Instruction synchronization barrier
#[inline]
pub fn isb() {
    // SAFETY: ISB is always safe
    unsafe {
        asm!("isb", options(nostack));
    }
}

/// Enable FP/SIMD access at EL0 and EL1
///
/// Sets CPACR_EL1.FPEN = 0b11 to allow FP/SIMD instructions.
/// This must be called on each CPU before any FP/SIMD code runs.
#[inline]
pub fn enable_fp_simd() {
    // SAFETY: Enabling FP/SIMD access is safe in kernel mode
    unsafe {
        asm!(
            "mrs {tmp}, cpacr_el1",
            "orr {tmp}, {tmp}, #(3 << 20)", // FPEN bits [21:20] = 0b11
            "msr cpacr_el1, {tmp}",
            "isb",
            tmp = out(reg) _,
            options(nomem, nostack)
        );
    }
}

/// Data memory barrier
#[inline]
pub fn dmb_sy() {
    // SAFETY: Memory barrier is always safe
    unsafe {
        asm!("dmb sy", options(nostack));
    }
}

/// Disable all interrupts and return previous state
#[must_use]
#[inline]
pub fn disable_interrupts() -> u64 {
    let daif = DAIF.get();
    // SAFETY: Reading and modifying DAIF is safe in kernel mode
    unsafe {
        asm!("msr daifset, #0xf", options(nomem, nostack));
    }
    daif
}

/// Enable all interrupts
#[inline]
pub fn enable_interrupts() {
    // SAFETY: Modifying DAIF is safe in kernel mode
    unsafe {
        asm!("msr daifclr, #0xf", options(nomem, nostack));
    }
}

/// Restore interrupt state
#[inline]
pub fn restore_interrupts(daif: u64) {
    DAIF.set(daif);
}

/// Check if interrupts are enabled
#[must_use]
pub fn interrupts_enabled() -> bool {
    let daif = DAIF.get();
    // Check if IRQ and FIQ bits are clear (interrupts enabled)
    (daif & 0xC0) == 0
}

/// Invalidate instruction cache
#[inline]
pub fn invalidate_icache() {
    // SAFETY: Cache operations are safe
    unsafe {
        asm!("ic iallu", "dsb sy", "isb", options(nostack));
    }
}

/// Clean and invalidate data cache by virtual address
#[inline]
pub fn clean_invalidate_dcache_line(addr: usize) {
    // SAFETY: Cache operations are safe
    unsafe {
        asm!(
            "dc civac, {}",
            in(reg) addr,
            options(nostack)
        );
    }
}

/// CPU feature detection
pub mod features {
    use aarch64_cpu::registers::Readable;
    use aarch64_cpu::registers::*;

    /// Check if MTE (Memory Tagging Extension) is supported
    pub fn has_mte() -> bool {
        ID_AA64PFR1_EL1.read(ID_AA64PFR1_EL1::MTE) >= 1
    }

    /// Check if SVE (Scalable Vector Extension) is supported
    pub fn has_sve() -> bool {
        ID_AA64PFR0_EL1.read(ID_AA64PFR0_EL1::SVE) >= 1
    }

    /// Check if PAC (Pointer Authentication) is supported
    pub fn has_pac() -> bool {
        ID_AA64ISAR1_EL1.read(ID_AA64ISAR1_EL1::APA) != 0
            || ID_AA64ISAR1_EL1.read(ID_AA64ISAR1_EL1::API) != 0
            || ID_AA64ISAR1_EL1.read(ID_AA64ISAR1_EL1::GPA) != 0
            || ID_AA64ISAR1_EL1.read(ID_AA64ISAR1_EL1::GPI) != 0
    }

    /// Check if BTI (Branch Target Identification) is supported
    pub fn has_bti() -> bool {
        (ID_AA64PFR1_EL1.get() & 0xF) >= 1
    }

    /// Check if hardware RNG is available
    pub fn has_rng() -> bool {
        ID_AA64ISAR0_EL1.read(ID_AA64ISAR0_EL1::RNDR) >= 1
    }

    /// Check if AES instructions are available
    pub fn has_aes() -> bool {
        (ID_AA64ISAR0_EL1.get() >> 4) & 0xF >= 1
    }

    /// Check if SHA instructions are available
    pub fn has_sha() -> bool {
        let id = ID_AA64ISAR0_EL1.get();
        ((id >> 8) & 0xF >= 1) || ((id >> 12) & 0xF >= 1)
    }
}
