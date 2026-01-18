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

/// Check if currently running at EL2
#[must_use]
pub fn is_el2() -> bool {
    current_el() == 2
}

/// Check if currently running at EL1
#[must_use]
pub fn is_el1() -> bool {
    current_el() == 1
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
    // FPEN bits [21:20] = 0b11
    CPACR_EL1.modify(CPACR_EL1::FPEN::TrapNothing);
    // SAFETY: ISB is always safe
    unsafe { asm!("isb", options(nostack)); }
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

/// Read a random value from the hardware RNG (ARMv8.5-RNG).
///
/// Returns `Some(value)` if successful, or `None` if:
/// - Hardware RNG is not supported
/// - Entropy pool is temporarily exhausted
///
/// Use `features::has_rng()` to check for support beforehand.
#[inline]
pub fn read_random() -> Option<u64> {
    // First check if the CPU supports RNDR
    if !features::has_rng() {
        return None;
    }

    let val: u64;
    let success: u64;

    // SAFETY: RNDR is a safe read-only register, and we've verified support.
    unsafe {
        asm!(
            "mrs {val}, s3_3_c2_c4_0",  // RNDR encoding
            "cset {success}, ne",        // Success if Z flag not set
            val = out(reg) val,
            success = out(reg) success,
            options(nomem, nostack)
        );
    }

    if success != 0 { Some(val) } else { None }
}

/// Physical Address Range detection
pub mod pa_range {
    use aarch64_cpu::registers::{ID_AA64MMFR0_EL1, Readable};

    /// Get the physical address range supported by this CPU.
    ///
    /// Returns the PARange value from ID_AA64MMFR0_EL1 (bits 3:0):
    /// - 0 = 32-bit (4 GB)
    /// - 1 = 36-bit (64 GB)
    /// - 2 = 40-bit (1 TB)
    /// - 3 = 42-bit (4 TB)
    /// - 4 = 44-bit (16 TB)
    /// - 5 = 48-bit (256 TB)
    /// - 6 = 52-bit (4 PB, requires LPA)
    #[must_use]
    pub fn pa_range() -> u64 {
        ID_AA64MMFR0_EL1.read(ID_AA64MMFR0_EL1::PARange)
    }

    /// Get the TCR IPS field value for the CPU's physical address capability.
    ///
    /// The PARange value maps directly to TCR.IPS encoding.
    /// Clamps to 48-bit maximum (we don't support 52-bit LPA yet).
    #[must_use]
    pub fn tcr_ips() -> u64 {
        pa_range().min(5)
    }

    /// Get the number of physical address bits supported.
    #[must_use]
    pub fn pa_bits() -> u8 {
        match pa_range() {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            6 => 52,
            _ => 32, // Conservative fallback
        }
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

/// EL2 (Hypervisor) configuration for dropping to EL1
///
/// These functions are used during boot when the UEFI firmware leaves
/// the CPU at EL2 (e.g., Rock 5B+). They configure EL2 state to allow
/// clean transition to EL1 where the kernel runs.
pub mod el2 {
    use core::arch::asm;

    /// HCR_EL2 bit definitions
    pub mod hcr {
        /// RW bit: EL1 is AArch64 (not AArch32)
        pub const RW: u64 = 1 << 31;
        /// SWIO bit: Set/Way Invalidation Override
        pub const SWIO: u64 = 1 << 1;
    }

    /// SPSR_EL2 value for returning to EL1h with interrupts masked
    /// D=1, A=1, I=1, F=1 (all masked), M=0b0101 (EL1h)
    pub const SPSR_EL1H_MASKED: u64 = 0x3c5;

    /// Configure HCR_EL2 for EL1 execution
    ///
    /// Sets RW=1 to indicate EL1 is AArch64, and SWIO=1 for cache ops.
    ///
    /// # Safety
    /// Must be called from EL2. Calling from other ELs will fault.
    #[inline]
    pub unsafe fn configure_hcr_for_el1() {
        use aarch64_cpu::registers::{HCR_EL2, Writeable};
        HCR_EL2.write(HCR_EL2::RW::EL1IsAarch64 + HCR_EL2::SWIO::SET);
    }

    /// Enable EL1 access to physical timer and counter
    ///
    /// Configures CNTHCTL_EL2 to allow EL1 to access the physical
    /// timer registers without trapping to EL2.
    ///
    /// # Safety
    /// Must be called from EL2. Calling from other ELs will fault.
    #[inline]
    pub unsafe fn enable_el1_timer_access() {
        use aarch64_cpu::registers::{CNTHCTL_EL2, Writeable};
        // EL1PCEN=1, EL1PCTEN=1 (bits 1:0)
        CNTHCTL_EL2.write(CNTHCTL_EL2::EL1PCTEN::SET + CNTHCTL_EL2::EL1PCEN::SET);
        // CNTVOFF_EL2: No offset between physical and virtual counters
        // Note: CNTVOFF_EL2 is not yet available in aarch64-cpu crate
        unsafe {
            asm!("msr cntvoff_el2, xzr", options(nomem, nostack));
        }
    }

    /// Disable EL2 trapping of GIC system registers
    ///
    /// Configures ICC_SRE_EL2 to allow EL1 to use the GICv3 system
    /// register interface directly.
    ///
    /// # Safety
    /// Must be called from EL2 on a system with GICv3.
    #[inline]
    pub unsafe fn enable_el1_gic_access() {
        use aarch64_cpu::registers::{ICC_SRE_EL2, Writeable};
        // SRE=1 (enable), ENABLE=1 (allow EL1 access)
        // Both fields use raw values as aarch64-cpu doesn't define named variants
        ICC_SRE_EL2.write(ICC_SRE_EL2::SRE.val(1) + ICC_SRE_EL2::ENABLE.val(1));
        // SAFETY: ISB is always safe
        unsafe { asm!("isb", options(nostack)); }
    }

    /// Set SPSR_EL2 for return to EL1h with interrupts masked
    ///
    /// # Safety
    /// Must be called from EL2 before executing ERET.
    #[inline]
    pub unsafe fn set_spsr_for_el1h() {
        // SAFETY: Caller guarantees we're at EL2
        unsafe {
            asm!(
                "msr spsr_el2, {val}",
                val = in(reg) SPSR_EL1H_MASKED,
                options(nomem, nostack)
            );
        }
    }

    /// Set ELR_EL2 (return address for ERET)
    ///
    /// # Safety
    /// Must be called from EL2 with a valid code address.
    #[inline]
    pub unsafe fn set_elr(addr: u64) {
        use aarch64_cpu::registers::{ELR_EL2, Writeable};
        ELR_EL2.set(addr);
    }

    /// Set SP_EL1 (stack pointer for EL1)
    ///
    /// # Safety
    /// Must be called from EL2 with a valid, aligned stack address.
    #[inline]
    pub unsafe fn set_sp_el1(sp: u64) {
        use aarch64_cpu::registers::{SP_EL1, Writeable};
        SP_EL1.set(sp);
    }

    /// Disable all coprocessor trapping to EL2
    ///
    /// Clears CPTR_EL2 to prevent FP/SIMD, trace, and other coprocessor
    /// accesses from trapping to EL2. Without this, FP/SIMD instructions
    /// at EL1 would trap to EL2 with no valid handler after ERET.
    ///
    /// # Safety
    /// Must be called from EL2. Calling from other ELs will fault.
    #[inline]
    pub unsafe fn disable_coprocessor_traps() {
        use aarch64_cpu::registers::{CPTR_EL2, Writeable};
        CPTR_EL2.set(0);
    }

    /// Disable system register trapping to EL2
    ///
    /// Clears HSTR_EL2 to prevent system register accesses from
    /// trapping to EL2.
    ///
    /// # Safety
    /// Must be called from EL2. Calling from other ELs will fault.
    #[inline]
    pub unsafe fn disable_sysreg_traps() {
        // SAFETY: Caller guarantees we're at EL2
        // Note: HSTR_EL2 is not yet available in aarch64-cpu crate
        unsafe {
            asm!(
                "msr hstr_el2, xzr",
                options(nomem, nostack)
            );
        }
    }

    /// Disable debug and PMU trapping to EL2
    ///
    /// Clears MDCR_EL2 to allow EL1 debug and PMU access without
    /// trapping to EL2.
    ///
    /// # Safety
    /// Must be called from EL2. Calling from other ELs will fault.
    #[inline]
    pub unsafe fn disable_debug_traps() {
        use aarch64_cpu::registers::{MDCR_EL2, Writeable};
        MDCR_EL2.set(0);
    }
}
