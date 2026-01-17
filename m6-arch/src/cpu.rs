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
        // SAFETY: Caller guarantees we're at EL2
        unsafe {
            asm!(
                "msr hcr_el2, {val}",
                val = in(reg) hcr::RW | hcr::SWIO,
                options(nomem, nostack)
            );
        }
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
        // SAFETY: Caller guarantees we're at EL2
        unsafe {
            asm!(
                // CNTHCTL_EL2: EL1PCEN=1, EL1PCTEN=1 (bits 1:0)
                "mov {tmp}, #3",
                "msr cnthctl_el2, {tmp}",
                // CNTVOFF_EL2: No offset between physical and virtual counters
                "msr cntvoff_el2, xzr",
                tmp = out(reg) _,
                options(nomem, nostack)
            );
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
        // SAFETY: Caller guarantees we're at EL2 with GICv3
        unsafe {
            asm!(
                // ICC_SRE_EL2: SRE=1 (enable), Enable=1 (allow EL1 access)
                "mov {tmp}, #0xf",
                "msr icc_sre_el2, {tmp}",
                "isb",
                tmp = out(reg) _,
                options(nomem, nostack)
            );
        }
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
        // SAFETY: Caller guarantees we're at EL2 and addr is valid code
        unsafe {
            asm!(
                "msr elr_el2, {addr}",
                addr = in(reg) addr,
                options(nomem, nostack)
            );
        }
    }

    /// Set SP_EL1 (stack pointer for EL1)
    ///
    /// # Safety
    /// Must be called from EL2 with a valid, aligned stack address.
    #[inline]
    pub unsafe fn set_sp_el1(sp: u64) {
        // SAFETY: Caller guarantees we're at EL2 and sp is valid stack
        unsafe {
            asm!(
                "msr sp_el1, {sp}",
                sp = in(reg) sp,
                options(nomem, nostack)
            );
        }
    }
}
