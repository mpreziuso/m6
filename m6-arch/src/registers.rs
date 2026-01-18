//! System Register Definitions
//!
//! Additional register definitions and helpers not covered by aarch64-cpu.

use aarch64_cpu::registers::{
    ELR_EL1, ESR_EL1, FAR_EL1, SP_EL0, SPSR_EL1, TPIDR_EL0, TPIDR_EL1, TTBR1_EL1, VBAR_EL1,
};
use tock_registers::interfaces::{Readable, Writeable};

/// Read VBAR_EL1 (Vector Base Address Register)
#[must_use]
#[inline]
pub fn read_vbar_el1() -> u64 {
    VBAR_EL1.get()
}

/// Write VBAR_EL1 (Vector Base Address Register)
///
/// # Safety
/// The address must point to a valid exception vector table.
#[inline]
pub fn write_vbar_el1(value: u64) {
    VBAR_EL1.set(value);
}

/// Read SP_EL0
#[must_use]
#[inline]
pub fn read_sp_el0() -> u64 {
    SP_EL0.get()
}

/// Write SP_EL0
#[inline]
pub fn write_sp_el0(value: u64) {
    SP_EL0.set(value);
}

/// Read TPIDR_EL0 (Thread Pointer ID Register for EL0)
#[must_use]
#[inline]
pub fn read_tpidr_el0() -> u64 {
    TPIDR_EL0.get()
}

/// Write TPIDR_EL0
#[inline]
pub fn write_tpidr_el0(value: u64) {
    TPIDR_EL0.set(value);
}

/// Read TPIDR_EL1 (Thread Pointer ID Register for EL1 - kernel use)
#[must_use]
#[inline]
pub fn read_tpidr_el1() -> u64 {
    TPIDR_EL1.get()
}

/// Write TPIDR_EL1
#[inline]
pub fn write_tpidr_el1(value: u64) {
    TPIDR_EL1.set(value);
}

/// Read ESR_EL1 (Exception Syndrome Register)
#[must_use]
#[inline]
pub fn read_esr_el1() -> u64 {
    ESR_EL1.get()
}

/// Read ELR_EL1 (Exception Link Register)
#[must_use]
#[inline]
pub fn read_elr_el1() -> u64 {
    ELR_EL1.get()
}

/// Read FAR_EL1 (Fault Address Register)
#[must_use]
#[inline]
pub fn read_far_el1() -> u64 {
    FAR_EL1.get()
}

/// Read SPSR_EL1 (Saved Program Status Register)
#[must_use]
#[inline]
pub fn read_spsr_el1() -> u64 {
    SPSR_EL1.get()
}

/// Read TTBR1_EL1 (Translation Table Base Register 1)
///
/// Returns the physical address of the L0 page table for kernel space (TTBR1).
/// The BADDR field contains the physical address, masked by TCR_EL1 settings.
#[must_use]
#[inline]
pub fn read_ttbr1_el1() -> u64 {
    TTBR1_EL1.get()
}

/// Get TTBR1_EL1 base address (mask off ASID and other fields)
///
/// Returns only the physical address portion of TTBR1_EL1.
#[must_use]
#[inline]
pub fn ttbr1_base_address() -> u64 {
    // BADDR is bits [47:1] for 4KB granule, but we mask to page boundary
    read_ttbr1_el1() & 0x0000_FFFF_FFFF_F000
}

/// Exception Syndrome Register (ESR) parsing
pub mod esr {
    /// Exception class (EC) field extraction
    #[inline]
    pub const fn exception_class(esr: u64) -> u8 {
        ((esr >> 26) & 0x3F) as u8
    }

    /// Instruction Length (IL) field - true if 32-bit instruction
    #[inline]
    pub const fn instruction_length(esr: u64) -> bool {
        (esr >> 25) & 1 != 0
    }

    /// Instruction Specific Syndrome (ISS) field
    #[inline]
    pub const fn iss(esr: u64) -> u32 {
        (esr & 0x1FF_FFFF) as u32
    }

    /// Get human-readable name for exception class
    pub fn ec_name(ec: u8) -> &'static str {
        match ec {
            ec::UNKNOWN => "Unknown",
            ec::WFI_WFE => "WFI/WFE trapped",
            ec::MCR_MRC_CP15 => "MCR/MRC CP15 (AArch32)",
            ec::MCRR_MRRC_CP15 => "MCRR/MRRC CP15 (AArch32)",
            ec::MCR_MRC_CP14 => "MCR/MRC CP14 (AArch32)",
            ec::LDC_STC => "LDC/STC (AArch32)",
            ec::SVE_SIMD_FP => "SVE/SIMD/FP access",
            ec::LD64B_ST64B => "LD64B/ST64B trapped",
            ec::MRRC_CP14 => "MRRC CP14 (AArch32)",
            ec::BRANCH_TARGET => "Branch target exception",
            ec::ILLEGAL_EXECUTION => "Illegal execution state",
            ec::SVC_AARCH32 => "SVC (AArch32)",
            ec::HVC_AARCH32 => "HVC (AArch32)",
            ec::SMC_AARCH32 => "SMC (AArch32)",
            ec::SVC_AARCH64 => "SVC (AArch64)",
            ec::HVC_AARCH64 => "HVC (AArch64)",
            ec::SMC_AARCH64 => "SMC (AArch64)",
            ec::SYS_INSTRUCTION => "MSR/MRS/SYS trapped",
            ec::SVE_ACCESS => "SVE access",
            ec::ERET_ERETAA_ERETAB => "ERET/ERETAA/ERETAB",
            ec::PAC_FAILURE => "PAC failure",
            ec::INSTRUCTION_ABORT_LOWER => "Instruction abort (lower EL)",
            ec::INSTRUCTION_ABORT_SAME => "Instruction abort (same EL)",
            ec::PC_ALIGNMENT => "PC alignment fault",
            ec::DATA_ABORT_LOWER => "Data abort (lower EL)",
            ec::DATA_ABORT_SAME => "Data abort (same EL)",
            ec::SP_ALIGNMENT => "SP alignment fault",
            ec::FP_EXCEPTION_AARCH32 => "FP exception (AArch32)",
            ec::FP_EXCEPTION => "FP exception (AArch64)",
            ec::SERROR => "SError",
            ec::BREAKPOINT_LOWER => "Breakpoint (lower EL)",
            ec::BREAKPOINT_SAME => "Breakpoint (same EL)",
            ec::SOFTWARE_STEP_LOWER => "Software step (lower EL)",
            ec::SOFTWARE_STEP_SAME => "Software step (same EL)",
            ec::WATCHPOINT_LOWER => "Watchpoint (lower EL)",
            ec::WATCHPOINT_SAME => "Watchpoint (same EL)",
            ec::BKPT_AARCH32 => "BKPT (AArch32)",
            ec::BRK_AARCH64 => "BRK (AArch64)",
            _ => "Reserved/Unknown",
        }
    }

    /// Exception class values
    pub mod ec {
        pub const UNKNOWN: u8 = 0b000000;
        pub const WFI_WFE: u8 = 0b000001;
        pub const MCR_MRC_CP15: u8 = 0b000011;
        pub const MCRR_MRRC_CP15: u8 = 0b000100;
        pub const MCR_MRC_CP14: u8 = 0b000101;
        pub const LDC_STC: u8 = 0b000110;
        pub const SVE_SIMD_FP: u8 = 0b000111;
        pub const LD64B_ST64B: u8 = 0b001010;
        pub const MRRC_CP14: u8 = 0b001100;
        pub const BRANCH_TARGET: u8 = 0b001101;
        pub const ILLEGAL_EXECUTION: u8 = 0b001110;
        pub const SVC_AARCH32: u8 = 0b010001;
        pub const HVC_AARCH32: u8 = 0b010010;
        pub const SMC_AARCH32: u8 = 0b010011;
        pub const SVC_AARCH64: u8 = 0b010101;
        pub const HVC_AARCH64: u8 = 0b010110;
        pub const SMC_AARCH64: u8 = 0b010111;
        pub const SYS_INSTRUCTION: u8 = 0b011000;
        pub const SVE_ACCESS: u8 = 0b011001;
        pub const ERET_ERETAA_ERETAB: u8 = 0b011010;
        pub const PAC_FAILURE: u8 = 0b011100;
        pub const INSTRUCTION_ABORT_LOWER: u8 = 0b100000;
        pub const INSTRUCTION_ABORT_SAME: u8 = 0b100001;
        pub const PC_ALIGNMENT: u8 = 0b100010;
        pub const DATA_ABORT_LOWER: u8 = 0b100100;
        pub const DATA_ABORT_SAME: u8 = 0b100101;
        pub const SP_ALIGNMENT: u8 = 0b100110;
        pub const FP_EXCEPTION_AARCH32: u8 = 0b101000;
        pub const FP_EXCEPTION: u8 = 0b101100;
        pub const SERROR: u8 = 0b101111;
        pub const BREAKPOINT_LOWER: u8 = 0b110000;
        pub const BREAKPOINT_SAME: u8 = 0b110001;
        pub const SOFTWARE_STEP_LOWER: u8 = 0b110010;
        pub const SOFTWARE_STEP_SAME: u8 = 0b110011;
        pub const WATCHPOINT_LOWER: u8 = 0b110100;
        pub const WATCHPOINT_SAME: u8 = 0b110101;
        pub const BKPT_AARCH32: u8 = 0b111000;
        pub const BRK_AARCH64: u8 = 0b111100;
    }

    /// Data/Instruction abort ISS fields
    pub mod abort {
        /// Data/Instruction Fault Status Code (bits [5:0])
        #[inline]
        pub const fn dfsc(iss: u32) -> u8 {
            (iss & 0x3F) as u8
        }

        /// Alias for instruction fault status code (same encoding as dfsc)
        #[inline]
        pub const fn ifsc(iss: u32) -> u8 {
            dfsc(iss)
        }

        /// Write not Read (bit 6) - true if write caused the abort
        #[inline]
        pub const fn wnr(iss: u32) -> bool {
            (iss >> 6) & 1 != 0
        }

        /// Stage 1 translation table walk (bit 7)
        #[inline]
        pub const fn s1ptw(iss: u32) -> bool {
            (iss >> 7) & 1 != 0
        }

        /// Cache maintenance operation (bit 8)
        #[inline]
        pub const fn cm(iss: u32) -> bool {
            (iss >> 8) & 1 != 0
        }

        /// External abort type (bit 9)
        #[inline]
        pub const fn ea(iss: u32) -> bool {
            (iss >> 9) & 1 != 0
        }

        /// FAR not Valid (bit 10)
        #[inline]
        pub const fn fnv(iss: u32) -> bool {
            (iss >> 10) & 1 != 0
        }

        /// Synchronous Error Type (bits [12:11])
        #[inline]
        pub const fn set(iss: u32) -> u8 {
            ((iss >> 11) & 0x3) as u8
        }

        /// Acquire/Release (bit 14)
        #[inline]
        pub const fn ar(iss: u32) -> bool {
            (iss >> 14) & 1 != 0
        }

        /// Syndrome valid (bit 24) - indicates ISS[23:14] are valid
        #[inline]
        pub const fn isv(iss: u32) -> bool {
            (iss >> 24) & 1 != 0
        }

        /// Get human-readable name for fault status code
        pub fn dfsc_name(dfsc: u8) -> &'static str {
            match dfsc {
                DFSC_ADDRESS_SIZE_L0 => "Address size fault, level 0",
                DFSC_ADDRESS_SIZE_L1 => "Address size fault, level 1",
                DFSC_ADDRESS_SIZE_L2 => "Address size fault, level 2",
                DFSC_ADDRESS_SIZE_L3 => "Address size fault, level 3",
                DFSC_TRANSLATION_L0 => "Translation fault, level 0",
                DFSC_TRANSLATION_L1 => "Translation fault, level 1",
                DFSC_TRANSLATION_L2 => "Translation fault, level 2",
                DFSC_TRANSLATION_L3 => "Translation fault, level 3",
                DFSC_ACCESS_FLAG_L0 => "Access flag fault, level 0",
                DFSC_ACCESS_FLAG_L1 => "Access flag fault, level 1",
                DFSC_ACCESS_FLAG_L2 => "Access flag fault, level 2",
                DFSC_ACCESS_FLAG_L3 => "Access flag fault, level 3",
                DFSC_PERMISSION_L0 => "Permission fault, level 0",
                DFSC_PERMISSION_L1 => "Permission fault, level 1",
                DFSC_PERMISSION_L2 => "Permission fault, level 2",
                DFSC_PERMISSION_L3 => "Permission fault, level 3",
                DFSC_SYNC_EXTERNAL => "Synchronous external abort",
                DFSC_SYNC_EXTERNAL_L0 => "Synchronous external abort, level 0",
                DFSC_SYNC_EXTERNAL_L1 => "Synchronous external abort, level 1",
                DFSC_SYNC_EXTERNAL_L2 => "Synchronous external abort, level 2",
                DFSC_SYNC_EXTERNAL_L3 => "Synchronous external abort, level 3",
                DFSC_SYNC_PARITY => "Synchronous parity/ECC error",
                DFSC_SYNC_PARITY_L0 => "Synchronous parity/ECC error, level 0",
                DFSC_SYNC_PARITY_L1 => "Synchronous parity/ECC error, level 1",
                DFSC_SYNC_PARITY_L2 => "Synchronous parity/ECC error, level 2",
                DFSC_SYNC_PARITY_L3 => "Synchronous parity/ECC error, level 3",
                DFSC_ALIGNMENT => "Alignment fault",
                DFSC_TLB_CONFLICT => "TLB conflict abort",
                DFSC_UNSUPPORTED_ATOMIC => "Unsupported atomic hardware update",
                DFSC_LOCKDOWN => "Implementation defined (lockdown)",
                DFSC_UNSUPPORTED_EXCLUSIVE => "Unsupported exclusive or atomic",
                _ => "Unknown/Reserved fault",
            }
        }

        /// Fault status codes - Address size faults
        pub const DFSC_ADDRESS_SIZE_L0: u8 = 0b000000;
        pub const DFSC_ADDRESS_SIZE_L1: u8 = 0b000001;
        pub const DFSC_ADDRESS_SIZE_L2: u8 = 0b000010;
        pub const DFSC_ADDRESS_SIZE_L3: u8 = 0b000011;

        /// Fault status codes - Translation faults (page not mapped)
        pub const DFSC_TRANSLATION_L0: u8 = 0b000100;
        pub const DFSC_TRANSLATION_L1: u8 = 0b000101;
        pub const DFSC_TRANSLATION_L2: u8 = 0b000110;
        pub const DFSC_TRANSLATION_L3: u8 = 0b000111;

        /// Fault status codes - Access flag faults
        pub const DFSC_ACCESS_FLAG_L0: u8 = 0b001000;
        pub const DFSC_ACCESS_FLAG_L1: u8 = 0b001001;
        pub const DFSC_ACCESS_FLAG_L2: u8 = 0b001010;
        pub const DFSC_ACCESS_FLAG_L3: u8 = 0b001011;

        /// Fault status codes - Permission faults
        pub const DFSC_PERMISSION_L0: u8 = 0b001100;
        pub const DFSC_PERMISSION_L1: u8 = 0b001101;
        pub const DFSC_PERMISSION_L2: u8 = 0b001110;
        pub const DFSC_PERMISSION_L3: u8 = 0b001111;

        /// Fault status codes - Synchronous external aborts
        pub const DFSC_SYNC_EXTERNAL: u8 = 0b010000;
        pub const DFSC_SYNC_EXTERNAL_L0: u8 = 0b010100;
        pub const DFSC_SYNC_EXTERNAL_L1: u8 = 0b010101;
        pub const DFSC_SYNC_EXTERNAL_L2: u8 = 0b010110;
        pub const DFSC_SYNC_EXTERNAL_L3: u8 = 0b010111;

        /// Fault status codes - Synchronous parity/ECC errors
        pub const DFSC_SYNC_PARITY: u8 = 0b011000;
        pub const DFSC_SYNC_PARITY_L0: u8 = 0b011100;
        pub const DFSC_SYNC_PARITY_L1: u8 = 0b011101;
        pub const DFSC_SYNC_PARITY_L2: u8 = 0b011110;
        pub const DFSC_SYNC_PARITY_L3: u8 = 0b011111;

        /// Fault status codes - Other
        pub const DFSC_ALIGNMENT: u8 = 0b100001;
        pub const DFSC_TLB_CONFLICT: u8 = 0b110000;
        pub const DFSC_UNSUPPORTED_ATOMIC: u8 = 0b110001;
        pub const DFSC_LOCKDOWN: u8 = 0b110100;
        pub const DFSC_UNSUPPORTED_EXCLUSIVE: u8 = 0b110101;
    }
}

/// Saved Program Status Register (SPSR) parsing
pub mod spsr {
    /// NZCV condition flags (bits [31:28])
    #[inline]
    pub const fn nzcv(spsr: u64) -> (bool, bool, bool, bool) {
        (
            (spsr >> 31) & 1 != 0, // N - Negative
            (spsr >> 30) & 1 != 0, // Z - Zero
            (spsr >> 29) & 1 != 0, // C - Carry
            (spsr >> 28) & 1 != 0, // V - Overflow
        )
    }

    /// DAIF interrupt mask bits (bits [9:6])
    #[inline]
    pub const fn daif(spsr: u64) -> (bool, bool, bool, bool) {
        (
            (spsr >> 9) & 1 != 0, // D - Debug mask
            (spsr >> 8) & 1 != 0, // A - SError mask
            (spsr >> 7) & 1 != 0, // I - IRQ mask
            (spsr >> 6) & 1 != 0, // F - FIQ mask
        )
    }

    /// Exception level from M[3:2] bits
    #[inline]
    pub const fn exception_level(spsr: u64) -> u8 {
        ((spsr >> 2) & 0x3) as u8
    }

    /// Stack pointer selection from M[0] bit (true = SP_ELx, false = SP_EL0)
    #[inline]
    pub const fn sp_sel(spsr: u64) -> bool {
        spsr & 1 != 0
    }

    /// Execution state from M[4] bit (true = AArch32, false = AArch64)
    #[inline]
    pub const fn is_aarch32(spsr: u64) -> bool {
        (spsr >> 4) & 1 != 0
    }

    /// Get exception level name (e.g., "EL0t", "EL1h")
    pub fn el_name(spsr: u64) -> &'static str {
        if is_aarch32(spsr) {
            return "AArch32";
        }
        let el = exception_level(spsr);
        let sp = sp_sel(spsr);
        match (el, sp) {
            (0, false) => "EL0t",
            (0, true) => "EL0t", // SP_EL0 not valid at EL0
            (1, false) => "EL1t",
            (1, true) => "EL1h",
            (2, false) => "EL2t",
            (2, true) => "EL2h",
            (3, false) => "EL3t",
            (3, true) => "EL3h",
            _ => "Unknown",
        }
    }
}
