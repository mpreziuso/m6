//! Fault types and messages
//!
//! Defines the fault types that can be delivered to user fault handlers
//! and the message format for fault delivery via IPC.
//!
//! # Fault Delivery
//!
//! When a user thread faults, the kernel delivers a fault message to the
//! thread's `fault_endpoint` (if configured). The message contains:
//!
//! - Fault type (semantic classification)
//! - Faulting PC (instruction that caused the fault)
//! - Fault address (for memory faults)
//! - Raw ESR (for detailed analysis)
//! - Access flags (read/write, level, etc.)
//!
//! The fault handler can then:
//! 1. Handle the fault (e.g., map a page)
//! 2. Reply to resume the faulted thread
//! 3. Or terminate the thread by not replying

/// Fault type classification.
///
/// These are semantic fault types that abstract over the raw ARM64
/// exception classes. User fault handlers receive this classification
/// along with the raw ESR for detailed analysis if needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum FaultType {
    /// Data abort - page not mapped, permission denied, etc.
    ///
    /// This is the most common fault type, typically requiring the
    /// fault handler to map a page.
    PageFault = 1,

    /// Instruction fetch fault - trying to execute unmapped/non-executable memory.
    InstructionFault = 2,

    /// Alignment fault (PC or SP alignment).
    AlignmentFault = 3,

    /// Debug exception (breakpoint, watchpoint, single-step).
    DebugFault = 4,

    /// Illegal execution state.
    IllegalState = 5,

    /// Floating-point exception.
    FpException = 6,

    /// Unknown or reserved exception type.
    Unknown = 0,
}

impl FaultType {
    /// Convert from raw u64 value.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        match value {
            1 => Self::PageFault,
            2 => Self::InstructionFault,
            3 => Self::AlignmentFault,
            4 => Self::DebugFault,
            5 => Self::IllegalState,
            6 => Self::FpException,
            _ => Self::Unknown,
        }
    }

    /// Convert to u64 for IPC message.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

/// Fault message for IPC delivery.
///
/// This structure contains all the information about a fault that is
/// delivered to a fault handler via the thread's fault endpoint.
///
/// # Message Register Layout
///
/// When delivered via IPC, the message is encoded as (5 words):
/// - msg[0]: fault_type (FaultType enum value)
/// - msg[1]: faulting_pc (ELR - instruction that faulted)
/// - msg[2]: fault_address (FAR - for memory faults, 0 otherwise)
/// - msg[3]: esr_raw (raw Exception Syndrome Register)
/// - msg[4]: flags (packed access information)
/// - x6 (badge): identifies the faulting thread's capability
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FaultMessage {
    /// Semantic fault type classification.
    pub fault_type: u64,
    /// Faulting instruction address (ELR_EL1).
    pub faulting_pc: u64,
    /// Fault address (FAR_EL1) for memory faults.
    pub fault_address: u64,
    /// Raw Exception Syndrome Register value.
    pub esr_raw: u64,
    /// Packed flags with access information.
    ///
    /// Bit layout:
    /// - Bit 0: WNR (1 = write, 0 = read)
    /// - Bit 1: S1PTW (stage 1 page table walk)
    /// - Bit 2: CM (cache maintenance)
    /// - Bit 3: FNV (FAR not valid)
    /// - Bits 4-7: DFSC/IFSC (fault status code, low 4 bits)
    /// - Bits 8-15: Reserved
    /// - Bits 16-23: Exception class (EC)
    /// - Bits 24-63: Reserved
    pub flags: u64,
}

impl FaultMessage {
    /// Create a new fault message.
    #[must_use]
    pub const fn new(
        fault_type: FaultType,
        faulting_pc: u64,
        fault_address: u64,
        esr_raw: u64,
        flags: u64,
    ) -> Self {
        Self {
            fault_type: fault_type as u64,
            faulting_pc,
            fault_address,
            esr_raw,
            flags,
        }
    }

    /// Get the fault type.
    #[must_use]
    pub const fn fault_type(&self) -> FaultType {
        FaultType::from_u64(self.fault_type)
    }

    /// Check if this was a write access (for memory faults).
    #[must_use]
    pub const fn is_write(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Check if FAR is valid.
    #[must_use]
    pub const fn is_far_valid(&self) -> bool {
        // FNV bit is 1 when FAR is NOT valid
        self.flags & (1 << 3) == 0
    }

    /// Get the fault status code (DFSC/IFSC).
    #[must_use]
    pub const fn fault_status_code(&self) -> u8 {
        ((self.flags >> 4) & 0xF) as u8
    }

    /// Get the exception class.
    #[must_use]
    pub const fn exception_class(&self) -> u8 {
        ((self.flags >> 16) & 0x3F) as u8
    }

    /// Convert to IPC message register array.
    #[must_use]
    pub const fn to_regs(&self) -> [u64; 5] {
        [
            self.fault_type,
            self.faulting_pc,
            self.fault_address,
            self.esr_raw,
            self.flags,
        ]
    }

    /// Create from IPC message register array.
    #[must_use]
    pub const fn from_regs(regs: [u64; 5]) -> Self {
        Self {
            fault_type: regs[0],
            faulting_pc: regs[1],
            fault_address: regs[2],
            esr_raw: regs[3],
            flags: regs[4],
        }
    }
}

/// Fault flags bit positions.
pub mod flags {
    /// Write not Read (bit 0) - 1 if write caused the fault.
    pub const WNR: u64 = 1 << 0;
    /// Stage 1 page table walk (bit 1).
    pub const S1PTW: u64 = 1 << 1;
    /// Cache maintenance operation (bit 2).
    pub const CM: u64 = 1 << 2;
    /// FAR not valid (bit 3).
    pub const FNV: u64 = 1 << 3;

    /// Pack fault flags from ISS and EC values.
    #[must_use]
    pub const fn pack(iss: u32, ec: u8) -> u64 {
        let wnr = if (iss >> 6) & 1 != 0 { WNR } else { 0 };
        let s1ptw = if (iss >> 7) & 1 != 0 { S1PTW } else { 0 };
        let cm = if (iss >> 8) & 1 != 0 { CM } else { 0 };
        let fnv = if (iss >> 10) & 1 != 0 { FNV } else { 0 };
        let dfsc = ((iss & 0x3F) as u64) << 4;
        let ec_bits = (ec as u64) << 16;

        wnr | s1ptw | cm | fnv | dfsc | ec_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_type_conversion() {
        assert_eq!(FaultType::from_u64(1), FaultType::PageFault);
        assert_eq!(FaultType::from_u64(99), FaultType::Unknown);
        assert_eq!(FaultType::PageFault.as_u64(), 1);
    }

    #[test]
    fn test_fault_message_regs() {
        let msg = FaultMessage::new(
            FaultType::PageFault,
            0x1000,
            0x2000,
            0x3000,
            flags::WNR,
        );
        let regs = msg.to_regs();
        let msg2 = FaultMessage::from_regs(regs);
        assert_eq!(msg.fault_type, msg2.fault_type);
        assert_eq!(msg.faulting_pc, msg2.faulting_pc);
        assert!(msg2.is_write());
    }
}
