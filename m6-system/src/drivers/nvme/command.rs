//! NVMe Command and Register Definitions
//!
//! Provides type-safe definitions for NVMe commands, completions, and
//! controller registers using tock-registers for bitfield access.

#![allow(dead_code)]

use tock_registers::register_bitfields;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// -- NVMe Controller Register Offsets

/// Controller Capabilities (CAP)
pub const REG_CAP: usize = 0x00;
/// Version (VS)
pub const REG_VS: usize = 0x08;
/// Interrupt Mask Set (INTMS)
pub const REG_INTMS: usize = 0x0C;
/// Interrupt Mask Clear (INTMC)
pub const REG_INTMC: usize = 0x10;
/// Controller Configuration (CC)
pub const REG_CC: usize = 0x14;
/// Controller Status (CSTS)
pub const REG_CSTS: usize = 0x1C;
/// NVM Subsystem Reset (NSSR)
pub const REG_NSSR: usize = 0x20;
/// Admin Queue Attributes (AQA)
pub const REG_AQA: usize = 0x24;
/// Admin Submission Queue Base Address (ASQ)
pub const REG_ASQ: usize = 0x28;
/// Admin Completion Queue Base Address (ACQ)
pub const REG_ACQ: usize = 0x30;
/// Controller Memory Buffer Location (CMBLOC)
pub const REG_CMBLOC: usize = 0x38;
/// Controller Memory Buffer Size (CMBSZ)
pub const REG_CMBSZ: usize = 0x3C;

/// Doorbell stride offset calculation.
/// Doorbells start at offset 0x1000 in NVMe 1.0+.
pub const DOORBELL_BASE: usize = 0x1000;

// -- Register Bitfields

register_bitfields![u64,
    /// Controller Capabilities (64-bit)
    pub CAP [
        /// Maximum Queue Entries Supported (0-based, actual = MQES + 1)
        MQES OFFSET(0) NUMBITS(16) [],
        /// Contiguous Queues Required
        CQR OFFSET(16) NUMBITS(1) [],
        /// Arbitration Mechanism Supported
        AMS OFFSET(17) NUMBITS(2) [],
        /// Timeout (in 500ms units)
        TO OFFSET(24) NUMBITS(8) [],
        /// Doorbell Stride (4 << DSTRD bytes)
        DSTRD OFFSET(32) NUMBITS(4) [],
        /// NVM Subsystem Reset Supported
        NSSRS OFFSET(36) NUMBITS(1) [],
        /// Command Sets Supported
        CSS OFFSET(37) NUMBITS(8) [],
        /// Boot Partition Support
        BPS OFFSET(45) NUMBITS(1) [],
        /// Memory Page Size Minimum (2^(12+MPSMIN))
        MPSMIN OFFSET(48) NUMBITS(4) [],
        /// Memory Page Size Maximum (2^(12+MPSMAX))
        MPSMAX OFFSET(52) NUMBITS(4) [],
        /// Persistent Memory Region Supported
        PMRS OFFSET(56) NUMBITS(1) [],
        /// Controller Memory Buffer Supported
        CMBS OFFSET(57) NUMBITS(1) [],
    ]
];

register_bitfields![u32,
    /// Controller Configuration (32-bit)
    pub CC [
        /// Enable
        EN OFFSET(0) NUMBITS(1) [],
        /// I/O Command Set Selected
        CSS OFFSET(4) NUMBITS(3) [],
        /// Memory Page Size (2^(12+MPS))
        MPS OFFSET(7) NUMBITS(4) [],
        /// Arbitration Mechanism Selected
        AMS OFFSET(11) NUMBITS(3) [],
        /// Shutdown Notification
        SHN OFFSET(14) NUMBITS(2) [],
        /// I/O Submission Queue Entry Size (2^IOSQES)
        IOSQES OFFSET(16) NUMBITS(4) [],
        /// I/O Completion Queue Entry Size (2^IOCQES)
        IOCQES OFFSET(20) NUMBITS(4) [],
    ],

    /// Controller Status (32-bit)
    pub CSTS [
        /// Ready
        RDY OFFSET(0) NUMBITS(1) [],
        /// Controller Fatal Status
        CFS OFFSET(1) NUMBITS(1) [],
        /// Shutdown Status
        SHST OFFSET(2) NUMBITS(2) [],
        /// NVM Subsystem Reset Occurred
        NSSRO OFFSET(4) NUMBITS(1) [],
        /// Processing Paused
        PP OFFSET(5) NUMBITS(1) [],
    ],

    /// Admin Queue Attributes (32-bit)
    pub AQA [
        /// Admin Submission Queue Size (0-based)
        ASQS OFFSET(0) NUMBITS(12) [],
        /// Admin Completion Queue Size (0-based)
        ACQS OFFSET(16) NUMBITS(12) [],
    ],

    /// Version (32-bit)
    pub VS [
        /// Tertiary Version Number
        TER OFFSET(0) NUMBITS(8) [],
        /// Minor Version Number
        MNR OFFSET(8) NUMBITS(8) [],
        /// Major Version Number
        MJR OFFSET(16) NUMBITS(16) [],
    ]
];

// -- NVMe Command Opcodes

/// Admin command opcodes
pub mod admin_opcode {
    /// Delete I/O Submission Queue
    pub const DELETE_IO_SQ: u8 = 0x00;
    /// Create I/O Submission Queue
    pub const CREATE_IO_SQ: u8 = 0x01;
    /// Get Log Page
    pub const GET_LOG_PAGE: u8 = 0x02;
    /// Delete I/O Completion Queue
    pub const DELETE_IO_CQ: u8 = 0x04;
    /// Create I/O Completion Queue
    pub const CREATE_IO_CQ: u8 = 0x05;
    /// Identify
    pub const IDENTIFY: u8 = 0x06;
    /// Abort
    pub const ABORT: u8 = 0x08;
    /// Set Features
    pub const SET_FEATURES: u8 = 0x09;
    /// Get Features
    pub const GET_FEATURES: u8 = 0x0A;
    /// Asynchronous Event Request
    pub const ASYNC_EVENT: u8 = 0x0C;
    /// Namespace Management
    pub const NS_MANAGEMENT: u8 = 0x0D;
    /// Firmware Commit
    pub const FW_COMMIT: u8 = 0x10;
    /// Firmware Image Download
    pub const FW_DOWNLOAD: u8 = 0x11;
    /// Device Self-test
    pub const DEVICE_SELF_TEST: u8 = 0x14;
    /// Namespace Attachment
    pub const NS_ATTACHMENT: u8 = 0x15;
    /// Keep Alive
    pub const KEEP_ALIVE: u8 = 0x18;
    /// Format NVM
    pub const FORMAT_NVM: u8 = 0x80;
    /// Security Send
    pub const SECURITY_SEND: u8 = 0x81;
    /// Security Receive
    pub const SECURITY_RECV: u8 = 0x82;
    /// Sanitize
    pub const SANITIZE: u8 = 0x84;
}

/// NVM command opcodes (I/O commands)
pub mod nvm_opcode {
    /// Flush
    pub const FLUSH: u8 = 0x00;
    /// Write
    pub const WRITE: u8 = 0x01;
    /// Read
    pub const READ: u8 = 0x02;
    /// Write Uncorrectable
    pub const WRITE_UNCORRECTABLE: u8 = 0x04;
    /// Compare
    pub const COMPARE: u8 = 0x05;
    /// Write Zeroes
    pub const WRITE_ZEROES: u8 = 0x08;
    /// Dataset Management
    pub const DATASET_MANAGEMENT: u8 = 0x09;
    /// Reservation Register
    pub const RESERVATION_REGISTER: u8 = 0x0D;
    /// Reservation Report
    pub const RESERVATION_REPORT: u8 = 0x0E;
    /// Reservation Acquire
    pub const RESERVATION_ACQUIRE: u8 = 0x11;
    /// Reservation Release
    pub const RESERVATION_RELEASE: u8 = 0x15;
}

/// Identify CNS values
pub mod identify_cns {
    /// Identify Namespace
    pub const NAMESPACE: u8 = 0x00;
    /// Identify Controller
    pub const CONTROLLER: u8 = 0x01;
    /// Active Namespace ID list
    pub const ACTIVE_NS_LIST: u8 = 0x02;
    /// Namespace Identification Descriptor list
    pub const NS_ID_DESC_LIST: u8 = 0x03;
}

// -- NVMe Command Structure (64 bytes)

/// NVMe Submission Queue Entry (Command)
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NvmeCommand {
    /// Command Dword 0 (Opcode, Fused, PSDT, CID)
    pub cdw0: u32,
    /// Namespace Identifier
    pub nsid: u32,
    /// Command Dword 2 (Reserved)
    pub cdw2: u32,
    /// Command Dword 3 (Reserved)
    pub cdw3: u32,
    /// Metadata Pointer
    pub mptr: u64,
    /// Data Pointer 1 (PRP1 or SGL)
    pub prp1: u64,
    /// Data Pointer 2 (PRP2 or SGL)
    pub prp2: u64,
    /// Command Dword 10
    pub cdw10: u32,
    /// Command Dword 11
    pub cdw11: u32,
    /// Command Dword 12
    pub cdw12: u32,
    /// Command Dword 13
    pub cdw13: u32,
    /// Command Dword 14
    pub cdw14: u32,
    /// Command Dword 15
    pub cdw15: u32,
}

impl NvmeCommand {
    /// Create a new command with the given opcode and command ID.
    #[inline]
    #[must_use]
    pub const fn new(opcode: u8, cid: u16) -> Self {
        Self {
            cdw0: (opcode as u32) | ((cid as u32) << 16),
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Set the namespace ID.
    #[inline]
    pub fn set_nsid(&mut self, nsid: u32) {
        self.nsid = nsid;
    }

    /// Set PRP1 and PRP2.
    #[inline]
    pub fn set_prp(&mut self, prp1: u64, prp2: u64) {
        self.prp1 = prp1;
        self.prp2 = prp2;
    }

    /// Get the command ID from CDW0.
    #[inline]
    #[must_use]
    pub const fn cid(&self) -> u16 {
        (self.cdw0 >> 16) as u16
    }

    /// Get the opcode from CDW0.
    #[inline]
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    /// Create an Identify Controller command.
    #[inline]
    #[must_use]
    pub fn identify_controller(cid: u16, prp1: u64) -> Self {
        let mut cmd = Self::new(admin_opcode::IDENTIFY, cid);
        cmd.prp1 = prp1;
        cmd.cdw10 = identify_cns::CONTROLLER as u32;
        cmd
    }

    /// Create an Identify Namespace command.
    #[inline]
    #[must_use]
    pub fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> Self {
        let mut cmd = Self::new(admin_opcode::IDENTIFY, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.cdw10 = identify_cns::NAMESPACE as u32;
        cmd
    }

    /// Create a Create I/O Completion Queue command.
    #[inline]
    #[must_use]
    pub fn create_io_cq(cid: u16, qid: u16, prp1: u64, qsize: u16, iv: u16, ien: bool) -> Self {
        let mut cmd = Self::new(admin_opcode::CREATE_IO_CQ, cid);
        cmd.prp1 = prp1;
        // CDW10: QSIZE[31:16], QID[15:0]
        cmd.cdw10 = ((qsize as u32 - 1) << 16) | (qid as u32);
        // CDW11: IV[31:16], IEN[1], PC[0]
        cmd.cdw11 = ((iv as u32) << 16) | ((ien as u32) << 1) | 1; // PC=1 (physically contiguous)
        cmd
    }

    /// Create a Create I/O Submission Queue command.
    #[inline]
    #[must_use]
    pub fn create_io_sq(cid: u16, qid: u16, prp1: u64, qsize: u16, cqid: u16) -> Self {
        let mut cmd = Self::new(admin_opcode::CREATE_IO_SQ, cid);
        cmd.prp1 = prp1;
        // CDW10: QSIZE[31:16], QID[15:0]
        cmd.cdw10 = ((qsize as u32 - 1) << 16) | (qid as u32);
        // CDW11: CQID[31:16], QPRIO[2:1], PC[0]
        cmd.cdw11 = ((cqid as u32) << 16) | 1; // PC=1, QPRIO=0 (urgent)
        cmd
    }

    /// Create a Read command.
    #[inline]
    #[must_use]
    pub fn read(cid: u16, nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new(nvm_opcode::READ, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        // CDW10: Starting LBA (lower 32 bits)
        cmd.cdw10 = lba as u32;
        // CDW11: Starting LBA (upper 32 bits)
        cmd.cdw11 = (lba >> 32) as u32;
        // CDW12: NLB[15:0] (0-based, actual = NLB + 1)
        cmd.cdw12 = (nlb - 1) as u32;
        cmd
    }

    /// Create a Write command.
    #[inline]
    #[must_use]
    pub fn write(cid: u16, nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        let mut cmd = Self::new(nvm_opcode::WRITE, cid);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (nlb - 1) as u32;
        cmd
    }

    /// Create a Flush command.
    #[inline]
    #[must_use]
    pub fn flush(cid: u16, nsid: u32) -> Self {
        let mut cmd = Self::new(nvm_opcode::FLUSH, cid);
        cmd.nsid = nsid;
        cmd
    }
}

// -- NVMe Completion Queue Entry (16 bytes)

/// NVMe Completion Queue Entry
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NvmeCompletion {
    /// Command-specific result (DW0)
    pub result: u32,
    /// Reserved
    pub rsvd: u32,
    /// SQ Head Pointer
    pub sq_head: u16,
    /// SQ Identifier
    pub sq_id: u16,
    /// Command Identifier
    pub cid: u16,
    /// Status Field (includes phase bit at bit 0)
    pub status: u16,
}

impl NvmeCompletion {
    /// Get the phase bit.
    #[inline]
    #[must_use]
    pub const fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// Get the status code (SC field).
    #[inline]
    #[must_use]
    pub const fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// Get the status code type (SCT field).
    #[inline]
    #[must_use]
    pub const fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x7) as u8
    }

    /// Check if the command completed successfully.
    #[inline]
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }

    /// Check for a specific error.
    #[inline]
    #[must_use]
    pub const fn is_error(&self, sct: u8, sc: u8) -> bool {
        self.status_code_type() == sct && self.status_code() == sc
    }
}

/// NVMe status code types
pub mod status_code_type {
    /// Generic Command Status
    pub const GENERIC: u8 = 0;
    /// Command Specific Status
    pub const COMMAND_SPECIFIC: u8 = 1;
    /// Media and Data Integrity Errors
    pub const MEDIA_ERROR: u8 = 2;
    /// Path Related Status
    pub const PATH_RELATED: u8 = 3;
    /// Vendor Specific
    pub const VENDOR_SPECIFIC: u8 = 7;
}

/// Generic status codes (SCT = 0)
pub mod generic_status {
    /// Successful Completion
    pub const SUCCESS: u8 = 0x00;
    /// Invalid Command Opcode
    pub const INVALID_OPCODE: u8 = 0x01;
    /// Invalid Field in Command
    pub const INVALID_FIELD: u8 = 0x02;
    /// Command ID Conflict
    pub const CID_CONFLICT: u8 = 0x03;
    /// Data Transfer Error
    pub const DATA_TRANSFER_ERROR: u8 = 0x04;
    /// Commands Aborted due to Power Loss
    pub const ABORTED_POWER_LOSS: u8 = 0x05;
    /// Internal Error
    pub const INTERNAL_ERROR: u8 = 0x06;
    /// Command Abort Requested
    pub const ABORT_REQUESTED: u8 = 0x07;
    /// Command Aborted due to SQ Deletion
    pub const ABORTED_SQ_DELETION: u8 = 0x08;
    /// Command Aborted due to Failed Fused Command
    pub const ABORTED_FUSED_FAIL: u8 = 0x09;
    /// Command Aborted due to Missing Fused Command
    pub const ABORTED_FUSED_MISSING: u8 = 0x0A;
    /// Invalid Namespace or Format
    pub const INVALID_NAMESPACE: u8 = 0x0B;
    /// Command Sequence Error
    pub const COMMAND_SEQUENCE_ERROR: u8 = 0x0C;
    /// LBA Out of Range
    pub const LBA_OUT_OF_RANGE: u8 = 0x80;
    /// Capacity Exceeded
    pub const CAPACITY_EXCEEDED: u8 = 0x81;
    /// Namespace Not Ready
    pub const NS_NOT_READY: u8 = 0x82;
}

// -- Size assertions

const _: () = {
    assert!(core::mem::size_of::<NvmeCommand>() == 64);
    assert!(core::mem::size_of::<NvmeCompletion>() == 16);
};
