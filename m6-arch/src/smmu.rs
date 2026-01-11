//! ARM SMMUv3 shared register definitions
//!
//! This module contains SMMU register definitions and structures that are
//! shared between the kernel SMMU driver and the userspace SMMU monitoring
//! driver.
//!
//! Based on ARM System Memory Management Unit Architecture Specification
//! SMMU v3.0 to v3.3 (ARM IHI 0070).

// -- Event Queue Register Offsets

/// Event Queue Base
pub const SMMU_EVENTQ_BASE: usize = 0x0A0;
/// Event Queue Producer Index
pub const SMMU_EVENTQ_PROD: usize = 0x100A8;
/// Event Queue Consumer Index
pub const SMMU_EVENTQ_CONS: usize = 0x100AC;

// -- Event Queue Entry

/// Event Queue Entry - 32 bytes
///
/// Each event in the SMMU event queue is represented by this structure.
/// The userspace driver reads these from the event queue to monitor
/// DMA faults and other SMMU events.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventEntry {
    pub dwords: [u64; 4],
}

impl EventEntry {
    /// Size of an event entry in bytes.
    pub const SIZE: usize = 32;

    /// Get the event type/fault code.
    ///
    /// Common fault codes:
    /// - 0x01: C_BAD_STREAMID - Invalid stream ID
    /// - 0x02: C_BAD_STE - Invalid stream table entry
    /// - 0x08-0x0F: Permission faults (read/write/execute denied)
    /// - 0x10-0x1F: Translation faults (page not present)
    #[inline]
    pub fn event_type(&self) -> u8 {
        (self.dwords[0] & 0xFF) as u8
    }

    /// Get the stream ID that caused the event.
    #[inline]
    pub fn stream_id(&self) -> u32 {
        ((self.dwords[0] >> 32) & 0xFFFF_FFFF) as u32
    }

    /// Get the faulting address (if applicable).
    ///
    /// This is the I/O virtual address (IOVA) that caused the fault.
    #[inline]
    pub fn address(&self) -> u64 {
        self.dwords[2]
    }

    /// Check if this is a translation fault (page not present).
    #[inline]
    pub fn is_translation_fault(&self) -> bool {
        matches!(self.event_type(), 0x10..=0x1F)
    }

    /// Check if this is a permission fault (access denied).
    #[inline]
    pub fn is_permission_fault(&self) -> bool {
        matches!(self.event_type(), 0x08..=0x0F)
    }

    /// Check if this is a bad stream ID fault.
    #[inline]
    pub fn is_bad_streamid(&self) -> bool {
        self.event_type() == 0x01
    }

    /// Check if this is a bad STE fault.
    #[inline]
    pub fn is_bad_ste(&self) -> bool {
        self.event_type() == 0x02
    }

    /// Get a human-readable description of the fault type.
    pub fn fault_description(&self) -> &'static str {
        match self.event_type() {
            0x01 => "Bad Stream ID",
            0x02 => "Bad Stream Table Entry",
            0x08..=0x0F => "Permission Fault",
            0x10..=0x1F => "Translation Fault",
            _ => "Unknown Event",
        }
    }
}
