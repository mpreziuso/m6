//! IPC Protocol for NVMe Block Device
//!
//! Defines the message protocol for block device operations between
//! clients and the NVMe driver.

#![allow(dead_code)]

/// IPC request message labels
pub mod request {
    /// Get device information (capacity, block size, etc.)
    pub const GET_INFO: u64 = 0x0001;
    /// Get device status
    pub const GET_STATUS: u64 = 0x0002;
    /// Read sectors from device
    /// x1: starting LBA
    /// x2: number of blocks
    /// Requires: Frame capability in IPC buffer
    pub const READ_SECTOR: u64 = 0x0010;
    /// Write sectors to device
    /// x1: starting LBA
    /// x2: number of blocks
    /// Requires: Frame capability in IPC buffer
    pub const WRITE_SECTOR: u64 = 0x0011;
    /// Flush device write cache
    pub const FLUSH: u64 = 0x0012;
    /// Discard sectors (TRIM)
    /// x1: starting LBA
    /// x2: number of blocks
    pub const DISCARD: u64 = 0x0020;
}

/// IPC response codes
pub mod response {
    /// Operation completed successfully
    pub const OK: u64 = 0;
    /// Invalid request
    pub const ERR_INVALID: u64 = 1;
    /// I/O error
    pub const ERR_IO: u64 = 2;
    /// Device not ready
    pub const ERR_NOT_READY: u64 = 3;
    /// Invalid sector/LBA
    pub const ERR_INVALID_SECTOR: u64 = 4;
    /// Operation not supported
    pub const ERR_UNSUPPORTED: u64 = 5;
    /// Device is read-only
    pub const ERR_READ_ONLY: u64 = 6;
    /// No space/resources
    pub const ERR_NO_SPACE: u64 = 7;
    /// Timeout
    pub const ERR_TIMEOUT: u64 = 8;
}

/// Device status flags
pub mod status {
    /// Device is ready for I/O
    pub const READY: u64 = 1 << 0;
    /// Device is read-only
    pub const READ_ONLY: u64 = 1 << 1;
    /// Flush command is supported
    pub const FLUSH_SUPPORTED: u64 = 1 << 2;
    /// Discard (TRIM) is supported
    pub const DISCARD_SUPPORTED: u64 = 1 << 3;
    /// Volatile write cache enabled
    pub const VOLATILE_WRITE_CACHE: u64 = 1 << 4;
}

/// Device information structure (returned in IPC registers)
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceInfo {
    /// Total capacity in logical blocks
    pub capacity_blocks: u64,
    /// Logical block size in bytes
    pub block_size: u32,
    /// Maximum transfer size in blocks (0 = no limit)
    pub max_transfer_blocks: u32,
    /// Optimal I/O alignment in blocks
    pub optimal_alignment: u32,
}

impl DeviceInfo {
    /// Get total capacity in bytes.
    #[inline]
    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks * (self.block_size as u64)
    }

    /// Pack into IPC message format.
    /// Returns (x1, x2, x3, x4) for reply.
    #[must_use]
    pub const fn pack(&self) -> (u64, u64, u64, u64) {
        (
            self.capacity_blocks,
            self.block_size as u64,
            self.max_transfer_blocks as u64,
            self.optimal_alignment as u64,
        )
    }
}
