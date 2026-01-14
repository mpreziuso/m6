//! IPC protocol definitions for VirtIO block driver.
//!
//! Defines the request/response codes and message formats for
//! block device operations.

#![allow(dead_code)]

/// Request codes (in IPC message label)
pub mod request {
    /// Read sector(s) from the block device.
    /// msg[0]: start sector (u64)
    /// msg[1]: sector count (u64)
    /// Response data is written to shared buffer or returned inline.
    pub const READ_SECTOR: u64 = 0x0001;

    /// Write sector(s) to the block device.
    /// msg[0]: start sector (u64)
    /// msg[1]: sector count (u64)
    /// Data to write is in shared buffer or passed inline.
    pub const WRITE_SECTOR: u64 = 0x0002;

    /// Get device information.
    /// Response: msg[0] = total sectors, msg[1] = sector size
    pub const GET_INFO: u64 = 0x0003;

    /// Flush device cache.
    pub const FLUSH: u64 = 0x0004;

    /// Get driver status.
    pub const GET_STATUS: u64 = 0x0010;
}

/// Response codes (in IPC response x0)
pub mod response {
    /// Operation completed successfully
    pub const OK: u64 = 0;
    /// I/O error
    pub const ERR_IO: u64 = 1;
    /// Invalid request
    pub const ERR_INVALID: u64 = 2;
    /// Device busy
    pub const ERR_BUSY: u64 = 3;
    /// Operation not supported
    pub const ERR_UNSUPPORTED: u64 = 4;
    /// Invalid sector address
    pub const ERR_INVALID_SECTOR: u64 = 5;
}

/// Status flags
pub mod status {
    /// Device is ready for operations
    pub const READY: u64 = 1 << 0;
    /// Device is read-only
    pub const READ_ONLY: u64 = 1 << 1;
    /// Device supports flush
    pub const FLUSH_SUPPORTED: u64 = 1 << 2;
}
