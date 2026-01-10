//! IPC protocol for PL011 UART driver.
//!
//! Defines request/response labels and message formats for UART communication.

// -- Request labels (in x0)

pub mod request {
    /// Write data inline in registers x1-x5 (up to 40 bytes).
    /// x0[32:47] = length in bytes
    pub const WRITE_INLINE: u64 = 0x0001;

    /// Read data, returns inline in x1-x5.
    /// x1 = max bytes to read
    /// Response: x0 = OK, x1 = actual bytes read, x2-x5 = data
    pub const READ: u64 = 0x0002;

    /// Get UART status flags.
    /// Response: x0 = OK, x1 = status flags
    pub const GET_STATUS: u64 = 0x0010;
}

// -- Response codes (in x0)

pub mod response {
    /// Success
    pub const OK: u64 = 0;
    /// Invalid request label
    pub const ERR_INVALID_REQUEST: u64 = 1;
    /// Operation would block (for non-blocking mode)
    pub const ERR_WOULD_BLOCK: u64 = 2;
    /// No data available for read
    pub const ERR_NO_DATA: u64 = 3;
}

// -- Status flags (returned in x1 for GET_STATUS)

pub mod status {
    /// TX FIFO has space available
    pub const TX_READY: u64 = 1 << 0;
    /// RX FIFO has data available
    pub const RX_READY: u64 = 1 << 1;
}

/// Extract inline write length from x0.
#[inline]
pub const fn write_inline_len(x0: u64) -> usize {
    ((x0 >> 32) & 0xFFFF) as usize
}

/// Create WRITE_INLINE x0 value with length.
#[inline]
pub const fn write_inline_x0(len: usize) -> u64 {
    request::WRITE_INLINE | ((len as u64) << 32)
}
