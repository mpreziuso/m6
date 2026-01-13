//! SMMU driver IPC protocol
//!
//! This module defines the IPC protocol for communicating with the SMMU
//! monitoring driver. The driver provides diagnostic and statistics
//! interfaces for observing SMMU faults and events.

/// Request message labels.
pub mod request {
    /// Check SMMU health status.
    ///
    /// Returns: 0 on success, error code otherwise
    pub const HEALTH_CHECK: u64 = 0x0001;

    /// Get count of claimed stream IDs.
    ///
    /// Returns: Number of claimed streams in x0
    pub const GET_STREAM_COUNT: u64 = 0x0002;

    /// Get total fault count.
    ///
    /// Returns: Total faults observed since boot in x0
    pub const GET_FAULT_COUNT: u64 = 0x0003;

    /// Get most recent fault information.
    ///
    /// Returns:
    /// - x0: fault_type (event code)
    /// - x1: stream_id
    /// - x2: faulting_address (low 32 bits)
    /// - x3: faulting_address (high 32 bits)
    pub const GET_LAST_FAULT: u64 = 0x0004;
}

/// Response codes.
pub mod response {
    /// Success.
    pub const OK: u64 = 0;

    /// Invalid request.
    pub const ERR_INVALID_REQUEST: u64 = 1;

    /// No fault data available.
    pub const ERR_NO_FAULT: u64 = 2;
}
