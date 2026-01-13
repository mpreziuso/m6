//! Error types for the allocator

use core::fmt;

/// Errors that can occur during allocation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// Out of memory - no pages available from pool
    OutOfMemory,
    /// Failed to map virtual memory
    MapFailed,
    /// Failed to unmap virtual memory
    UnmapFailed,
    /// Large allocation side table is full
    SideTableFull,
    /// No free spans available
    NoFreeSpans,
    /// Allocator not initialised
    NotInitialised,
    /// Allocator already initialised
    AlreadyInitialised,
    /// Invalid configuration
    InvalidConfig,
    /// Allocator is poisoned due to detected corruption
    Poisoned,
}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::MapFailed => write!(f, "failed to map virtual memory"),
            Self::UnmapFailed => write!(f, "failed to unmap virtual memory"),
            Self::SideTableFull => write!(f, "large allocation side table full"),
            Self::NoFreeSpans => write!(f, "no free spans available"),
            Self::NotInitialised => write!(f, "allocator not initialised"),
            Self::AlreadyInitialised => write!(f, "allocator already initialised"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
            Self::Poisoned => write!(f, "allocator poisoned due to corruption"),
        }
    }
}

/// Errors that can occur during freelist operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreelistError {
    /// Decoded pointer has bad alignment
    BadAlignment,
    /// Decoded pointer is outside span range
    OutOfRange,
    /// Decoded pointer is not on a slot boundary
    NotSlotAligned,
    /// Double-free detected via bitmap
    DoubleFree,
    /// Freelist corruption detected
    Corrupted,
}

impl fmt::Display for FreelistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadAlignment => write!(f, "bad alignment in freelist pointer"),
            Self::OutOfRange => write!(f, "freelist pointer out of span range"),
            Self::NotSlotAligned => write!(f, "freelist pointer not slot-aligned"),
            Self::DoubleFree => write!(f, "double-free detected"),
            Self::Corrupted => write!(f, "freelist corruption detected"),
        }
    }
}

impl From<FreelistError> for AllocError {
    fn from(_: FreelistError) -> Self {
        AllocError::Poisoned
    }
}
