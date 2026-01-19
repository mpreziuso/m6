//! Cache maintenance syscall handlers
//!
//! Exposes ARM64 cache maintenance operations to userspace for non-coherent DMA.
//! These are required when a device performs DMA to/from memory that may be
//! cached by the CPU.
//!
//! # Operations
//!
//! - **Clean** (CacheClean): Write dirty cache lines to memory before DMA to device
//! - **Invalidate** (CacheInvalidate): Discard stale cache after DMA from device
//! - **Flush** (CacheFlush): Clean + invalidate for bidirectional DMA
//!
//! # Security
//!
//! - Only userspace addresses (< 0x0001_0000_0000_0000) are permitted
//! - Maximum size is limited to 16MB to prevent DoS

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};
use m6_arch::cache::{cache_clean_range, cache_flush_range, cache_invalidate_range};

/// Maximum buffer size for cache operations (16MB).
const MAX_CACHE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum userspace address (end of TTBR0 space).
const MAX_USER_ADDR: u64 = 0x0001_0000_0000_0000;

/// Handle CacheClean syscall.
///
/// Cleans (writes back) cache lines to memory. Use before DMA to device
/// to ensure memory contains the latest CPU writes.
///
/// # Arguments
/// - x0: Virtual address of buffer
/// - x1: Size in bytes
pub fn handle_cache_clean(args: &SyscallArgs) -> SyscallResult {
    validate_and_clean(args.arg0, args.arg1 as usize)
}

/// Handle CacheInvalidate syscall.
///
/// Invalidates (discards) cache lines. Use after DMA from device
/// to ensure CPU reads fresh data from memory.
///
/// # Arguments
/// - x0: Virtual address of buffer
/// - x1: Size in bytes
pub fn handle_cache_invalidate(args: &SyscallArgs) -> SyscallResult {
    validate_and_invalidate(args.arg0, args.arg1 as usize)
}

/// Handle CacheFlush syscall.
///
/// Flushes (clean + invalidate) cache lines. Use for bidirectional DMA
/// or when the coherency direction is uncertain.
///
/// # Arguments
/// - x0: Virtual address of buffer
/// - x1: Size in bytes
pub fn handle_cache_flush(args: &SyscallArgs) -> SyscallResult {
    validate_and_flush(args.arg0, args.arg1 as usize)
}

/// Validate address and size, then clean cache range.
fn validate_and_clean(vaddr: u64, size: usize) -> SyscallResult {
    validate_params(vaddr, size)?;
    cache_clean_range(vaddr, size);
    Ok(0)
}

/// Validate address and size, then invalidate cache range.
fn validate_and_invalidate(vaddr: u64, size: usize) -> SyscallResult {
    validate_params(vaddr, size)?;
    cache_invalidate_range(vaddr, size);
    Ok(0)
}

/// Validate address and size, then flush cache range.
fn validate_and_flush(vaddr: u64, size: usize) -> SyscallResult {
    validate_params(vaddr, size)?;
    cache_flush_range(vaddr, size);
    Ok(0)
}

/// Validate userspace address and size.
///
/// Returns error if:
/// - Address is outside userspace range
/// - Size exceeds maximum allowed
/// - Address + size would overflow
fn validate_params(vaddr: u64, size: usize) -> SyscallResult {
    // Check size limit
    if size > MAX_CACHE_SIZE {
        log::warn!("Cache op size {} exceeds maximum {}", size, MAX_CACHE_SIZE);
        return Err(SyscallError::InvalidArg);
    }

    // Zero size is a no-op, but valid
    if size == 0 {
        return Ok(0);
    }

    // Check address is in userspace range
    if vaddr >= MAX_USER_ADDR {
        log::warn!("Cache op address {:#x} outside userspace", vaddr);
        return Err(SyscallError::Range);
    }

    // Check for overflow
    let end = vaddr.checked_add(size as u64).ok_or_else(|| {
        log::warn!("Cache op address overflow");
        SyscallError::Range
    })?;

    // Check end is also in userspace range
    if end > MAX_USER_ADDR {
        log::warn!("Cache op end address {:#x} outside userspace", end);
        return Err(SyscallError::Range);
    }

    Ok(0)
}
