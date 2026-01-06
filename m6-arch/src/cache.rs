//! ARM64 Cache Management Operations
//!
//! Provides cache maintenance operations required for DMA coherency.
//! ARM64 caches are PIPT (Physically Indexed, Physically Tagged) for data caches,
//! so we use virtual addresses with DC (Data Cache) instructions.
//!
//! # Cache Line Size
//!
//! The cache line size is read from `CTR_EL0.DminLine` at runtime and cached.
//! This ensures correct behavior across different ARM64 implementations.
//!
//! # Coherency Model
//! - **Clean**: Write dirty cache lines to memory (DC CVAC)
//! - **Invalidate**: Discard cache lines without writing (DC IVAC)
//! - **Flush**: Clean + Invalidate (DC CIVAC)
//!
//! # DMA Usage
//! - **Before DMA to device**: `cache_clean_range()` to ensure memory has latest data
//! - **After DMA from device**: `cache_invalidate_range()` to discard stale cache
//! - **Bidirectional DMA**: `cache_flush_range()` for both directions

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Cached cache line size (initialised on first use).
///
/// Value of 0 indicates not yet initialised.
static CACHE_LINE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Get the data cache minimum line size from CTR_EL0.
///
/// Returns the cache line size in bytes. The result is cached after
/// the first call for efficiency.
///
/// # Implementation
///
/// Reads `CTR_EL0.DminLine` (bits [19:16]), which contains log2 of the
/// number of words per cache line. Since a word is 4 bytes on ARM64:
/// `line_size = 4 << DminLine`
#[inline]
#[must_use]
pub fn cache_line_size() -> usize {
    let cached = CACHE_LINE_SIZE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    // Read CTR_EL0.DminLine (bits [19:16])
    // DminLine = log2(words per cache line), where word = 4 bytes
    let ctr: u64;
    // SAFETY: Reading CTR_EL0 is always safe and doesn't have side effects.
    unsafe {
        asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }

    let dmin_line = ((ctr >> 16) & 0xF) as usize;
    let line_size = 4 << dmin_line; // 4 bytes * 2^DminLine

    CACHE_LINE_SIZE.store(line_size, Ordering::Relaxed);
    line_size
}

/// Align address down to cache line boundary
#[inline]
fn align_down_to_cache_line(addr: u64) -> u64 {
    let mask = cache_line_size() as u64 - 1;
    addr & !mask
}

/// Align address up to cache line boundary
#[inline]
fn align_up_to_cache_line(addr: u64) -> u64 {
    let size = cache_line_size() as u64;
    (addr + size - 1) & !(size - 1)
}

/// Clean (write back) data cache lines
///
/// Writes dirty cache lines to memory without invalidating them.
/// Use before DMA to device to ensure memory has latest CPU writes.
///
/// # Arguments
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Safety
/// - vaddr must point to valid, mapped memory
/// - Buffer must not span unmapped regions
///
/// # Implementation
/// Uses DC CVAC (Data Cache Clean by VA to PoC - Point of Coherency)
/// followed by DSB to ensure completion.
pub fn cache_clean_range(vaddr: u64, size: usize) {
    if size == 0 {
        return;
    }

    // Align to cache line boundaries
    let start = align_down_to_cache_line(vaddr);
    let end = align_up_to_cache_line(vaddr + size as u64);

    // Clean each cache line
    let line_size = cache_line_size() as u64;
    let mut addr = start;
    while addr < end {
        // SAFETY: DC CVAC is safe for any valid mapped address.
        unsafe {
            // DC CVAC: Data Cache Clean by VA to Point of Coherency
            asm!(
                "dc cvac, {addr}",
                addr = in(reg) addr,
                options(nostack)
            );
        }
        addr += line_size;
    }

    // Data Synchronization Barrier - ensure all cache ops complete
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

/// Invalidate (discard) data cache lines
///
/// Discards cache lines without writing them back to memory.
/// Use after DMA from device to ensure CPU reads fresh data from memory.
///
/// # Arguments
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Safety
/// - vaddr must point to valid, mapped memory
/// - Buffer must not span unmapped regions
/// - CRITICAL: Only use when you're certain no dirty data should be preserved
///   (typically after device has written new data via DMA)
///
/// # Implementation
/// Uses DC IVAC (Data Cache Invalidate by VA to PoC)
/// followed by DSB to ensure completion.
pub fn cache_invalidate_range(vaddr: u64, size: usize) {
    if size == 0 {
        return;
    }

    // Align to cache line boundaries
    let start = align_down_to_cache_line(vaddr);
    let end = align_up_to_cache_line(vaddr.saturating_add(size as u64));

    // Invalidate each cache line
    let line_size = cache_line_size() as u64;
    let mut addr = start;
    while addr < end {
        // SAFETY: DC IVAC is safe for any valid mapped address.
        unsafe {
            // DC IVAC: Data Cache Invalidate by VA to Point of Coherency
            asm!(
                "dc ivac, {addr}",
                addr = in(reg) addr,
                options(nostack)
            );
        }
        addr += line_size;
    }

    // Data Synchronization Barrier
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

/// Flush (clean + invalidate) data cache lines
///
/// Combines clean and invalidate: writes dirty data to memory, then discards cache.
/// Use for bidirectional DMA or when coherency requirements are uncertain.
///
/// # Arguments
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Safety
/// - vaddr must point to valid, mapped memory
/// - Buffer must not span unmapped regions
///
/// # Implementation
/// Uses DC CIVAC (Data Cache Clean and Invalidate by VA to PoC)
/// followed by DSB to ensure completion.
pub fn cache_flush_range(vaddr: u64, size: usize) {
    if size == 0 {
        return;
    }

    // Align to cache line boundaries
    let start = align_down_to_cache_line(vaddr);
    let end = align_up_to_cache_line(vaddr.saturating_add(size as u64));

    // Flush (clean + invalidate) each cache line
    let line_size = cache_line_size() as u64;
    let mut addr = start;
    while addr < end {
        // SAFETY: DC CIVAC is safe for any valid mapped address.
        unsafe {
            // DC CIVAC: Data Cache Clean and Invalidate by VA to PoC
            asm!(
                "dc civac, {addr}",
                addr = in(reg) addr,
                options(nostack)
            );
        }
        addr += line_size;
    }

    // Data Synchronization Barrier
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

/// Clean entire data cache
///
/// Used rarely - typically for system-wide coherency operations.
/// Most DMA operations should use range-based operations above.
///
/// # Safety
/// This is a privileged operation. Only call from kernel context.
pub fn cache_clean_all() {
    unsafe {
        // There's no single instruction to clean all caches on ARM64
        // Proper implementation requires walking cache hierarchy via CLIDR_EL1/CCSIDR_EL1
        // For now, issue DSB to ensure all prior cache ops complete
        asm!("dsb sy", options(nostack));
    }
}

/// Invalidate entire instruction cache
///
/// Required after modifying executable code (e.g., loading programs).
///
/// # Safety
/// This is a privileged operation. Only call from kernel context.
pub fn icache_invalidate_all() {
    unsafe {
        // IC IALLU: Instruction Cache Invalidate All to PoU
        asm!(
            "ic iallu",
            "dsb sy",
            "isb",
            options(nostack)
        );
    }
}
