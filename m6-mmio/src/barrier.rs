//! Memory Barrier Helpers
//!
//! Provides memory barrier operations for device drivers. These ensure
//! proper ordering of memory operations, which is critical for:
//!
//! - Device register accesses (producer/consumer queues)
//! - DMA buffer visibility
//! - Interrupt handling
//!
//! # ARM64 Memory Model
//!
//! ARM64 has a weakly-ordered memory model. The barriers provided here map to:
//! - `read_barrier()`: Acquire semantics (loads before this complete first)
//! - `write_barrier()`: Release semantics (stores before this complete first)
//! - `dsb()`: Data Synchronisation Barrier (full barrier, all memory ops complete)
//! - `isb()`: Instruction Synchronisation Barrier (pipeline flush)
//!
//! # Usage Patterns
//!
//! ## Producer-Consumer Queue (Driver writes, Device reads)
//!
//! ```ignore
//! // Write data to queue entry
//! queue[tail] = entry;
//! write_barrier();           // Ensure entry is visible before tail update
//! doorbell.write(tail + 1);  // Notify device
//! ```
//!
//! ## Consumer Queue (Device writes, Driver reads)
//!
//! ```ignore
//! read_barrier();            // Ensure we see latest completion entries
//! if queue[head].phase == expected_phase {
//!     // Process completion
//! }
//! ```

use core::sync::atomic::{Ordering, fence};

/// Read barrier (acquire semantics).
///
/// Ensures all loads before this barrier complete before any loads after.
/// Use before reading shared memory that may have been written by a device.
#[inline]
pub fn read_barrier() {
    fence(Ordering::Acquire);
}

/// Write barrier (release semantics).
///
/// Ensures all stores before this barrier complete before any stores after.
/// Use before writing to a doorbell to notify a device of new data.
#[inline]
pub fn write_barrier() {
    fence(Ordering::Release);
}

/// Full memory barrier.
///
/// Ensures all memory operations before this barrier complete before any
/// operations after. Use when you need to ensure both loads and stores
/// are ordered (e.g., between DMA setup and device notification).
#[inline]
pub fn full_barrier() {
    fence(Ordering::SeqCst);
}

/// Data Synchronisation Barrier (DSB SY).
///
/// Ensures all memory accesses (including device memory) complete before
/// continuing. This is stronger than a compiler fence and affects the CPU's
/// memory system directly.
///
/// Use for:
/// - After MMIO writes that must complete before continuing
/// - Before reading memory modified by DMA
/// - After modifying page tables
#[inline]
pub fn dsb() {
    // SAFETY: DSB is always safe to execute
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Instruction Synchronisation Barrier (ISB).
///
/// Flushes the processor pipeline, ensuring all preceding instructions
/// complete and subsequent instructions are fetched fresh.
///
/// Use for:
/// - After modifying system registers
/// - After modifying code (self-modifying code)
/// - After modifying page tables (with DSB)
#[inline]
pub fn isb() {
    // SAFETY: ISB is always safe to execute
    unsafe {
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

/// Data Memory Barrier (DMB SY).
///
/// Ensures that all memory accesses before this barrier are observed before
/// any memory accesses after. Unlike DSB, this doesn't wait for completion,
/// just ensures ordering.
#[inline]
pub fn dmb() {
    // SAFETY: DMB is always safe to execute
    unsafe {
        core::arch::asm!("dmb sy", options(nostack, preserves_flags));
    }
}

/// Store-release barrier.
///
/// Ensures all preceding stores complete before continuing.
/// Lighter weight than full DSB when only stores need ordering.
#[inline]
pub fn dmb_st() {
    // SAFETY: DMB ST is always safe to execute
    unsafe {
        core::arch::asm!("dmb st", options(nostack, preserves_flags));
    }
}

/// Load-acquire barrier.
///
/// Ensures all subsequent loads happen after this point.
/// Lighter weight than full DSB when only loads need ordering.
#[inline]
pub fn dmb_ld() {
    // SAFETY: DMB LD is always safe to execute
    unsafe {
        core::arch::asm!("dmb ld", options(nostack, preserves_flags));
    }
}

/// Outer-shareable DSB (for multi-cluster systems).
///
/// Ensures memory operations are visible to other clusters/CPUs in an
/// outer-shareable domain (e.g., for SMMU operations).
#[inline]
pub fn dsb_osh() {
    // SAFETY: DSB OSH is always safe to execute
    unsafe {
        core::arch::asm!("dsb osh", options(nostack, preserves_flags));
    }
}

/// Inner-shareable DSB (for single-cluster systems).
///
/// Ensures memory operations are visible within the inner-shareable domain.
/// Lighter weight than OSH for single-cluster systems.
#[inline]
pub fn dsb_ish() {
    // SAFETY: DSB ISH is always safe to execute
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    }
}
