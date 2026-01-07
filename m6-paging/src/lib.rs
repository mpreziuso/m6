//! Paging - Type-safe page table abstractions
//!
//! This crate provides type-safe abstractions for ARM64 page table management,
//! following modern Rust best practices for compile-time safety and optimal
//! TLB usage through greedy block mapping.
//!
//! # Architecture
//!
//! - `address`: Typed physical and virtual addresses (`PA`, `VA`, `TPA<T>`, `TVA<T>`)
//! - `region`: Memory region abstractions with alignment helpers
//! - `permissions`: Page table entry permissions and memory types
//! - `traits`: Allocator and invalidator traits
//! - `arch::arm64`: ARM64-specific page table implementation
//!
//! # Physical-to-Virtual Mapping
//!
//! By default, this crate assumes identity mapping (physical == virtual), which
//! is appropriate for bootloaders. For kernels with a direct physical map at
//! a different offset, call `set_phys_to_virt_offset()` during initialisation.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use spin::Once;

pub mod address;
pub mod permissions;
pub mod region;
pub mod traits;

pub mod arch;

// Re-export commonly used types
pub use address::{Address, Physical, Virtual, MemKind, PA, VA, TPA, TVA};
pub use permissions::{MemoryType, PtePermissions};
pub use region::{MemoryRegion, PhysMemoryRegion, VirtMemoryRegion};
pub use traits::{MapAttributes, MapError, PageAllocator};

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Number of entries per page table (512 for 4KB granule)
pub const ENTRIES_PER_TABLE: usize = 512;

// Compile-time verification of paging constants
const _: () = assert!(PAGE_SIZE.is_power_of_two(), "PAGE_SIZE must be a power of two");
const _: () = assert!(PAGE_SIZE >= 4096, "PAGE_SIZE must be at least 4KB");
const _: () = assert!(ENTRIES_PER_TABLE == 512, "4KB granule requires 512 entries per table");
const _: () = assert!(
    PAGE_SIZE * ENTRIES_PER_TABLE == 2 * 1024 * 1024,
    "L2 block size must be 2MB"
);

// ============================================================================
// Physical-to-Virtual Address Translation
// ============================================================================

/// Physical-to-virtual offset (initialised once during kernel init).
///
/// Uses `spin::Once` to ensure the offset can only be set once,
/// preventing accidental double-initialisation.
static PHYS_TO_VIRT_OFFSET: Once<u64> = Once::new();

/// Set the offset to add to physical addresses when converting to virtual.
///
/// This should be called once during kernel initialisation, before any page
/// table operations that require accessing physical memory.
///
/// # Arguments
///
/// * `offset` - The base virtual address of the direct physical map
///   (e.g., 0xFFFF_FFFF_0000_0000 for a kernel with RAM mapped there)
///
/// # Example
///
/// ```ignore
/// // Map physical memory at virtual address 0xFFFF_FFFF_0000_0000
/// m6_paging::set_phys_to_virt_offset(0xFFFF_FFFF_0000_0000);
/// ```
///
/// # Note
///
/// This function can only be called once. Subsequent calls are ignored.
/// Use [`try_set_phys_to_virt_offset`] if you need to know whether the
/// offset was successfully set.
pub fn set_phys_to_virt_offset(offset: u64) {
    PHYS_TO_VIRT_OFFSET.call_once(|| offset);
}

/// Try to set the physical-to-virtual offset.
///
/// Returns `true` if the offset was set, `false` if it was already configured.
#[must_use]
pub fn try_set_phys_to_virt_offset(offset: u64) -> bool {
    let mut was_set = false;
    PHYS_TO_VIRT_OFFSET.call_once(|| {
        was_set = true;
        offset
    });
    was_set
}

/// Get the current physical-to-virtual offset.
///
/// Returns 0 if not yet configured (identity mapping).
#[inline]
#[must_use]
pub fn phys_to_virt_offset() -> u64 {
    PHYS_TO_VIRT_OFFSET.get().copied().unwrap_or(0)
}

/// Convert a physical address to a virtual address for kernel access.
///
/// This adds the configured offset to the physical address.
/// By default (offset = 0), this is an identity mapping.
#[inline]
#[must_use]
pub fn phys_to_virt(phys: u64) -> u64 {
    phys.wrapping_add(phys_to_virt_offset())
}
