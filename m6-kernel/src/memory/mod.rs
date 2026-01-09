//! Kernel Memory Management
//!
//! Provides:
//! - Physical frame allocator (bitmap-based)
//! - Kernel heap allocator (buddy system with dynamic growth)
//! - Physical-to-virtual address translation via direct map
//! - Virtual address space layout
//!
//! # Design
//!
//! The bootloader allocates the frame bitmap and passes it via BootInfo.
//! This solves the chicken-and-egg problem: we can't allocate the bitmap
//! without knowing how much RAM exists, but we can't know RAM size without
//! parsing the memory map (which the bootloader already does).
//!
//! # Safety Invariants
//!
//! - `init_memory_from_boot_info()` must be called exactly once during kernel init
//! - No heap allocations are permitted in interrupt context (deadlock risk)
//! - All reserved memory (bitmap, kernel image, page tables) must be marked
//!   allocated after initialising the frame allocator

use core::sync::atomic::{AtomicU64, Ordering};

// Submodule declarations
pub mod asid;
pub mod frame;
pub mod heap;
pub mod init;
pub mod layout;
pub mod translate;

// Re-export public API
pub use asid::{
    allocate_asid, current_generation, init_asid_allocator, is_asid_valid,
    refresh_asid_if_needed, AllocatedAsid,
};
pub use frame::{
    alloc_frame, alloc_frame_zeroed, alloc_frames, alloc_frames_zeroed,
    free_frame, memory_stats,
};
pub use init::init_memory_from_boot_info;
pub use layout::virt;
pub use translate::{
    phys_to_virt, phys_to_virt_checked, virt_to_phys, virt_to_phys_checked,
    phys_to_ptr, phys_to_ptr_checked,
};

// -- Dynamic Physical Map Size

/// Maximum physical address detected from memory map.
/// Set during init from BootInfo.max_phys_addr.
static MAX_PHYS_ADDR: AtomicU64 = AtomicU64::new(0);

/// Get the maximum physical address (dynamic, set from BootInfo).
#[inline]
#[must_use]
pub fn max_phys_addr() -> u64 {
    MAX_PHYS_ADDR.load(Ordering::Relaxed)
}

/// Set the maximum physical address (called once during init).
pub(crate) fn set_max_phys_addr(addr: u64) {
    MAX_PHYS_ADDR.store(addr, Ordering::Relaxed);
}
