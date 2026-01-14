//! Runtime initialisation module
//!
//! Provides the entry point and runtime setup for M6 userspace programs.

pub mod lang_items;
pub mod providers;

use core::sync::atomic::{AtomicBool, Ordering};

use m6_common::boot::BootInfo;

/// Fixed address where the kernel maps boot info for the init process.
pub const USER_BOOT_INFO_ADDR: usize = 0x0000_7FFF_E000_0000;

/// Default heap base address (1GB mark).
pub const DEFAULT_HEAP_BASE: usize = 0x4000_0000;

/// Default heap size (128 MiB).
pub const DEFAULT_HEAP_SIZE: usize = 128 * 1024 * 1024;

/// Whether the runtime has been initialised.
static RUNTIME_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Check if the runtime has been initialised.
#[inline]
pub fn is_initialised() -> bool {
    RUNTIME_INITIALISED.load(Ordering::Acquire)
}

/// Get a reference to the boot info structure.
///
/// # Safety
///
/// Only valid after runtime initialisation and only for the init process
/// (other processes may not have boot info mapped at this address).
#[inline]
pub unsafe fn boot_info() -> &'static BootInfo {
    // SAFETY: Caller ensures this is only called when boot info is valid
    unsafe { &*(USER_BOOT_INFO_ADDR as *const BootInfo) }
}

/// Initialise the runtime.
///
/// This function is called automatically by `_start` before `main`.
/// It sets up:
/// - The global allocator
/// - I/O subsystem
/// - Runtime state
///
/// # Safety
///
/// Must be called exactly once, before any allocations or I/O.
pub unsafe fn init(boot_info_ptr: usize) -> Result<(), &'static str> {
    if RUNTIME_INITIALISED.swap(true, Ordering::AcqRel) {
        return Err("Runtime already initialised");
    }

    // Initialise the allocator if the alloc feature is enabled
    #[cfg(feature = "alloc")]
    {
        providers::init_allocator(boot_info_ptr)?;
    }

    Ok(())
}
