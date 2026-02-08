//! Runtime initialisation module
//!
//! Provides the entry point and runtime setup for M6 userspace programs.
//!
//! # Entry Point
//!
//! This module provides the `_start` entry point that the kernel jumps to
//! when starting a userspace program. It initialises the runtime and calls
//! the user's `main()` function.
//!
//! # Usage
//!
//! User programs should define a `main` function:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! extern crate m6_std as std;
//!
//! use std::println;
//!
//! #[no_mangle]
//! fn main() -> i32 {
//!     println!("Hello from M6!");
//!     0
//! }
//! ```

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

/// The x0 register value passed by the kernel at program start.
/// This can be used to pass configuration to userspace programs.
static mut STARTUP_X0: u64 = 0;

/// Get the x0 register value that was passed by the kernel at program start.
///
/// This is typically used to pass configuration (like CNode radix) to
/// userspace programs. The value is captured in `_start` before any
/// function calls.
pub fn startup_arg() -> u64 {
    // SAFETY: STARTUP_X0 is only written once in _start before main is called
    unsafe { STARTUP_X0 }
}

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

// -- Entry point (only when entry-point feature is enabled)

#[cfg(feature = "entry-point")]
mod entry {
    use super::{init, STARTUP_X0};
    use crate::process::exit;

    unsafe extern "Rust" {
        /// User-defined main function.
        ///
        /// This function must be defined by the user program with `#[unsafe(no_mangle)]`.
        safe fn main() -> i32;
    }

    /// Program entry point.
    ///
    /// This function is called by the kernel when starting a userspace program.
    /// It initialises the runtime and calls the user's `main()` function.
    ///
    /// # Safety
    ///
    /// This function must only be called once by the kernel at program start.
    /// The user must define a `main` function with `#[unsafe(no_mangle)]`.
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".text.entry")]
    pub unsafe extern "C" fn _start(x0: u64) -> ! {
        // Save x0 before any function calls clobber it
        // SAFETY: Only written once here before main is called
        unsafe {
            STARTUP_X0 = x0;
        }

        // Initialise runtime (boot_info_ptr is 0 for non-init processes)
        // SAFETY: Called once at program start
        unsafe {
            let _ = init(0);
        }

        // Call user's main function
        let exit_code = main();

        // Exit with the return code
        exit(exit_code);
    }
}
