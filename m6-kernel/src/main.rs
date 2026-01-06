//! Kernel Initialization
//!
//! This module contains the kernel entry point and initialization sequence.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;
use m6_arch::cpu;
use m6_common::boot::BootInfo;
use m6_pal::platform;


/// Panic handler for the kernel
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // TODO: Log panic info when we have a logger
    loop {
        cpu::halt();
    }
}


/// Kernel entry point called by the bootloader
///
/// # Safety
/// This function is called directly by the bootloader with a valid BootInfo pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(boot_info: *const BootInfo) -> ! {
    let boot_info = unsafe { &*boot_info };
    if !boot_info.is_valid() {
        #[allow(clippy::never_loop)]
        loop {
            cpu::halt();
        }
    }

    platform::init(boot_info);

    loop {
        cpu::wait_for_interrupt();
    }
}
