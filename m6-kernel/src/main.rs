//! M6 Kernel

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;
use core::ptr;
use m6_common::boot::BootInfo;

/// Kernel entry point called by the bootloader
///
/// # Safety
/// This function is called directly by the bootloader with a valid BootInfo pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(boot_info: *const BootInfo) -> ! {
    // Validate boot info
    let boot_info = unsafe { &*boot_info };
    if !boot_info.is_valid() {
        halt();
    }

    // Initialize UART
    let uart = Uart::new(boot_info.uart_virt_base.as_u64());
    
    // Print hello message
    uart.write_str("hello from kernel\n");

    // Halt forever
    halt();
}

/// Panic handler - required for no_std
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt();
}

/// Halt the CPU
fn halt() -> ! {
    m6_arch::halt();
}

/// Simple UART driver for ARM PL011
struct Uart {
    base: u64,
}

impl Uart {
    /// Create a new UART instance
    const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Write a single byte to UART
    fn write_byte(&self, byte: u8) {
        unsafe {
            // Wait for TX FIFO to have space
            while (ptr::read_volatile((self.base + 0x18) as *const u32) & (1 << 5)) != 0 {
                core::hint::spin_loop();
            }
            // Write data
            ptr::write_volatile(self.base as *mut u8, byte);
        }
    }

    /// Write a string to UART
    fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}
