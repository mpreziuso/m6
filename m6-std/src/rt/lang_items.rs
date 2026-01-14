//! Language items required by Rust
//!
//! Provides panic handler and other lang items for no_std environments.

use core::panic::PanicInfo;

use m6_syscall::invoke::{debug_putc, sched_yield};

/// Panic handler for m6-std programs.
///
/// Prints the panic message to the debug console and loops forever.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Print "PANIC: " prefix
    for c in b"PANIC: " {
        debug_putc(*c);
    }

    // Print location if available
    if let Some(location) = info.location() {
        // Print file
        for c in location.file().bytes() {
            debug_putc(c);
        }
        debug_putc(b':');

        // Print line number
        print_u32(location.line());

        debug_putc(b' ');
    }

    // Print the message if available
    if let Some(message) = info.message().as_str() {
        for c in message.bytes() {
            debug_putc(c);
        }
    } else {
        for c in b"<no message>" {
            debug_putc(*c);
        }
    }

    debug_putc(b'\n');

    // Loop forever, yielding to allow other tasks to run
    loop {
        sched_yield();
    }
}

/// Print a u32 as decimal digits.
fn print_u32(mut n: u32) {
    if n == 0 {
        debug_putc(b'0');
        return;
    }

    let mut digits = [0u8; 10];
    let mut i = 0;

    while n > 0 {
        digits[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        debug_putc(digits[i]);
    }
}
