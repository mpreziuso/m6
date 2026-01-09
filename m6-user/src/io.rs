//! I/O utilities for userspace
//!
//! Provides basic output functions using debug syscalls.

use m6_syscall::invoke::debug_putc;

/// Print a string using the debug syscall.
pub fn puts(s: &str) {
    for byte in s.bytes() {
        debug_putc(byte);
    }
}

/// Print a decimal number.
pub fn put_u64(mut n: u64) {
    if n == 0 {
        debug_putc(b'0');
        return;
    }

    // Maximum digits in u64 is 20
    let mut buf = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Print in reverse order
    while i > 0 {
        i -= 1;
        debug_putc(buf[i]);
    }
}

/// Print a hexadecimal number with 0x prefix.
pub fn put_hex(n: u64) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";

    puts("0x");

    // Find the highest non-zero nibble
    if n == 0 {
        debug_putc(b'0');
        return;
    }

    // Calculate number of hex digits needed
    let mut started = false;
    for shift in (0..16).rev() {
        let nibble = ((n >> (shift * 4)) & 0xF) as usize;
        if nibble != 0 || started {
            debug_putc(HEX_CHARS[nibble]);
            started = true;
        }
    }
}

/// Print a newline.
pub fn newline() {
    debug_putc(b'\n');
}
