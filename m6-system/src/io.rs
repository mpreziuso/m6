//! I/O utilities for userspace
//!
//! Provides console output using IPC when a UART driver is available,
//! falling back to debug syscalls for early boot.

use core::sync::atomic::{AtomicU64, Ordering};
use m6_syscall::invoke::{debug_puts, send};

/// UART driver endpoint slot (0 = not initialised, use debug syscall fallback)
static UART_ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// Initialise the console with a UART driver endpoint.
///
/// After calling this, `puts()` and other output functions will use IPC
/// to communicate with the UART driver instead of the debug syscall.
#[allow(dead_code)]
pub fn init_console(uart_ep: u64) {
    UART_ENDPOINT.store(uart_ep, Ordering::Release);
}

/// Check if IPC console is available.
#[inline]
#[expect(dead_code)]
pub fn has_ipc_console() -> bool {
    UART_ENDPOINT.load(Ordering::Acquire) != 0
}

/// Print a string.
///
/// Uses IPC to UART driver if available, otherwise uses debug syscall.
pub fn puts(s: &str) {
    let ep = UART_ENDPOINT.load(Ordering::Acquire);
    if ep != 0 {
        ipc_write_string(ep, s);
    } else {
        debug_puts(s);
    }
}

/// Write a string via IPC to the UART driver.
///
/// Sends data in chunks of up to 24 bytes per message (using x1-x3,
/// with length encoded in x0's upper bits). x0 contains the label.
fn ipc_write_string(ep: u64, s: &str) {
    let bytes = s.as_bytes();

    // Send in chunks of 24 bytes (3 data registers × 8 bytes each)
    // Note: send() passes label + 3 data words via x1-x4
    for chunk in bytes.chunks(24) {
        // Pack bytes into registers x1-x3
        let mut regs = [0u64; 3];
        for (i, &byte) in chunk.iter().enumerate() {
            let reg_idx = i / 8;
            let byte_idx = i % 8;
            regs[reg_idx] |= (byte as u64) << (byte_idx * 8);
        }

        // x0 = WRITE_INLINE label | (length << 32)
        let x0 = 0x0001u64 | ((chunk.len() as u64) << 32);

        // Send and ignore result (fire-and-forget for console output)
        let _ = send(ep, x0, regs[0], regs[1], regs[2]);
    }
}

/// Print a decimal number.
pub fn put_u64(mut n: u64) {
    if n == 0 {
        puts("0");
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

    // Reverse the digits
    let mut reversed = [0u8; 20];
    let len = i;
    for j in 0..len {
        reversed[j] = buf[len - 1 - j];
    }

    // SAFETY: We just filled this with ASCII digits
    let s = unsafe { core::str::from_utf8_unchecked(&reversed[..len]) };
    puts(s);
}

/// Print a hexadecimal number with 0x prefix.
#[allow(dead_code)]
pub fn put_hex(n: u64) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";

    puts("0x");

    if n == 0 {
        puts("0");
        return;
    }

    // Build hex string
    let mut buf = [0u8; 16];
    let mut len = 0;
    let mut started = false;

    for shift in (0..16).rev() {
        let nibble = ((n >> (shift * 4)) & 0xF) as usize;
        if nibble != 0 || started {
            buf[len] = HEX_CHARS[nibble];
            len += 1;
            started = true;
        }
    }

    // SAFETY: We just filled this with hex chars
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..len]) };
    puts(s);
}

/// Print a newline.
pub fn newline() {
    puts("\n");
}

/// Print a byte as two hex digits (no prefix).
#[allow(dead_code)]
pub fn put_hex_byte(b: u8) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut buf = [0u8; 2];
    buf[0] = HEX_CHARS[(b >> 4) as usize];
    buf[1] = HEX_CHARS[(b & 0xF) as usize];
    // SAFETY: We just filled this with hex chars
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    puts(s);
}

/// Print a 16-bit value as hex (no prefix).
#[allow(dead_code)]
pub fn put_hex16(v: u16) {
    put_hex_byte((v >> 8) as u8);
    put_hex_byte(v as u8);
}

/// Print a 32-bit value as hex (no prefix).
#[allow(dead_code)]
pub fn put_hex32(v: u32) {
    put_hex_byte((v >> 24) as u8);
    put_hex_byte((v >> 16) as u8);
    put_hex_byte((v >> 8) as u8);
    put_hex_byte(v as u8);
}
