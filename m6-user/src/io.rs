//! I/O utilities for userspace
//!
//! Provides console output using IPC when a UART driver is available,
//! falling back to debug syscalls for early boot.

use core::sync::atomic::{AtomicU64, Ordering};
use m6_syscall::invoke::{debug_putc, send};

/// UART driver endpoint slot (0 = not initialised, use debug syscall fallback)
static UART_ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// Initialise the console with a UART driver endpoint.
///
/// After calling this, `puts()` and other output functions will use IPC
/// to communicate with the UART driver instead of the debug syscall.
pub fn init_console(uart_ep: u64) {
    UART_ENDPOINT.store(uart_ep, Ordering::Release);
}

/// Check if IPC console is available.
#[inline]
pub fn has_ipc_console() -> bool {
    UART_ENDPOINT.load(Ordering::Acquire) != 0
}

/// Print a string.
///
/// Uses IPC to UART driver if available, otherwise falls back to debug syscall.
pub fn puts(s: &str) {
    let ep = UART_ENDPOINT.load(Ordering::Acquire);
    if ep != 0 {
        ipc_write_string(ep, s);
    } else {
        for byte in s.bytes() {
            debug_putc(byte);
        }
    }
}

/// Write a string via IPC to the UART driver.
///
/// Sends data in chunks of up to 32 bytes per message (using x1-x4,
/// with length encoded in x0's upper bits).
fn ipc_write_string(ep: u64, s: &str) {
    let bytes = s.as_bytes();

    // Send in chunks of 32 bytes (4 registers × 8 bytes each)
    for chunk in bytes.chunks(32) {
        // Pack bytes into registers x1-x4
        let mut regs = [0u64; 4];
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
        let ep = UART_ENDPOINT.load(Ordering::Acquire);
        if ep != 0 {
            ipc_write_string(ep, "0");
        } else {
            debug_putc(b'0');
        }
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

    let ep = UART_ENDPOINT.load(Ordering::Acquire);
    if ep != 0 {
        // SAFETY: We just filled this with ASCII digits
        let s = unsafe { core::str::from_utf8_unchecked(&reversed[..len]) };
        ipc_write_string(ep, s);
    } else {
        for j in 0..len {
            debug_putc(reversed[j]);
        }
    }
}

/// Print a hexadecimal number with 0x prefix.
pub fn put_hex(n: u64) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";

    puts("0x");

    if n == 0 {
        let ep = UART_ENDPOINT.load(Ordering::Acquire);
        if ep != 0 {
            ipc_write_string(ep, "0");
        } else {
            debug_putc(b'0');
        }
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

    let ep = UART_ENDPOINT.load(Ordering::Acquire);
    if ep != 0 {
        // SAFETY: We just filled this with hex chars
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..len]) };
        ipc_write_string(ep, s);
    } else {
        for i in 0..len {
            debug_putc(buf[i]);
        }
    }
}

/// Print a newline.
pub fn newline() {
    puts("\n");
}
