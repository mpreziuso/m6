//! Bare-metal test harness for aarch64-unknown-none.
//!
//! Provides a custom test runner, semihosting-based QEMU exit, and an
//! assembly entry point with stack setup. Include via dev-dependency and
//! `test_entry!()` at crate root.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

// -- Stack

/// 4 MB stack for the test runner.
///
/// Tests may allocate large buffers as local variables (e.g. 256 KB heap
/// arrays in allocator tests), so the stack must be much larger than the
/// typical 64 KB default.
#[unsafe(no_mangle)]
pub static mut M6_TEST_STACK: [u8; 4 * 1024 * 1024] = [0u8; 4 * 1024 * 1024];

core::arch::global_asm!(
    ".section .text._start",
    ".global _start",
    "_start:",
    // Enable FP/SIMD at EL1: CPACR_EL1.FPEN = 0b11 (bits 21:20).
    // Without this, any compiler-generated SIMD instruction (e.g. from
    // bounds-checking helpers) traps to the FP/SIMD exception vector,
    // which is invalid since we have no vector table.
    "    mrs x0, cpacr_el1",
    "    mov x1, #0x300000",
    "    orr x0, x0, x1",
    "    msr cpacr_el1, x0",
    "    isb",
    // Set up the stack pointer to the top of M6_TEST_STACK, 16-byte aligned.
    "    adrp x0, M6_TEST_STACK",
    "    add  x0, x0, :lo12:M6_TEST_STACK",
    "    add  x0, x0, #0x400000",
    "    and  x0, x0, #0xFFFFFFFFFFFFFFF0",
    "    mov  sp, x0",
    "    b    m6_test_run",
);

// -- Test runner

/// Custom test runner: iterates tests, prints `[N/M]` progress.
///
/// On completion returns normally so the caller (`m6_test_run` via
/// `test_entry!`) can invoke `exit(true)`. On any test failure (panic),
/// the `#[panic_handler]` calls `exit(false)`.
pub fn runner(tests: &[&dyn Fn()]) {
    let total = tests.len();
    puts("running ");
    put_usize(total);
    puts(" test(s)\n");

    for (i, test) in tests.iter().enumerate() {
        puts("[");
        put_usize(i + 1);
        puts("/");
        put_usize(total);
        puts("] ... ");
        test();
        puts("ok\n");
    }

    puts("all tests passed\n");
}

// -- Semihosting exit

/// Exit QEMU with success or failure via AArch64 semihosting SYS_EXIT.
pub fn exit(success: bool) -> ! {
    // Parameter block: [reason, subcode].
    // ADP_Stopped_ApplicationExit (0x20026), subcode 0  → QEMU exit 0.
    // ADP_Stopped_RunTimeErrorUnknown (0x20024), subcode 1 → QEMU exit 1.
    let block: [u64; 2] = if success {
        [0x20026, 0]
    } else {
        [0x20024, 1]
    };

    // SAFETY: semihosting HLT #0xf000 is only valid in QEMU with
    // -semihosting-config enable=on. x0=0x18 (SYS_EXIT), x1=block ptr.
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") 0x18_u64,
            in("x1") block.as_ptr(),
            options(nostack, noreturn),
        );
    }
}

// -- Output helpers (semihosting SYS_WRITE0 — one call per string)

/// Write a null-terminated string to the semihosting console (SYS_WRITE0).
///
/// Copies `s` into a 512-byte stack buffer, appends `\0`, then issues one
/// `HLT #0xf000` semihosting call.  Strings longer than 511 bytes are
/// silently truncated.
pub fn puts(s: &str) {
    let mut buf = [0u8; 512];
    let len = s.len().min(511);
    buf[..len].copy_from_slice(&s.as_bytes()[..len]);
    // buf[len] is already 0 (null-terminator).

    // SAFETY: semihosting SYS_WRITE0 (0x04) — x1 = pointer to
    // null-terminated string.  buf lives on the stack for the duration
    // of this asm block.
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") 0x04_u64,
            in("x1") buf.as_ptr(),
            options(nostack),
        );
    }
}

/// Write a `usize` as decimal digits to the semihosting console.
pub fn put_usize(n: usize) {
    let mut buf = [0u8; 20];
    let s = if n == 0 {
        buf[0] = b'0';
        &buf[..1]
    } else {
        let mut i = buf.len();
        let mut val = n;
        while val > 0 {
            i -= 1;
            buf[i] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        &buf[i..]
    };
    // SAFETY: buf[i..] contains only ASCII digit bytes.
    puts(unsafe { core::str::from_utf8_unchecked(s) });
}

/// Write a single byte to the semihosting console.
pub fn putc(c: u8) {
    puts(unsafe { core::str::from_utf8_unchecked(core::slice::from_ref(&c)) });
}

// -- Panic handler

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    puts("PANIC");
    if let Some(msg) = info.message().as_str() {
        puts(": ");
        puts(msg);
    }
    if let Some(loc) = info.location() {
        puts(" at ");
        puts(loc.file());
        puts(":");
        put_usize(loc.line() as usize);
    }
    puts("\n");
    exit(false)
}

// -- test_entry! macro

/// Emit the `m6_test_run` entry point called from the `_start` stub.
///
/// Place this at crate root alongside the `cfg_attr` test attributes.
/// It expands only under `#[cfg(test)]`.
///
/// ```rust,ignore
/// #[cfg(test)]
/// m6_testlib::test_entry!();
/// ```
#[macro_export]
macro_rules! test_entry {
    () => {
        #[cfg(test)]
        #[allow(missing_docs)]
        #[unsafe(no_mangle)]
        pub extern "C" fn m6_test_run() -> ! {
            test_main();
            m6_testlib::exit(true)
        }
    };
}
