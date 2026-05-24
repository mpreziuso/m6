//! M6 echo
//!
//! Print arguments to stdout, separated by spaces, followed by a newline.
//! Arguments are read from the argv page passed via x0 at startup.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::{print, println};

/// Parse argv from the page at `startup_arg()`.
/// Returns the number of arguments (including argv[0]).
///
/// # Safety
///
/// `startup_arg()` must be 0 or a valid ARGS_PAGE_ADDR mapped by the shell.
unsafe fn parse_argv(buf: &mut [*const u8; 16]) -> usize {
    let args_ptr = std::rt::startup_arg();
    if args_ptr == 0 {
        return 0;
    }
    // SAFETY: the shell maps this page before resuming the child
    let argc = unsafe { *(args_ptr as *const u64) } as usize;
    let count = argc.min(16);
    for (i, slot) in buf.iter_mut().enumerate().take(count) {
        // SAFETY: pointer array follows the argc word
        *slot = unsafe { *((args_ptr + 8 + i as u64 * 8) as *const *const u8) };
    }
    count
}

/// Dereference a null-terminated string pointer from the argv page.
///
/// # Safety
///
/// `ptr` must point into the argv page, null-terminated.
unsafe fn str_from_ptr(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        return "";
    }
    // SAFETY: null-terminated string in argv page
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len)) }
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    let mut argv: [*const u8; 16] = [core::ptr::null(); 16];
    // SAFETY: startup_arg() is 0 or valid ARGS_PAGE_ADDR from the shell
    let argc = unsafe { parse_argv(&mut argv) };

    // Print argv[1..], space-separated, then a newline
    for (i, &ptr) in argv.iter().enumerate().take(argc).skip(1) {
        if i > 1 {
            print!(" ");
        }
        // SAFETY: ptr from argv page
        let s = unsafe { str_from_ptr(ptr) };
        print!("{}", s);
    }
    println!();
    0
}
