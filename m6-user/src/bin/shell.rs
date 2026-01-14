//! M6 Shell
//!
//! Interactive command shell for M6 userspace.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::{print, println, thread};
use core::time::Duration;

#[unsafe(no_mangle)]
fn main() -> i32 {
    // Print banner
    println!("\n\x1b[36m=== M6 Shell v0.1 ===\x1b[0m");
    println!("Shell running in userspace (m6-std runtime)");
    println!("Input handling not yet implemented.\n");
    print!("\x1b[32mm6>\x1b[0m ");

    // Idle loop - sleep to avoid 100% CPU usage
    // Input handling will be added later
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
