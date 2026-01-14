//! M6 Shell
//!
//! Interactive command shell for M6 userspace.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

use std::println;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("M6 Shell starting...");
    println!("Type 'help' for available commands.");

    // TODO: Implement shell loop
    loop {
        std::process::yield_now();
    }
}
