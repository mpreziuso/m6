//! M6 cat
//!
//! Concatenate and display file contents.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

use std::println;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("cat: not yet implemented");

    // TODO: Implement file reading via FAT32 service IPC
    0
}
