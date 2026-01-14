//! M6 mkdir
//!
//! Create directories.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

use std::println;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("mkdir: not yet implemented");

    // TODO: Implement directory creation via FAT32 service IPC
    0
}
