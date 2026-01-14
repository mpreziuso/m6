//! M6 ls
//!
//! List directory contents.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

use std::println;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("ls: not yet implemented");

    // TODO: Implement directory listing via FAT32 service IPC
    0
}
