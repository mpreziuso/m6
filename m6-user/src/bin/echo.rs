//! M6 echo
//!
//! Display a line of text.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

use std::println;

#[unsafe(no_mangle)]
fn main() -> i32 {
    // TODO: Get arguments and print them
    println!("echo: not yet implemented");
    0
}
