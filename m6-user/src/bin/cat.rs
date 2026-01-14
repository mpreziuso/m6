//! M6 cat
//!
//! Concatenate and display file contents.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("cat: not yet implemented");

    // TODO: Implement file reading via FAT32 service IPC
    0
}
