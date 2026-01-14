//! M6 cp
//!
//! Copy files.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("cp: not yet implemented");

    // TODO: Implement file copying via FAT32 service IPC
    0
}
