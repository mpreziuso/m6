//! M6 ls
//!
//! List directory contents.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("ls: not yet implemented");

    // TODO: Implement directory listing via FAT32 service IPC
    0
}
