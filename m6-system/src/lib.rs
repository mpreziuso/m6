#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod elf;
pub mod process;

// Re-export for shell use — avoids adding m6-syscall as a direct dep in m6-user.
pub use m6_syscall::{invoke, slot_to_cptr};

/// Virtual address where init maps the initrd into the shell's VSpace.
pub const SHELL_INITRD_ADDR: u64 = 0x0000_0002_0000_0000;

/// Find a named file in the initrd TAR archive.
pub fn find_in_initrd<'a>(initrd: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let archive = tar_no_std::TarArchiveRef::new(initrd).ok()?;
    for entry in archive.entries() {
        if entry.filename().as_str() == Ok(name) {
            return Some(entry.data());
        }
    }
    None
}
