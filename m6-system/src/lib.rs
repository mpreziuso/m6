#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod elf;
pub mod process;

// Re-export for shell use — avoids adding m6-syscall as a direct dep in m6-user.
pub use m6_syscall::{invoke, numbers, slot_to_cptr};

/// Virtual address where init maps the initrd into the shell's VSpace.
pub const SHELL_INITRD_ADDR: u64 = 0x0000_0002_0000_0000;

// -- svc-starnix boot-ELF hand-off
//
// On flashed hardware the only runtime-readable store is the initrd (loaded
// into RAM by the bootloader) — there is no SD/eMMC driver, and the NVMe is
// not provisioned at flash time. So the shell resolves the Linux binary from
// the initrd and maps it, plus a small info page, into svc-starnix's VSpace
// at these fixed addresses before resuming it. svc-starnix loads the ELF from
// this mapping instead of reading it from the FAT32 (NVMe-backed) service.

/// Boot-info page mapped into svc-starnix: `[magic u64][elf vaddr u64][elf len u64]`.
pub const STARNIX_BOOTELF_INFO_ADDR: u64 = 0x7000_0000;

/// Where the Linux ELF image itself is mapped in svc-starnix's VSpace.
pub const STARNIX_BOOTELF_DATA_ADDR: u64 = 0x7000_1000;

/// Magic at offset 0 of the boot-info page; absence means no ELF was handed over.
pub const STARNIX_BOOTELF_MAGIC: u64 = 0x4D36_4C58_454C_4631;

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
