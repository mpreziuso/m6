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

/// Boot-info page mapped into svc-starnix. Layout (little-endian u64s):
///   [0]  magic
///   [1]  main ELF vaddr (= STARNIX_BOOTELF_DATA_ADDR)
///   [2]  main ELF length
///   [3]  rootfs file count N
///   then N × { [path vaddr][path len][data vaddr][data len] } starting at [4].
/// N is 0 for a plain static binary (e.g. busybox), making the rootfs path a
/// no-op. Extra files (an ELF interpreter, shared libraries, data) are laid down
/// into the Starnix tmpfs at their path before exec — see [`for_each_rootfs_entry`].
pub const STARNIX_BOOTELF_INFO_ADDR: u64 = 0x7000_0000;

/// Where the Linux ELF image itself is mapped in svc-starnix's VSpace.
pub const STARNIX_BOOTELF_DATA_ADDR: u64 = 0x7000_1000;

/// Magic at offset 0 of the boot-info page; absence means no ELF was handed over.
pub const STARNIX_BOOTELF_MAGIC: u64 = 0x4D36_4C58_454C_4631;

/// Where the packed rootfs path strings are mapped in svc-starnix's VSpace.
pub const STARNIX_ROOTFS_PATHS_ADDR: u64 = 0x7100_0000;

/// Base address where rootfs file contents are mapped (each page-aligned,
/// sequential) in svc-starnix's VSpace.
pub const STARNIX_ROOTFS_DATA_BASE: u64 = 0x7800_0000;

/// One past the last address usable for rootfs file contents. svc-starnix maps
/// its restricted-mode state frame at `0x8000_0000`, so rootfs data must stay
/// below it — the shell refuses to map a file that would cross this ceiling.
pub const STARNIX_ROOTFS_DATA_LIMIT: u64 = 0x8000_0000;

/// Initrd path prefix marking files to extract into the Starnix tmpfs. An entry
/// `rootfs/lib/ld-musl-aarch64.so.1` is laid down at `/lib/ld-musl-aarch64.so.1`.
pub const STARNIX_ROOTFS_PREFIX: &str = "rootfs/";

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

/// Invoke `f(tmpfs_path, data)` for every initrd entry under
/// [`STARNIX_ROOTFS_PREFIX`], with the prefix stripped and a leading `/` added so
/// the path is absolute in the tmpfs (`rootfs/lib/x.so` → `/lib/x.so`). Entries
/// whose name is exactly the prefix (the directory itself) are skipped.
pub fn for_each_rootfs_entry<'a>(initrd: &'a [u8], mut f: impl FnMut(&str, &'a [u8])) {
    let Ok(archive) = tar_no_std::TarArchiveRef::new(initrd) else {
        return;
    };
    for entry in archive.entries() {
        // Bind the filename locally so its `as_str()` borrow outlives the call.
        let filename = entry.filename();
        let Ok(name) = filename.as_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(STARNIX_ROOTFS_PREFIX) else {
            continue;
        };
        // Skip the directory entry and any nested directory markers (trailing `/`).
        if rest.is_empty() || rest.ends_with('/') {
            continue;
        }
        f(rest, entry.data());
    }
}
