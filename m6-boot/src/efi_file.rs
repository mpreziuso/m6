//! EFI file reading utility
//!
//! Provides a helper to read files from the EFI system partition.

extern crate alloc;

use alloc::vec::Vec;
use uefi::boot::{self};
use uefi::fs::FileSystem;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::CStr16;

/// Reads a file from the EFI system partition.
/// Returns None if the file is not found or invalid.
pub fn read_efi_file(path: &str) -> Option<Vec<u8>> {
    let sfs_handle = boot::get_handle_for_protocol::<SimpleFileSystem>().ok()?;
    let sfs = boot::open_protocol_exclusive::<SimpleFileSystem>(sfs_handle).ok()?;
    let mut fs = FileSystem::new(sfs);
    let mut path_buf = [0u16; 64];
    let cpath = CStr16::from_str_with_buf(path, &mut path_buf).ok()?;
    fs.read(cpath).ok()
}
