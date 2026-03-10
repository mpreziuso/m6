//! EFI file reading utility
//!
//! Provides a helper to read files from the EFI system partition.

extern crate alloc;

use alloc::vec::Vec;
use uefi::CStr16;
use uefi::boot;
use uefi::fs::FileSystem;

/// Reads a file from the EFI system partition (the volume the bootloader was loaded from).
/// Returns None if the file is not found or invalid.
pub fn read_efi_file(path: &str) -> Option<Vec<u8>> {
    let sfs = boot::get_image_file_system(boot::image_handle()).ok()?;
    let mut fs = FileSystem::new(sfs);
    let mut path_buf = [0u16; 64];
    let cpath = CStr16::from_str_with_buf(path, &mut path_buf).ok()?;
    fs.read(cpath).ok()
}
