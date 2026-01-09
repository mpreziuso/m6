//! InitRD handling
//!
//! Parses USTAR tar archives from the bootloader-provided initrd and loads
//! ELF binaries for userspace execution.

pub mod elf_loader;
pub mod tar;

use m6_common::boot::BootInfo;

use crate::memory::translate::phys_to_virt;

/// Find a file in the initrd by name.
///
/// # Arguments
///
/// * `boot_info` - Boot information containing initrd location
/// * `name` - Name of the file to find (without leading slash)
///
/// # Returns
///
/// A slice containing the file data, or `None` if not found or no initrd.
pub fn find_file<'a>(boot_info: &BootInfo, name: &str) -> Option<&'a [u8]> {
    if !boot_info.has_initrd() {
        log::debug!("No initrd present");
        return None;
    }

    let initrd_virt = phys_to_virt(boot_info.initrd_phys_base.0);
    // SAFETY: The bootloader guarantees the initrd is valid and mapped
    // in the direct physical map.
    let initrd = unsafe {
        core::slice::from_raw_parts(initrd_virt as *const u8, boot_info.initrd_size as usize)
    };

    tar::find_file(initrd, name)
}

/// List all files in the initrd.
///
/// This is primarily for debugging purposes.
pub fn list_files(boot_info: &BootInfo) {
    if !boot_info.has_initrd() {
        log::info!("No initrd present");
        return;
    }

    let initrd_virt = phys_to_virt(boot_info.initrd_phys_base.0);
    // SAFETY: The bootloader guarantees the initrd is valid and mapped.
    let initrd = unsafe {
        core::slice::from_raw_parts(initrd_virt as *const u8, boot_info.initrd_size as usize)
    };

    log::info!("InitRD contents ({} bytes):", boot_info.initrd_size);
    tar::list_files(initrd);
}
