//! InitRD Loader
//!
//! Loads the initial ramdisk from the EFI system partition.
//! The initrd contains the init binary and other userspace files.

extern crate alloc;

use crate::config::{INITRD_PATH, MAX_INITRD_SIZE};
use crate::efi_file::read_efi_file;
use alloc::vec::Vec;
use uefi::boot::{self, AllocateType, MemoryType};

/// Loaded initrd information
pub struct LoadedInitRD {
    /// Physical address where initrd is loaded
    pub phys_base: u64,
    /// Size of the initrd in bytes
    pub size: u64,
}

/// Load the initrd from the EFI filesystem
///
/// Returns None if initrd is not found (this is not an error - initrd is optional)
pub fn load_initrd() -> Option<LoadedInitRD> {
    log::info!("Looking for initrd at {}", INITRD_PATH);
    let initrd_data: Vec<u8> = read_efi_file(INITRD_PATH)?;
    if initrd_data.is_empty() {
        log::warn!("Initrd file is empty");
        return None;
    }
    if initrd_data.len() > MAX_INITRD_SIZE {
        log::error!(
            "Initrd too large: {} bytes (max {} bytes)",
            initrd_data.len(),
            MAX_INITRD_SIZE
        );
        return None;
    }
    log::info!("Initrd found: {} bytes", initrd_data.len());

    // Allocate physical memory for the initrd
    let num_pages = initrd_data.len().div_ceil(4096);
    let initrd_phys = match boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        num_pages,
    ) {
        Ok(ptr) => ptr,
        Err(e) => {
            log::error!("Failed to allocate memory for initrd: {:?}", e);
            return None;
        }
    };

    log::info!(
        "Allocated {} pages for initrd at physical {:#x}",
        num_pages,
        initrd_phys.as_ptr() as u64
    );

    // Copy initrd data to allocated memory
    // SAFETY: We just allocated this memory and initrd_data is valid
    unsafe {
        core::ptr::copy_nonoverlapping(
            initrd_data.as_ptr(),
            initrd_phys.as_ptr(),
            initrd_data.len(),
        );
    }

    Some(LoadedInitRD {
        phys_base: initrd_phys.as_ptr() as u64,
        size: initrd_data.len() as u64,
    })
}
