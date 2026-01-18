//! UEFI Bootloader
//!
//! This bootloader:
//! 1. Obtains the memory map from UEFI
//! 2. Loads the kernel ELF image
//! 3. Sets up initial page tables
//! 4. Prepares the BootInfo structure
//! 5. Exits boot services and jumps to kernel

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod dtb_devices;
pub mod efi_file;
pub mod gop;
pub mod initrd_loader;
pub mod kernel_loader;
pub mod memory;
pub mod page_table;
