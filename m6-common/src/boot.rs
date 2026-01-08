//! Boot Handoff Protocol
//!
//! Defines the structure passed from the bootloader to the kernel.

use crate::addr::{PhysAddr, VirtAddr};
use crate::memory::MemoryMap;

/// Magic number for boot info validation: "M6BOOT\0\0" as u64
pub const BOOT_INFO_MAGIC: u64 = 0x00_00_54_4F_4F_42_36_4D;

/// Boot info version for compatibility checking
/// Version 1: Initial version
/// Version 2: Added initrd support
/// Version 3: Added frame bitmap and max_phys_addr for dynamic memory
pub const BOOT_INFO_VERSION: u32 = 3;

/// Maximum number of memory regions supported
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Virtual base address of kernel direct physical map in TTBR1
/// All physical memory is mapped at KERNEL_PHYS_MAP_BASE + phys_addr
pub const KERNEL_PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Framebuffer information for early graphics
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    /// Physical base address of the framebuffer
    pub base: u64,
    /// Size of the framebuffer in bytes
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Stride (bytes per row)
    pub stride: u32,
    /// Bits per pixel
    pub bpp: u32,
    /// Red mask position
    pub red_position: u8,
    /// Red mask size
    pub red_size: u8,
    /// Green mask position
    pub green_position: u8,
    /// Green mask size
    pub green_size: u8,
    /// Blue mask position
    pub blue_position: u8,
    /// Blue mask size
    pub blue_size: u8,
    /// Reserved
    pub _reserved: [u8; 2],
}

impl FramebufferInfo {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            width: 0,
            height: 0,
            stride: 0,
            bpp: 0,
            red_position: 0,
            red_size: 0,
            green_position: 0,
            green_size: 0,
            blue_position: 0,
            blue_size: 0,
            _reserved: [0; 2],
        }
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.base != 0 && self.size != 0 && self.width != 0 && self.height != 0
    }
}

/// Boot information passed from bootloader to kernel
///
/// This struct uses a fixed layout to ensure ABI stability between
/// the bootloader and kernel, even if compiled separately.
#[derive(Debug)]
#[repr(C)]
pub struct BootInfo {
    /// Magic number for validation (must be BOOT_INFO_MAGIC)
    pub magic: u64,
    /// Version of the boot info structure
    pub version: u32,
    /// Physical address where the kernel was loaded
    pub kernel_phys_base: PhysAddr,
    /// Virtual address where the kernel is mapped
    pub kernel_virt_base: VirtAddr,
    /// Size of the kernel image in bytes
    pub kernel_size: u64,
    /// Physical address of the initial page tables
    pub page_table_base: PhysAddr,
    /// Size of the page table allocation in bytes
    pub page_table_size: u64,
    /// Memory map from UEFI
    pub memory_map: MemoryMap,
    /// Optional framebuffer information
    pub framebuffer: FramebufferInfo,
    /// Physical address of ACPI RSDP (0 if not available)
    pub acpi_rsdp: PhysAddr,
    /// Physical address of device tree blob (0 if not available)
    pub dtb_address: PhysAddr,
    /// Kernel virtual address for GIC (mapped in TTBR1)
    pub gic_virt_base: VirtAddr,
    /// Kernel virtual address for UART (mapped in TTBR1)
    pub uart_virt_base: VirtAddr,
    /// Physical address of initrd (0 if not present)
    pub initrd_phys_base: PhysAddr,
    /// Size of initrd in bytes (0 if not present)
    pub initrd_size: u64,
    /// Physical address of the frame allocator bitmap (allocated by bootloader)
    pub frame_bitmap_phys: PhysAddr,
    /// Size of the frame allocator bitmap in bytes
    pub frame_bitmap_size: u64,
    /// Maximum physical address detected from memory map
    /// Used to configure direct physical map size and frame allocator range
    pub max_phys_addr: u64,
    /// Reserved for future use
    pub _reserved: [u64; 1],
}

impl BootInfo {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC && self.version == BOOT_INFO_VERSION
    }

    #[must_use]
    pub const fn has_initrd(&self) -> bool {
        !self.initrd_phys_base.is_null() && self.initrd_size != 0
    }
}

/// RSDP signature "RSD PTR " as bytes
pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
