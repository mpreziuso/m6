//! Virtual Address Space Layout
//!
//! Defines the kernel's virtual memory layout for ARM64 with 48-bit virtual addressing.

use m6_common::boot::KERNEL_PHYS_MAP_BASE;

/// Virtual address space regions.
///
/// Memory layout (48-bit virtual addresses):
/// ```text
/// 0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF : User space (lower half)
/// 0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF : Non-canonical (hole)
/// 0xFFFF_8000_0000_0000 - 0xFFFF_8000_XXXX_XXXX : Direct physical map (dynamic size)
/// 0xFFFF_FFFE_0000_0000 - 0xFFFF_FFFE_FFFF_FFFF : Device MMIO region
/// 0xFFFF_FFFF_8000_0000 - 0xFFFF_FFFF_BFFF_FFFF : Kernel image
/// 0xFFFF_FFFF_C000_0000 - 0xFFFF_FFFF_CFFF_FFFF : Kernel heap VA reservation
/// ```
pub mod virt {
    /// Kernel virtual base (upper half, where kernel image is loaded)
    pub const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

    /// Kernel heap virtual address start
    pub const KERNEL_HEAP_START: u64 = 0xFFFF_FFFF_C000_0000;

    /// Kernel heap virtual address reservation (256 MB)
    pub const KERNEL_HEAP_VA_SIZE: usize = 256 * 1024 * 1024;

    /// Device MMIO mapping region
    pub const DEVICE_MMIO_START: u64 = 0xFFFF_FFFE_0000_0000;

    /// User space virtual address limit (end of lower canonical half)
    pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

    /// Direct physical map base address.
    ///
    /// All physical memory (up to max_phys_addr) is mapped linearly here.
    /// Virtual = PHYS_MAP_BASE + Physical
    ///
    /// Re-exported from m6-common for consistency.
    pub const PHYS_MAP_BASE: u64 = super::KERNEL_PHYS_MAP_BASE;
}
