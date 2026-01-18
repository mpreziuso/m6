//! Memory Types and Memory Map
//!
//! Defines memory region types and the memory map structure.

use crate::boot::MAX_MEMORY_REGIONS;

/// Memory region type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    /// Unusable memory
    Reserved = 0,
    /// Conventional RAM, available for kernel use
    Conventional = 1,
    /// Memory used by UEFI runtime services (must be preserved)
    UefiRuntime = 2,
    /// Memory containing ACPI tables (can be reclaimed after parsing)
    AcpiReclaimable = 3,
    /// Memory containing ACPI NVS (must be preserved)
    AcpiNvs = 4,
    /// Memory-mapped I/O
    Mmio = 5,
    /// Memory used by the bootloader (can be reclaimed)
    BootloaderReclaimable = 6,
    /// Memory used by the kernel image
    KernelImage = 7,
    /// Memory used by kernel page tables
    KernelPageTables = 8,
    /// Memory used by the boot info structure
    BootInfo = 9,
    /// Framebuffer memory
    Framebuffer = 10,
    /// InitRD (initial ramdisk) containing init binary and userspace files
    InitRD = 11,
}

impl MemoryType {
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Conventional,
            2 => Self::UefiRuntime,
            3 => Self::AcpiReclaimable,
            4 => Self::AcpiNvs,
            5 => Self::Mmio,
            6 => Self::BootloaderReclaimable,
            7 => Self::KernelImage,
            8 => Self::KernelPageTables,
            9 => Self::BootInfo,
            10 => Self::Framebuffer,
            11 => Self::InitRD,
            _ => Self::Reserved,
        }
    }

    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(
            self,
            Self::Conventional | Self::BootloaderReclaimable | Self::AcpiReclaimable
        )
    }

    #[must_use]
    pub const fn must_preserve(&self) -> bool {
        matches!(
            self,
            Self::UefiRuntime
                | Self::AcpiNvs
                | Self::KernelImage
                | Self::KernelPageTables
                | Self::BootInfo
                | Self::InitRD
        )
    }
}

/// A single memory region
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryRegion {
    /// Physical start address (page-aligned)
    pub base: u64,
    /// Size in bytes (page-aligned)
    pub size: u64,
    /// Memory type
    pub memory_type: MemoryType,
    /// Reserved for flags
    pub _reserved: u32,
}

impl MemoryRegion {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
            _reserved: 0,
        }
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.size != 0
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

/// Memory map passed from bootloader to kernel
#[derive(Debug)]
#[repr(C)]
pub struct MemoryMap {
    /// Number of valid entries in the regions array
    pub entry_count: u32,
    /// Reserved for alignment
    pub _reserved: u32,
    /// Memory regions (sorted by base address)
    pub regions: [MemoryRegion; MAX_MEMORY_REGIONS],
}

impl MemoryMap {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entry_count: 0,
            _reserved: 0,
            regions: [MemoryRegion::empty(); MAX_MEMORY_REGIONS],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions[..self.entry_count as usize].iter()
    }

    #[must_use]
    pub fn total_usable_memory(&self) -> u64 {
        self.iter()
            .filter(|r| r.memory_type.is_usable())
            .map(|r| r.size)
            .sum()
    }

    #[must_use]
    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.iter().find(|r| r.contains(addr))
    }
}

/// Page size constants
pub mod page {
    /// 4KB page size
    pub const SIZE_4K: usize = 4096;
    /// 16KB page size
    pub const SIZE_16K: usize = 16384;
    /// 2MB huge page size
    pub const SIZE_2M: usize = 2 * 1024 * 1024;

    /// 4KB page shift
    pub const SHIFT_4K: usize = 12;
    /// 16KB page shift
    pub const SHIFT_16K: usize = 14;
    /// 2MB page shift
    pub const SHIFT_2M: usize = 21;

    /// 4KB page mask
    pub const MASK_4K: usize = SIZE_4K - 1;

    // Compile-time verification of page constants
    const _: () = assert!(SIZE_4K.is_power_of_two(), "SIZE_4K must be a power of two");
    const _: () = assert!(
        SIZE_16K.is_power_of_two(),
        "SIZE_16K must be a power of two"
    );
    const _: () = assert!(SIZE_2M.is_power_of_two(), "SIZE_2M must be a power of two");
    const _: () = assert!(SHIFT_4K == 12, "4KB page shift must be 12");
    const _: () = assert!(1 << SHIFT_4K == SIZE_4K, "SHIFT_4K must match SIZE_4K");
    const _: () = assert!(1 << SHIFT_16K == SIZE_16K, "SHIFT_16K must match SIZE_16K");
    const _: () = assert!(1 << SHIFT_2M == SIZE_2M, "SHIFT_2M must match SIZE_2M");
    const _: () = assert!(MASK_4K == SIZE_4K - 1, "MASK_4K must be SIZE_4K - 1");

    #[must_use]
    pub const fn align_down_4k(addr: usize) -> usize {
        addr & !MASK_4K
    }

    #[must_use]
    pub const fn align_up_4k(addr: usize) -> usize {
        (addr + MASK_4K) & !MASK_4K
    }

    #[must_use]
    pub const fn is_aligned_4k(addr: usize) -> bool {
        addr & MASK_4K == 0
    }
}
