//! Boot Handoff Protocol
//!
//! Defines the structure passed from the bootloader to the kernel.

use crate::addr::{PhysAddr, VirtAddr};
use crate::memory::MemoryMap;

/// Magic number for boot info validation: "M6BOOT\0\0" as u64
pub const BOOT_INFO_MAGIC: u64 = 0x00_00_54_4F_4F_42_36_4D;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 8;

/// Boot info version for compatibility checking
/// Version 1: Initial version
/// Version 2: Added initrd support
/// Version 3: Added frame bitmap and max_phys_addr for dynamic memory
/// Version 4: Added SMP support (cpu_count, per_cpu_stacks)
/// Version 5: Added ttbr0_el1 for secondary CPU MMU setup
/// Version 6: Added framebuffer virt_base for GOP support
/// Version 7: Added tcr_el1 with dynamic IPS for secondary CPU MMU setup
pub const BOOT_INFO_VERSION: u32 = 7;

/// Maximum number of memory regions supported
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Virtual base address of kernel direct physical map in TTBR1
/// All physical memory is mapped at KERNEL_PHYS_MAP_BASE + phys_addr
pub const KERNEL_PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Per-CPU kernel stack information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PerCpuStackInfo {
    /// Physical address of stack base (low address, not top)
    pub phys_base: PhysAddr,
    /// Virtual address of stack top (high address, where SP starts)
    pub virt_top: VirtAddr,
}

impl PerCpuStackInfo {
    /// Create an empty/uninitialised stack info.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            phys_base: PhysAddr::new(0),
            virt_top: VirtAddr::new(0),
        }
    }

    /// Check if this stack info is valid (non-zero addresses).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.phys_base.as_u64() != 0 && self.virt_top.as_u64() != 0
    }
}

/// Framebuffer information for early graphics
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    /// Physical base address of the framebuffer
    pub base: u64,
    /// Virtual base address (kernel-mapped)
    pub virt_base: u64,
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
    /// Create an empty framebuffer info (no framebuffer present).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            base: 0,
            virt_base: 0,
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

    /// Check if framebuffer information is valid (has both physical and virtual addresses).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.base != 0 && self.virt_base != 0 && self.size != 0 && self.width != 0 && self.height != 0
    }

    /// Check if the framebuffer uses BGR pixel format (blue at position 0).
    #[must_use]
    pub const fn is_bgr(&self) -> bool {
        self.blue_position == 0
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
    /// Number of CPUs detected from DTB
    pub cpu_count: u32,
    /// Padding to maintain alignment
    pub _cpu_count_pad: u32,
    /// Per-CPU kernel stack information (for SMP)
    pub per_cpu_stacks: [PerCpuStackInfo; MAX_CPUS],
    /// TTBR0_EL1 value for secondary CPU MMU setup (identity mapping)
    pub ttbr0_el1: u64,
    /// TCR_EL1 value for secondary CPU MMU setup (with correct IPS for this CPU)
    pub tcr_el1: u64,
}

impl BootInfo {
    /// Check if boot info is valid (correct magic and version).
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC && self.version == BOOT_INFO_VERSION
    }

    /// Check if an initrd is present.
    #[must_use]
    pub const fn has_initrd(&self) -> bool {
        !self.initrd_phys_base.is_null() && self.initrd_size != 0
    }

    /// Get the number of CPUs, clamped to MAX_CPUS.
    #[must_use]
    pub const fn cpu_count(&self) -> usize {
        let count = self.cpu_count as usize;
        if count > MAX_CPUS { MAX_CPUS } else if count == 0 { 1 } else { count }
    }

    /// Get stack info for a specific CPU.
    #[must_use]
    pub const fn cpu_stack(&self, cpu_id: usize) -> Option<&PerCpuStackInfo> {
        if cpu_id < MAX_CPUS {
            Some(&self.per_cpu_stacks[cpu_id])
        } else {
            None
        }
    }
}

/// RSDP signature "RSD PTR " as bytes
pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

// -- MMU configuration values for secondary CPU entry
// These must match the values used by the bootloader in m6-boot/src/page_table.rs

/// MAIR (Memory Attribute Indirection Register) value
/// - Index 0: Normal WB-RWA (0xFF)
/// - Index 1: Device-nGnRE (0x04)
/// - Index 2: Normal Non-cacheable (0x44)
pub const MAIR_VALUE: u64 = 0x00_00_00_00_44_04_FF;

/// TCR (Translation Control Register) value for 4KB pages, 48-bit VA
pub const TCR_VALUE: u64 = 16            // T0SZ = 16 (48-bit VA for TTBR0)
    | (16 << 16)                         // T1SZ = 16 (48-bit VA for TTBR1)
    | (0b10 << 30)                       // TG1 = 4KB
    | (0b101 << 32)                      // IPS = 48-bit PA
    | (0b11 << 12)                       // SH0 = Inner Shareable
    | (0b11 << 28)                       // SH1 = Inner Shareable
    | (0b01 << 10)                       // ORGN0 = WB-RWA
    | (0b01 << 26)                       // ORGN1 = WB-RWA
    | (0b01 << 8)                        // IRGN0 = WB-RWA
    | (0b01 << 24);                      // IRGN1 = WB-RWA

// -- BootInfo field offsets for assembly code (secondary CPU entry)
// These must be kept in sync with the struct layout above.

/// Offset of `page_table_base` in BootInfo (used for TTBR1)
pub const BOOTINFO_PAGE_TABLE_BASE_OFFSET: usize = 40;

/// Offset of `per_cpu_stacks` in BootInfo
pub const BOOTINFO_PER_CPU_STACKS_OFFSET: usize = 1728;

/// Offset of `ttbr0_el1` in BootInfo
pub const BOOTINFO_TTBR0_OFFSET: usize = 1856;

/// Offset of `tcr_el1` in BootInfo
pub const BOOTINFO_TCR_OFFSET: usize = 1864;

/// Size of PerCpuStackInfo (phys_base: u64, virt_top: u64)
pub const PER_CPU_STACK_INFO_SIZE: usize = 16;

/// Offset of `virt_top` within PerCpuStackInfo
pub const PER_CPU_STACK_VIRT_TOP_OFFSET: usize = 8;

// Compile-time verification of offsets
const _: () = {
    assert!(
        core::mem::offset_of!(BootInfo, page_table_base) == BOOTINFO_PAGE_TABLE_BASE_OFFSET,
        "BOOTINFO_PAGE_TABLE_BASE_OFFSET mismatch"
    );
    assert!(
        core::mem::offset_of!(BootInfo, per_cpu_stacks) == BOOTINFO_PER_CPU_STACKS_OFFSET,
        "BOOTINFO_PER_CPU_STACKS_OFFSET mismatch"
    );
    assert!(
        core::mem::offset_of!(BootInfo, ttbr0_el1) == BOOTINFO_TTBR0_OFFSET,
        "BOOTINFO_TTBR0_OFFSET mismatch"
    );
    assert!(
        core::mem::offset_of!(BootInfo, tcr_el1) == BOOTINFO_TCR_OFFSET,
        "BOOTINFO_TCR_OFFSET mismatch"
    );
    assert!(
        core::mem::size_of::<PerCpuStackInfo>() == PER_CPU_STACK_INFO_SIZE,
        "PER_CPU_STACK_INFO_SIZE mismatch"
    );
    assert!(
        core::mem::offset_of!(PerCpuStackInfo, virt_top) == PER_CPU_STACK_VIRT_TOP_OFFSET,
        "PER_CPU_STACK_VIRT_TOP_OFFSET mismatch"
    );
};
