//! Bootloader Configuration Constants

/// Kernel virtual base address (upper half of address space)
/// Using -2GB (0xFFFF_FFFF_8000_0000) for kernel base
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Maximum number of CPUs supported (must match m6-common::boot::MAX_CPUS)
pub const MAX_CPUS: usize = 8;

/// Size of each per-CPU kernel stack
pub const PER_CPU_STACK_SIZE: usize = 64 * 1024; // 64 KB per CPU

/// Size of the kernel stack (legacy, for single CPU - use PER_CPU_STACK_SIZE instead)
pub const KERNEL_STACK_SIZE: usize = PER_CPU_STACK_SIZE;

/// Maximum kernel image size
pub const MAX_KERNEL_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// Page table allocation size (for initial boot page tables)
/// Needs to be large enough for:
/// - TTBR0: Identity mapping for MMIO + RAM (3GB using 1GB blocks = ~2-4 pages)
/// - TTBR1: Kernel high-half mapping with multiple segments (~10-20 pages)
pub const PAGE_TABLE_ALLOC_SIZE: usize = 256 * 1024; // 256 KB for initial tables

/// Kernel file name on the EFI system partition
pub const KERNEL_PATH: &str = "\\EFI\\M6\\KERNEL";

/// InitRD file name on the EFI system partition
pub const INITRD_PATH: &str = "\\EFI\\M6\\INITRD";

/// Maximum initrd size
pub const MAX_INITRD_SIZE: usize = 64 * 1024 * 1024; // 64 MB

/// BootInfo allocation size
pub const BOOT_INFO_SIZE: usize = 4096;

// -- These are mapped in TTBR1 (kernel space) so the kernel can access
// -- hardware devices without per-process TTBR0 mappings.

/// Base address for kernel MMIO region in high-half kernel space
/// Using the last 256MB of the 48-bit kernel VA space
pub const KERNEL_MMIO_BASE: u64 = 0xFFFF_FFFF_F000_0000;

/// Kernel virtual address for GIC (maps 1MB region)
pub const KERNEL_GIC_VIRT: u64 = KERNEL_MMIO_BASE;
/// Size of GIC mapping (covers GICD, GICC, GICR)
pub const KERNEL_GIC_SIZE: usize = 0x0010_0000; // 1MB

/// Kernel virtual address for UART (offset from GIC to avoid overlap)
pub const KERNEL_UART_VIRT: u64 = KERNEL_MMIO_BASE + 0x0100_0000; // 16MB offset
/// Size of UART mapping
pub const KERNEL_UART_SIZE: usize = 0x0001_0000; // 64KB

// -- A direct mapping of all physical RAM into kernel virtual space.
// -- This allows the kernel to access any physical address by adding
// KERNEL_PHYS_MAP_BASE to the physical address.
//
// Virtual addresses in this region: PHYS_MAP_BASE + phys_addr
// Maps the first 4GB of physical memory to cover all RAM on QEMU virt.
//
// IMPORTANT: This must NOT overlap with kernel code (0xFFFF_FFFF_8000_0000)
// or other kernel regions. We use the lower part of the upper half.

/// Base virtual address for the direct physical map in kernel space
/// Located in the lower part of the kernel half to avoid conflicts
pub const KERNEL_PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;