//! Initial Page Table Setup
//!
//! Sets up the initial page tables for kernel boot using m6-paging abstractions:
//! - Identity mapping for bootloader code (temporary)
//! - High-half mapping for kernel at KERNEL_VIRT_BASE
//!
//! Uses 4KB pages with 4-level page tables (48-bit VA).

use crate::config::{
    KERNEL_GIC_SIZE, KERNEL_GIC_VIRT, KERNEL_PHYS_MAP_BASE, KERNEL_UART_SIZE, KERNEL_UART_VIRT,
    KERNEL_VIRT_BASE,
};
use crate::kernel_loader::LoadedKernel;
use core::ptr;
use m6_paging::arch::arm64::{L0Table, PgTable, map_range};
use m6_paging::{
    MapAttributes, MemoryType, PAGE_SIZE, PageAllocator, PhysMemoryRegion, PtePermissions, TPA,
    VirtMemoryRegion,
};

/// Result of page table setup containing both TTBR0 and TTBR1 addresses
pub struct PageTableSetup {
    /// TTBR0 physical address (identity mapping for bootloader transition)
    pub ttbr0: u64,
    /// TTBR1 physical address (kernel high-half mapping + MMIO)
    pub ttbr1: u64,
}

/// Platform-specific MMIO physical addresses
pub struct MmioConfig {
    /// Physical base address of GIC (GICD)
    pub gic_phys: u64,
    /// Physical base address of UART
    pub uart_phys: u64,
}

/// Initial page table allocator
///
/// Allocates page tables from a pre-allocated memory region.
/// Implements the `PageAllocator` trait from m6-paging.
pub struct BootPageAllocator {
    base: *mut u8,
    size: usize,
    offset: usize,
}

impl BootPageAllocator {
    /// Create a new allocator with the given memory region
    ///
    /// # Safety
    /// The memory region must be valid and properly aligned.
    pub unsafe fn new(base: *mut u8, size: usize) -> Self {
        Self {
            base,
            size,
            offset: 0,
        }
    }

    /// Get total bytes allocated
    pub fn bytes_used(&self) -> usize {
        self.offset
    }

    /// Allocate raw memory for a page table
    fn alloc_raw(&mut self) -> Option<*mut u8> {
        if self.offset + PAGE_SIZE > self.size {
            return None;
        }

        // SAFETY: We're allocating from our reserved region
        let ptr = unsafe {
            let ptr = self.base.add(self.offset);
            ptr::write_bytes(ptr, 0, PAGE_SIZE);
            ptr
        };

        self.offset += PAGE_SIZE;
        Some(ptr)
    }
}

impl PageAllocator for BootPageAllocator {
    fn allocate_table<T>(&mut self) -> Option<TPA<T>> {
        let ptr = self.alloc_raw()?;
        // SAFETY: We just allocated and zeroed this memory
        Some(unsafe { TPA::from_ptr(ptr) })
    }
}

/// Map kernel segments with W^X permissions into TTBR1
///
/// Returns the highest page address mapped (for subsequent mappings).
fn map_kernel_segments(
    ttbr1_l0: &mut L0Table,
    kernel: &LoadedKernel,
    allocator: &mut BootPageAllocator,
) -> Option<u64> {
    let mut highest_mapped_page: u64 = 0;

    // Map each kernel segment with proper W^X permissions
    // Segments are assumed to be sorted by virtual address (ELF loader provides them in order)
    for i in 0..kernel.segment_count {
        let seg = &kernel.segments[i];

        // Skip zero-size segments
        if seg.size == 0 {
            continue;
        }

        // Calculate page-aligned boundaries
        let seg_start = seg.virt_offset;
        let seg_end = seg.virt_offset + seg.size;

        // Page-align: round start down, round end up
        let page_start = seg_start & !(PAGE_SIZE as u64 - 1);
        let page_end = (seg_end + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

        // Skip pages we've already mapped (from overlapping previous segments)
        let adjusted_start = if page_start < highest_mapped_page {
            highest_mapped_page
        } else {
            page_start
        };

        // Skip if this segment is entirely within already-mapped pages
        if adjusted_start >= page_end {
            continue;
        }

        // Calculate physical and virtual addresses for this segment's non-overlapping portion
        let seg_phys = kernel.phys_base + adjusted_start;
        let seg_virt = KERNEL_VIRT_BASE + adjusted_start;
        let seg_size = (page_end - adjusted_start) as usize;

        let phys_region = PhysMemoryRegion::from_raw(seg_phys, seg_size);
        let virt_region = VirtMemoryRegion::from_raw(seg_virt, seg_size);

        // Determine permissions based on segment flags
        // W^X: A segment should NOT be both writable and executable
        let perms = if seg.execute && !seg.write {
            // Code segment: Read + Execute (no Write)
            PtePermissions::rx(false)
        } else if seg.write && !seg.execute {
            // Data segment: Read + Write (no Execute)
            PtePermissions::rw(false)
        } else if seg.read && !seg.write && !seg.execute {
            // Read-only data: Read only
            PtePermissions::ro(false)
        } else {
            // Fallback for unusual combinations (e.g., RWX - log warning but allow)
            // This handles legacy ELF files or combined segments
            log::warn!(
                "Segment {} at {:#x} has unusual permissions R={} W={} X={}, using RWX",
                i,
                seg_virt,
                seg.read,
                seg.write,
                seg.execute
            );
            PtePermissions::rwx(false)
        };

        log::debug!(
            "Mapping kernel segment {}: VA {:#x}..{:#x} -> PA {:#x} ({:?})",
            i,
            seg_virt,
            seg_virt + seg_size as u64,
            seg_phys,
            perms
        );

        if let Err(e) = map_range(
            ttbr1_l0,
            MapAttributes::new(phys_region, virt_region, MemoryType::Normal, perms),
            allocator,
        ) {
            log::error!("Failed to map kernel segment {}: {:?}", i, e);
            return None;
        }

        // Update the highest mapped page
        highest_mapped_page = page_end;
    }

    Some(highest_mapped_page)
}

/// Map kernel stack into TTBR1
fn map_kernel_stack(
    ttbr1_l0: &mut L0Table,
    kernel: &LoadedKernel,
    stack_phys: u64,
    stack_size: u64,
    allocator: &mut BootPageAllocator,
) -> Option<()> {
    // Align stack_virt_base to page boundary since kernel.size may not be page-aligned
    let stack_virt_base =
        (KERNEL_VIRT_BASE + kernel.size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let stack_phys_region = PhysMemoryRegion::from_raw(stack_phys, stack_size as usize);
    let stack_virt_region = VirtMemoryRegion::from_raw(stack_virt_base, stack_size as usize);

    log::debug!(
        "Mapping kernel stack: VA {:#x}..{:#x} -> PA {:#x}",
        stack_virt_base,
        stack_virt_base + stack_size,
        stack_phys
    );

    if let Err(e) = map_range(
        ttbr1_l0,
        MapAttributes::new(
            stack_phys_region,
            stack_virt_region,
            MemoryType::Normal,
            PtePermissions::rw(false), // Kernel-only, RW (no execute for stack)
        ),
        allocator,
    ) {
        log::error!("Failed to map kernel stack: {:?}", e);
        return None;
    }

    Some(())
}

/// Map MMIO regions (GIC and UART) into TTBR1
/// We need GIC and UART mapped for interrupt handling and early console output.
/// We then let the kernel remap them as needed later.
fn map_mmio_regions(
    ttbr1_l0: &mut L0Table,
    mmio: &MmioConfig,
    allocator: &mut BootPageAllocator,
) -> Option<()> {
    // Map GIC region
    let gic_phys_region = PhysMemoryRegion::from_raw(mmio.gic_phys, KERNEL_GIC_SIZE);
    let gic_virt_region = VirtMemoryRegion::from_raw(KERNEL_GIC_VIRT, KERNEL_GIC_SIZE);

    log::debug!(
        "Mapping GIC: VA {:#x}..{:#x} -> PA {:#x} (Device)",
        KERNEL_GIC_VIRT,
        KERNEL_GIC_VIRT + KERNEL_GIC_SIZE as u64,
        mmio.gic_phys
    );

    if let Err(e) = map_range(
        ttbr1_l0,
        MapAttributes::new(
            gic_phys_region,
            gic_virt_region,
            MemoryType::Device,
            PtePermissions::rw(false), // Kernel-only, RW, no execute
        ),
        allocator,
    ) {
        log::error!("Failed to map GIC: {:?}", e);
        return None;
    }

    // Map UART region
    let uart_phys_region = PhysMemoryRegion::from_raw(mmio.uart_phys, KERNEL_UART_SIZE);
    let uart_virt_region = VirtMemoryRegion::from_raw(KERNEL_UART_VIRT, KERNEL_UART_SIZE);

    log::debug!(
        "Mapping UART: VA {:#x}..{:#x} -> PA {:#x} (Device)",
        KERNEL_UART_VIRT,
        KERNEL_UART_VIRT + KERNEL_UART_SIZE as u64,
        mmio.uart_phys
    );

    if let Err(e) = map_range(
        ttbr1_l0,
        MapAttributes::new(
            uart_phys_region,
            uart_virt_region,
            MemoryType::Device,
            PtePermissions::rw(false), // Kernel-only, RW, no execute
        ),
        allocator,
    ) {
        log::error!("Failed to map UART: {:?}", e);
        return None;
    }

    Some(())
}

/// Map direct physical memory map into TTBR1
///
/// Maps all physical memory into kernel virtual space at KERNEL_PHYS_MAP_BASE
/// in 1GB chunks to use block mappings where possible.
///
/// The first 1GB is always mapped as Device memory (MMIO region).
/// Remaining chunks up to max_phys_addr are mapped as Normal memory.
fn map_direct_physmap(
    ttbr1_l0: &mut L0Table,
    max_phys_addr: u64,
    allocator: &mut BootPageAllocator,
) -> Option<()> {
    const GB: u64 = 0x4000_0000; // 1GB

    // Round up max_phys_addr to next 1GB boundary
    let total_size = max_phys_addr.div_ceil(GB) * GB;
    let num_chunks = (total_size / GB).max(1) as usize; // At least 1 chunk

    log::debug!(
        "Mapping Direct PhysMap: {} GB (0x0 - {:#x})",
        num_chunks,
        total_size
    );

    for chunk in 0..num_chunks {
        let phys_base = chunk as u64 * GB;
        let virt_base = KERNEL_PHYS_MAP_BASE + phys_base;

        // First chunk (0x0 - 0x40000000) is MMIO/Device memory
        // Remaining chunks are Normal memory (RAM)
        let (mem_type, type_str) = if chunk == 0 {
            (MemoryType::Device, "Device")
        } else {
            (MemoryType::Normal, "Normal")
        };

        let phys_region = PhysMemoryRegion::from_raw(phys_base, GB as usize);
        let virt_region = VirtMemoryRegion::from_raw(virt_base, GB as usize);

        log::debug!(
            "Mapping Direct PhysMap chunk {}: VA {:#x}..{:#x} -> PA {:#x} ({})",
            chunk,
            virt_base,
            virt_base + GB,
            phys_base,
            type_str
        );

        if let Err(e) = map_range(
            ttbr1_l0,
            MapAttributes::new(
                phys_region,
                virt_region,
                mem_type,
                PtePermissions::rw(false), // Kernel-only, RW (no execute for safety)
            ),
            allocator,
        ) {
            log::error!("Failed to map Direct PhysMap chunk {}: {:?}", chunk, e);
            return None;
        }
    }

    Some(())
}

/// Set up TTBR0 identity mapping for bootloader transition
///
/// Creates identity mapping so the bootloader can continue fetching
/// instructions after enabling MMU.
fn setup_ttbr0_identity(
    max_phys_addr: u64,
    allocator: &mut BootPageAllocator,
) -> Option<TPA<L0Table>> {
    const GB: u64 = 0x4000_0000; // 1GB

    let ttbr0_pa: TPA<L0Table> = allocator.allocate_table()?;
    let mut ttbr0_l0 = unsafe { L0Table::from_pa(ttbr0_pa) };
    log::debug!("Allocated TTBR0 L0 at {:#x}", ttbr0_pa.value());

    // Round up max_phys_addr to next 1GB boundary
    let total_size = max_phys_addr.div_ceil(GB) * GB;
    let num_chunks = (total_size / GB).max(1) as usize; // At least 1 chunk

    log::debug!(
        "Mapping TTBR0 identity: {} GB (0x0 - {:#x})",
        num_chunks,
        total_size
    );

    for chunk in 0..num_chunks {
        let phys_base = chunk as u64 * GB;

        // First chunk (0x0 - 0x40000000) is MMIO/Device memory
        // Remaining chunks are Normal memory (RAM) with RWX for bootloader code
        let (mem_type, perms, type_str) = if chunk == 0 {
            (MemoryType::Device, PtePermissions::rw(false), "Device")
        } else {
            (MemoryType::Normal, PtePermissions::rwx(false), "Normal")
        };

        let phys_region = PhysMemoryRegion::from_raw(phys_base, GB as usize);
        let virt_region = VirtMemoryRegion::from_raw(phys_base, GB as usize); // Identity mapping

        log::debug!(
            "Mapping TTBR0 chunk {}: {:#x}..{:#x} ({})",
            chunk,
            phys_base,
            phys_base + GB,
            type_str
        );

        if let Err(e) = map_range(
            &mut ttbr0_l0,
            MapAttributes::new(phys_region, virt_region, mem_type, perms),
            allocator,
        ) {
            log::error!("Failed to map TTBR0 chunk {}: {:?}", chunk, e);
            return None;
        }
    }

    Some(ttbr0_pa)
}

/// Set up initial page tables for kernel boot
///
/// Creates:
/// - TTBR0: Identity mapping for bootloader transition (RAM only for code execution)
/// - TTBR1: High-half mapping for kernel at KERNEL_VIRT_BASE with W^X enforcement,
///   plus MMIO mappings for GIC and UART
///
/// Parameters:
/// - `allocator`: Page table allocator
/// - `kernel`: Loaded kernel information including segment permissions
/// - `stack_phys`: Physical address of kernel stack (base, not top)
/// - `stack_size`: Size of kernel stack
/// - `mmio`: Platform-specific MMIO physical addresses
/// - `max_phys_addr`: Highest physical address to map in direct physmap
///
/// Returns PageTableSetup with physical addresses for both TTBR0 and TTBR1.
pub fn setup_initial_page_tables(
    allocator: &mut BootPageAllocator,
    kernel: &LoadedKernel,
    stack_phys: u64,
    stack_size: u64,
    mmio: &MmioConfig,
    max_phys_addr: u64,
) -> Option<PageTableSetup> {
    // TTBR1: Kernel high-half mapping with W^X enforcement

    // Allocate L0 (PGD) for TTBR1 (kernel space)
    let ttbr1_pa: TPA<L0Table> = allocator.allocate_table()?;
    let mut ttbr1_l0 = unsafe { L0Table::from_pa(ttbr1_pa) };
    log::debug!("Allocated TTBR1 L0 at {:#x}", ttbr1_pa.value());

    // Map kernel segments with W^X permissions
    map_kernel_segments(&mut ttbr1_l0, kernel, allocator)?;

    // Map kernel stack
    map_kernel_stack(&mut ttbr1_l0, kernel, stack_phys, stack_size, allocator)?;

    // Map MMIO regions (GIC and UART)
    map_mmio_regions(&mut ttbr1_l0, mmio, allocator)?;

    // Map direct physical memory map
    map_direct_physmap(&mut ttbr1_l0, max_phys_addr, allocator)?;

    // TTBR0: Identity mapping for bootloader transition
    let ttbr0_pa = setup_ttbr0_identity(max_phys_addr, allocator)?;

    Some(PageTableSetup {
        ttbr0: ttbr0_pa.value(),
        ttbr1: ttbr1_pa.value(),
    })
}

/// MAIR (Memory Attribute Indirection Register) value
///
/// Index 0: Normal memory, Write-Back, Read-Allocate, Write-Allocate (0xFF)
/// Index 1: Device-nGnRE memory (0x04) - allows early write acknowledgement
/// Index 2: Normal Non-cacheable memory (0x44)
///
/// Note: This matches the ATTR_INDEX values used in m6-paging descriptors:
/// - ATTR_INDEX::Normal = 0 -> MAIR Attr0 = 0xFF
/// - ATTR_INDEX::Device = 1 -> MAIR Attr1 = 0x04
/// - (reserved) = 2 -> MAIR Attr2 = 0x44 (for future non-cacheable mappings)
///
/// This value is aligned with the kernel's MAIR configuration in m6-arch/src/mmu.rs
pub const MAIR_VALUE: u64 = 0x00_00_00_00_44_04_FF;

/// TCR (Translation Control Register) value for 4KB pages, 48-bit VA
///
/// - T0SZ = 16 (48-bit VA for TTBR0)
/// - T1SZ = 16 (48-bit VA for TTBR1)
/// - TG0 = 0b00 (4KB granule for TTBR0)
/// - TG1 = 0b10 (4KB granule for TTBR1)
/// - IPS = 0b101 (48-bit PA)
/// - SH0/SH1 = 0b11 (Inner Shareable)
/// - ORGN0/ORGN1 = 0b01 (Write-Back, Read-Allocate, Write-Allocate)
/// - IRGN0/IRGN1 = 0b01 (Write-Back, Read-Allocate, Write-Allocate)
pub const TCR_VALUE: u64 = 16               // T0SZ
    | (16 << 16)       // T1SZ
    | (0b10 << 30)     // TG1 = 4KB
    | (0b101 << 32)    // IPS = 48-bit
    | (0b11 << 12)     // SH0 = Inner Shareable
    | (0b11 << 28)     // SH1 = Inner Shareable
    | (0b01 << 10)     // ORGN0
    | (0b01 << 26)     // ORGN1
    | (0b01 << 8)      // IRGN0
    | (0b01 << 24);    // IRGN1
