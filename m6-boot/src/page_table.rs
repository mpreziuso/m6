//! Initial Page Table Setup
//!
//! Sets up the initial page tables for kernel boot using m6-paging abstractions:
//! - Identity mapping for bootloader code (temporary)
//! - High-half mapping for kernel at KERNEL_VIRT_BASE
//!
//! Uses 4KB pages with 4-level page tables (48-bit VA).

use crate::config::{
    KERNEL_FB_MAX_SIZE, KERNEL_FB_VIRT, KERNEL_GIC_SIZE, KERNEL_GIC_VIRT, KERNEL_PHYS_MAP_BASE,
    KERNEL_UART_SIZE, KERNEL_UART_VIRT, KERNEL_VIRT_BASE,
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

/// Map framebuffer into TTBR1 as device memory
///
/// Maps the GOP framebuffer physical address into kernel virtual space.
/// Returns the virtual address where the framebuffer is mapped.
///
/// Uses Device memory type which is safe for framebuffers. Write-combining
/// would be more performant but requires extending MemoryType enum.
///
/// Parameters:
/// - `ttbr1_l0`: L0 page table for TTBR1
/// - `fb_phys`: Physical address of the framebuffer
/// - `fb_size`: Size of the framebuffer in bytes
/// - `allocator`: Page table allocator
///
/// Returns `Some(virt_addr)` on success, `None` on failure.
pub fn map_framebuffer(
    ttbr1_l0: &mut L0Table,
    fb_phys: u64,
    fb_size: u64,
    allocator: &mut BootPageAllocator,
) -> Option<u64> {
    // Skip if no framebuffer
    if fb_phys == 0 || fb_size == 0 {
        return None;
    }

    // Check if framebuffer is too large
    if fb_size > KERNEL_FB_MAX_SIZE as u64 {
        log::warn!(
            "Framebuffer too large: {} bytes > {} bytes max",
            fb_size,
            KERNEL_FB_MAX_SIZE
        );
        return None;
    }

    // Page-align the framebuffer region
    let fb_phys_aligned = fb_phys & !(PAGE_SIZE as u64 - 1);
    let fb_offset = fb_phys - fb_phys_aligned;
    let fb_end = (fb_phys + fb_size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let fb_size_aligned = fb_end - fb_phys_aligned;

    let fb_phys_region = PhysMemoryRegion::from_raw(fb_phys_aligned, fb_size_aligned as usize);
    let fb_virt_region = VirtMemoryRegion::from_raw(KERNEL_FB_VIRT, fb_size_aligned as usize);

    log::debug!(
        "Mapping Framebuffer: VA {:#x}..{:#x} -> PA {:#x} (Device, {} bytes)",
        KERNEL_FB_VIRT,
        KERNEL_FB_VIRT + fb_size_aligned,
        fb_phys_aligned,
        fb_size_aligned
    );

    if let Err(e) = map_range(
        ttbr1_l0,
        MapAttributes::new(
            fb_phys_region,
            fb_virt_region,
            MemoryType::Device, // Device memory is safe for framebuffers
            PtePermissions::rw(false), // Kernel-only, RW, no execute
        ),
        allocator,
    ) {
        log::error!("Failed to map framebuffer: {:?}", e);
        return None;
    }

    // Return virtual address adjusted for page alignment offset
    Some(KERNEL_FB_VIRT + fb_offset)
}

/// Map direct physical memory map into TTBR1
///
/// Maps all physical memory into kernel virtual space at KERNEL_PHYS_MAP_BASE
/// in 1GB chunks to use block mappings where possible.
///
/// Uses the RAM regions from UEFI memory map to determine which chunks
/// are RAM (Normal memory) vs MMIO (Device memory).
fn map_direct_physmap(
    ttbr1_l0: &mut L0Table,
    ram_regions: &RamRegions,
    allocator: &mut BootPageAllocator,
) -> Option<()> {
    const GB: u64 = 0x4000_0000; // 1GB

    let max_phys_addr = ram_regions.max_addr();
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

        // Use UEFI memory map to determine if this chunk contains RAM
        let (mem_type, type_str) = if ram_regions.chunk_is_ram(phys_base) {
            (MemoryType::Normal, "Normal")
        } else {
            (MemoryType::Device, "Device")
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
///
/// Uses the RAM regions from UEFI memory map to determine which chunks
/// are RAM (Normal memory with RWX) vs MMIO (Device memory with RW).
fn setup_ttbr0_identity(
    ram_regions: &RamRegions,
    allocator: &mut BootPageAllocator,
) -> Option<TPA<L0Table>> {
    const GB: u64 = 0x4000_0000; // 1GB

    let ttbr0_pa: TPA<L0Table> = allocator.allocate_table()?;
    let mut ttbr0_l0 = unsafe { L0Table::from_pa(ttbr0_pa) };
    log::debug!("Allocated TTBR0 L0 at {:#x}", ttbr0_pa.value());

    let max_phys_addr = ram_regions.max_addr();
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

        // Use UEFI memory map to determine if this chunk contains RAM
        // RAM chunks need RWX for bootloader code execution
        // Non-RAM chunks (MMIO) use Device memory with RW only
        let (mem_type, perms, type_str) = if ram_regions.chunk_is_ram(phys_base) {
            (MemoryType::Normal, PtePermissions::rwx(false), "Normal")
        } else {
            (MemoryType::Device, PtePermissions::rw(false), "Device")
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

/// Framebuffer information for page table setup
pub struct FramebufferMapping {
    /// Physical base address of framebuffer
    pub phys: u64,
    /// Size in bytes
    pub size: u64,
}

/// RAM region from UEFI memory map
#[derive(Clone, Copy, Debug)]
pub struct RamRegion {
    /// Physical start address
    pub start: u64,
    /// Physical end address (exclusive)
    pub end: u64,
}

/// Maximum number of RAM regions we track
pub const MAX_RAM_REGIONS: usize = 32;

/// RAM regions from UEFI memory map
pub struct RamRegions {
    /// Array of RAM regions
    pub regions: [RamRegion; MAX_RAM_REGIONS],
    /// Number of valid regions
    pub count: usize,
}

impl RamRegions {
    /// Create empty RAM regions
    pub const fn new() -> Self {
        Self {
            regions: [RamRegion { start: 0, end: 0 }; MAX_RAM_REGIONS],
            count: 0,
        }
    }

    /// Add a RAM region (merges overlapping/adjacent regions)
    pub fn add(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        // Try to merge with existing region
        for i in 0..self.count {
            let r = &mut self.regions[i];
            // Check if regions overlap or are adjacent
            if start <= r.end && end >= r.start {
                r.start = r.start.min(start);
                r.end = r.end.max(end);
                return;
            }
        }

        // Add as new region if space available
        if self.count < MAX_RAM_REGIONS {
            self.regions[self.count] = RamRegion { start, end };
            self.count += 1;
        }
    }

    /// Check if a physical address is within a RAM region
    pub fn contains(&self, addr: u64) -> bool {
        for i in 0..self.count {
            let r = &self.regions[i];
            if addr >= r.start && addr < r.end {
                return true;
            }
        }
        false
    }

    /// Check if a 1GB chunk overlaps with any RAM region
    pub fn chunk_is_ram(&self, chunk_start: u64) -> bool {
        const GB: u64 = 0x4000_0000;
        let chunk_end = chunk_start + GB;

        for i in 0..self.count {
            let r = &self.regions[i];
            // Check if chunk overlaps with this RAM region
            if chunk_start < r.end && chunk_end > r.start {
                return true;
            }
        }
        false
    }

    /// Get the highest address across all regions
    pub fn max_addr(&self) -> u64 {
        let mut max = 0u64;
        for i in 0..self.count {
            max = max.max(self.regions[i].end);
        }
        max
    }
}

/// Result of page table setup including optional framebuffer virtual address
pub struct PageTableSetupResult {
    /// Page table setup with TTBR0/TTBR1
    pub tables: PageTableSetup,
    /// Virtual address of framebuffer (if mapped)
    pub fb_virt: Option<u64>,
}

/// Set up initial page tables for kernel boot
///
/// Creates:
/// - TTBR0: Identity mapping for bootloader transition (RAM only for code execution)
/// - TTBR1: High-half mapping for kernel at KERNEL_VIRT_BASE with W^X enforcement,
///   plus MMIO mappings for GIC and UART, and optional framebuffer
///
/// Parameters:
/// - `allocator`: Page table allocator
/// - `kernel`: Loaded kernel information including segment permissions
/// - `stack_phys`: Physical address of kernel stack (base, not top)
/// - `stack_size`: Size of kernel stack
/// - `mmio`: Platform-specific MMIO physical addresses
/// - `ram_regions`: RAM regions from UEFI memory map
/// - `framebuffer`: Optional framebuffer to map
///
/// Returns PageTableSetupResult with physical addresses for both TTBR0 and TTBR1,
/// plus the framebuffer virtual address if mapped.
pub fn setup_initial_page_tables(
    allocator: &mut BootPageAllocator,
    kernel: &LoadedKernel,
    stack_phys: u64,
    stack_size: u64,
    mmio: &MmioConfig,
    ram_regions: &RamRegions,
    framebuffer: Option<&FramebufferMapping>,
) -> Option<PageTableSetupResult> {
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

    // Map framebuffer if present
    let fb_virt = if let Some(fb) = framebuffer {
        map_framebuffer(&mut ttbr1_l0, fb.phys, fb.size, allocator)
    } else {
        None
    };

    // Map direct physical memory map
    map_direct_physmap(&mut ttbr1_l0, ram_regions, allocator)?;

    // TTBR0: Identity mapping for bootloader transition
    let ttbr0_pa = setup_ttbr0_identity(ram_regions, allocator)?;

    Some(PageTableSetupResult {
        tables: PageTableSetup {
            ttbr0: ttbr0_pa.value(),
            ttbr1: ttbr1_pa.value(),
        },
        fb_virt,
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
/// Computes the TCR value with correct IPS for this CPU's physical address capability.
/// The IPS field is read from ID_AA64MMFR0_EL1.PARange at runtime.
///
/// - T0SZ = 16 (48-bit VA for TTBR0)
/// - T1SZ = 16 (48-bit VA for TTBR1)
/// - TG0 = 0b00 (4KB granule for TTBR0)
/// - TG1 = 0b10 (4KB granule for TTBR1)
/// - IPS = dynamic (from CPU's PARange)
/// - SH0/SH1 = 0b11 (Inner Shareable)
/// - ORGN0/ORGN1 = 0b01 (Write-Back, Read-Allocate, Write-Allocate)
/// - IRGN0/IRGN1 = 0b01 (Write-Back, Read-Allocate, Write-Allocate)
#[must_use]
pub fn tcr_value() -> u64 {
    // Get the CPU's physical address range capability and convert to IPS
    let ips = m6_arch::cpu::pa_range::tcr_ips();

    // Build TCR value with dynamic IPS
    let base: u64 = 16             // T0SZ = 48-bit VA
        | (16 << 16)               // T1SZ = 48-bit VA
        | (0b10 << 30)             // TG1 = 4KB granule
        | (0b11 << 12)             // SH0 = Inner Shareable
        | (0b11 << 28)             // SH1 = Inner Shareable
        | (0b01 << 10)             // ORGN0 = WB-RWA
        | (0b01 << 26)             // ORGN1 = WB-RWA
        | (0b01 << 8)              // IRGN0 = WB-RWA
        | (0b01 << 24);            // IRGN1 = WB-RWA

    base | (ips << 32)  // IPS is at bits [34:32]
}
