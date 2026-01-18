//! UEFI Bootloader Entry Point
//!
//! This is the UEFI application that loads and boots the M6 kernel.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod mmu_jump;
use mmu_jump::enable_mmu_and_jump;
use m6_boot::config::{
    KERNEL_GIC_VIRT, KERNEL_UART_VIRT, KERNEL_VIRT_BASE, MAX_CPUS, PAGE_TABLE_ALLOC_SIZE,
    PER_CPU_STACK_SIZE,
};
use m6_boot::gop::init_gop;
use m6_boot::initrd_loader::load_initrd;
use m6_boot::kernel_loader::load_kernel;
use m6_boot::memory::{mark_region, translate_memory_map};
use m6_boot::page_table::{
    setup_initial_page_tables, tcr_value, BootPageAllocator, FramebufferMapping, MmioConfig, RamRegions,
};
use m6_common::boot::{BootInfo, FramebufferInfo, PerCpuStackInfo, BOOT_INFO_MAGIC, BOOT_INFO_VERSION};
use m6_common::{PhysAddr, VirtAddr};
use m6_common::memory::MemoryType as M6MemoryType;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::mem::memory_map::MemoryMap;
use uefi::prelude::*;
use uefi::system;
use uefi::table::cfg::ConfigTableEntry;

/// FDT (Flattened Device Tree) GUID for UEFI configuration table
/// See: https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html
const FDT_GUID: uefi::Guid = uefi::guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");

/// SMBIOS 3.0 Entry Point GUID (reserved for future SMBIOS parsing)
#[allow(dead_code)]
const SMBIOS3_GUID: uefi::Guid = uefi::guid!("f2fd1544-9794-4a2c-992e-e5bbcf20e394");
/// SMBIOS 2.x Entry Point GUID (reserved for future SMBIOS parsing)
#[allow(dead_code)]
const SMBIOS_GUID: uefi::Guid = uefi::guid!("eb9d2d31-2d88-11d3-9a16-0090273fc14f");


#[entry]
fn efi_main() -> Status {
    // Initialise UEFI services
    uefi::helpers::init().unwrap();

    // Check current exception level (EL1 on QEMU, EL2 on Rock 5B+)
    let current_el = m6_arch::cpu::current_el();

    log::info!("M6 Bootloader starting at EL{}...", current_el);
    log::info!("UEFI Firmware Vendor: {}", system::firmware_vendor());
    log::info!(
        "UEFI Firmware Revision: {:#x}",
        system::firmware_revision()
    );

    // Find device tree blob (DTB) from UEFI config table (needed early for CPU count)
    let dtb_address = find_dtb();
    if dtb_address == 0 {
        log::error!("Device tree blob not found - cannot determine platform configuration");
        return Status::NOT_FOUND;
    }
    log::info!("Device tree blob found at {:#x}", dtb_address);

    // Parse CPU count from DTB before loading kernel (to allocate per-CPU stacks)
    let cpu_count = parse_cpu_count_from_dtb(dtb_address);
    log::info!("Detected {} CPUs from device tree", cpu_count);

    // Load the kernel with per-CPU stacks
    let kernel = match load_kernel(cpu_count) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load kernel: {:?}", e);
            return Status::LOAD_ERROR;
        }
    };

    log::info!(
        "Kernel loaded at physical {:#x}, entry at virtual {:#x}",
        kernel.phys_base,
        kernel.entry_virt
    );

    // Try to load initrd (optional)
    let initrd = load_initrd();
    if let Some(ref rd) = initrd {
        log::info!(
            "InitRD loaded at physical {:#x}, size {} bytes",
            rd.phys_base,
            rd.size
        );
    }

    // Try to initialise GOP framebuffer (optional - may not be available on headless systems)
    let mut framebuffer_info = init_gop().unwrap_or_else(|| {
        log::info!("No GOP framebuffer available (headless mode)");
        FramebufferInfo::empty()
    });

    // Allocate memory for page tables
    let pt_pages = PAGE_TABLE_ALLOC_SIZE.div_ceil(4096);
    let pt_phys = match boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        pt_pages,
    ) {
        Ok(ptr) => ptr.as_ptr() as u64,
        Err(e) => {
            log::error!("Failed to allocate page tables: {:?}", e);
            return Status::OUT_OF_RESOURCES;
        }
    };

    log::info!(
        "Page tables allocated at {:#x} ({} pages)",
        pt_phys,
        pt_pages
    );

    // Allocate memory for BootInfo
    let boot_info_size = core::mem::size_of::<BootInfo>();
    let boot_info_pages = boot_info_size.div_ceil(4096);
    let boot_info_phys = match boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        boot_info_pages,
    ) {
        Ok(ptr) => ptr.as_ptr() as u64,
        Err(e) => {
            log::error!("Failed to allocate boot info: {:?}", e);
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Find ACPI RSDP
    let acpi_rsdp = find_acpi_rsdp();
    if acpi_rsdp != 0 {
        log::info!("ACPI RSDP found at {:#x}", acpi_rsdp);
    }

    // Set up initial page tables
    // SAFETY: We just allocated this memory
    let mut pt_allocator =
        unsafe { BootPageAllocator::new(pt_phys as *mut u8, PAGE_TABLE_ALLOC_SIZE) };

    // Calculate stack base from stack top (stack_phys is top of CPU 0's stack)
    let stack_base_phys = kernel.stack_phys - PER_CPU_STACK_SIZE as u64;
    // Total size of all per-CPU stacks
    let total_stack_size = (kernel.cpu_count as usize) * PER_CPU_STACK_SIZE;

    // Parse platform-specific MMIO physical addresses from DTB
    let mmio = parse_mmio_from_dtb(dtb_address);

    // Get memory map to determine RAM regions for page table setup
    // We need to do this before exit_boot_services, but the map may change slightly
    // when we exit boot services. The important thing is to identify RAM vs MMIO regions.
    let mmap_storage = boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get memory map");

    // Build RAM regions from memory map
    let mut ram_regions = RamRegions::new();
    for descriptor in mmap_storage.entries().copied() {
        // Check if this is a RAM region (conventional memory or reclaimable)
        let is_ram = matches!(
            descriptor.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
                | MemoryType::LOADER_CODE
                | MemoryType::LOADER_DATA
                | MemoryType::PERSISTENT_MEMORY
        );
        if is_ram {
            let start = descriptor.phys_start;
            let end = descriptor.phys_start + (descriptor.page_count * 4096);
            ram_regions.add(start, end);
        }
    }

    // Ensure DTB region is included in physmap (may be in ACPI or other non-RAM type)
    // DTB is typically small (<2MB), add it with some margin
    const DTB_REGION_SIZE: u64 = 2 * 1024 * 1024; // 2MB
    ram_regions.add(dtb_address, dtb_address + DTB_REGION_SIZE);
    log::debug!("Added DTB region to physmap: {:#x} - {:#x}", dtb_address, dtb_address + DTB_REGION_SIZE);

    let max_phys_addr = ram_regions.max_addr();
    log::info!(
        "Detected {} RAM region(s), up to {:#x} ({} MB)",
        ram_regions.count,
        max_phys_addr,
        max_phys_addr / (1024 * 1024)
    );

    // Log individual RAM regions for debugging
    for i in 0..ram_regions.count {
        let r = &ram_regions.regions[i];
        log::debug!(
            "  RAM region {}: {:#x} - {:#x} ({} MB)",
            i,
            r.start,
            r.end,
            (r.end - r.start) / (1024 * 1024)
        );
    }

    // Calculate and allocate frame allocator bitmap
    // Each bit represents one 4KB frame
    let total_frames = max_phys_addr.div_ceil(4096);
    let bitmap_bytes = total_frames.div_ceil(8);
    let bitmap_size = (bitmap_bytes as usize).div_ceil(4096) * 4096; // Page-align
    let bitmap_pages = bitmap_size / 4096;

    let bitmap_phys = match boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        bitmap_pages,
    ) {
        Ok(ptr) => {
            // Zero the bitmap (all frames start as allocated)
            unsafe {
                core::ptr::write_bytes(ptr.as_ptr(), 0, bitmap_size);
            }
            ptr.as_ptr() as u64
        }
        Err(e) => {
            log::error!("Failed to allocate frame bitmap: {:?}", e);
            return Status::OUT_OF_RESOURCES;
        }
    };

    log::info!(
        "Frame bitmap allocated at {:#x} ({} KB for {} frames)",
        bitmap_phys,
        bitmap_size / 1024,
        total_frames
    );

    // Prepare framebuffer mapping if available
    let fb_mapping = if framebuffer_info.base != 0 && framebuffer_info.size != 0 {
        Some(FramebufferMapping {
            phys: framebuffer_info.base,
            size: framebuffer_info.size,
        })
    } else {
        None
    };

    let pt_result = match setup_initial_page_tables(
        &mut pt_allocator,
        &kernel,
        stack_base_phys,
        total_stack_size as u64,
        &mmio,
        &ram_regions,
        fb_mapping.as_ref(),
    ) {
        Some(result) => result,
        None => {
            log::error!("Failed to set up page tables");
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Update framebuffer_info with virtual address if mapped
    if let Some(virt) = pt_result.fb_virt {
        framebuffer_info.virt_base = virt;
        log::info!("Framebuffer mapped at virtual {:#x}", virt);
    }

    log::info!(
        "Page tables set up, TTBR0 = {:#x}, TTBR1 = {:#x}, used {} bytes",
        pt_result.tables.ttbr0,
        pt_result.tables.ttbr1,
        pt_allocator.bytes_used()
    );

    // Log TCR configuration before exiting boot services (for debugging)
    // Exit boot services and get final memory map
    log::info!("Exiting UEFI boot services...");

    // Exit boot services
    let uefi_mmap = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Translate memory map to M6 format
    let mut m6_mmap = translate_memory_map(&uefi_mmap);

    // Mark kernel image in memory map
    mark_region(
        &mut m6_mmap,
        kernel.phys_base,
        kernel.size,
        M6MemoryType::KernelImage,
    );

    // Mark page tables in memory map (so kernel doesn't reclaim them)
    mark_region(
        &mut m6_mmap,
        pt_phys,
        PAGE_TABLE_ALLOC_SIZE as u64,
        M6MemoryType::KernelPageTables,
    );

    // Mark initrd region in memory map (so kernel doesn't reclaim it)
    if let Some(ref rd) = initrd {
        // Round up to page-aligned size
        let aligned_size = ((rd.size as usize).div_ceil(4096) * 4096) as u64;
        mark_region(&mut m6_mmap, rd.phys_base, aligned_size, M6MemoryType::InitRD);
    }

    // Mark frame bitmap in memory map (so kernel doesn't reclaim it)
    mark_region(
        &mut m6_mmap,
        bitmap_phys,
        bitmap_size as u64,
        M6MemoryType::Reserved,
    );

    // Prepare BootInfo
    // SAFETY: We allocated this memory and it's properly aligned
    unsafe {
        let ptr = boot_info_phys as *mut BootInfo;
        core::ptr::write_bytes(ptr, 0, 1);

        (*ptr).magic = BOOT_INFO_MAGIC;
        (*ptr).version = BOOT_INFO_VERSION;
        (*ptr).kernel_phys_base = PhysAddr::new(kernel.phys_base);
        (*ptr).kernel_virt_base = VirtAddr::new(KERNEL_VIRT_BASE);
        (*ptr).kernel_size = kernel.size;
        (*ptr).page_table_base = PhysAddr::new(pt_phys);
        (*ptr).page_table_size = PAGE_TABLE_ALLOC_SIZE as u64;
        (*ptr).memory_map = m6_mmap;
        (*ptr).framebuffer = framebuffer_info;
        (*ptr).acpi_rsdp = PhysAddr::new(acpi_rsdp);
        (*ptr).dtb_address = PhysAddr::new(dtb_address);
        // Kernel MMIO virtual addresses (mapped in TTBR1)
        (*ptr).gic_virt_base = VirtAddr::new(KERNEL_GIC_VIRT);
        (*ptr).uart_virt_base = VirtAddr::new(KERNEL_UART_VIRT);
        // InitRD (if present)
        if let Some(ref rd) = initrd {
            (*ptr).initrd_phys_base = PhysAddr::new(rd.phys_base);
            (*ptr).initrd_size = rd.size;
        } else {
            (*ptr).initrd_phys_base = PhysAddr::new(0);
            (*ptr).initrd_size = 0;
        }
        // Frame allocator bitmap (allocated by bootloader for kernel)
        (*ptr).frame_bitmap_phys = PhysAddr::new(bitmap_phys);
        (*ptr).frame_bitmap_size = bitmap_size as u64;
        (*ptr).max_phys_addr = max_phys_addr;
        // SMP: CPU count and per-CPU stacks
        (*ptr).cpu_count = kernel.cpu_count;
        (*ptr)._cpu_count_pad = 0;
        for cpu in 0..MAX_CPUS {
            if cpu < kernel.cpu_count as usize {
                (*ptr).per_cpu_stacks[cpu] = PerCpuStackInfo {
                    phys_base: PhysAddr::new(kernel.per_cpu_stacks[cpu].phys_base),
                    virt_top: VirtAddr::new(kernel.per_cpu_stacks[cpu].virt_top),
                };
            } else {
                (*ptr).per_cpu_stacks[cpu] = PerCpuStackInfo::empty();
            }
        }
        // TTBR0 value for secondary CPU MMU setup (identity mapping)
        (*ptr).ttbr0_el1 = pt_result.tables.ttbr0;
        // TCR value with correct IPS for this CPU's physical address capability
        (*ptr).tcr_el1 = tcr_value();
    }

    // Clean all bootloader-written memory from cache to Point of Coherency.
    // This is critical because:
    // 1. Page tables: The MMU table walker reads from PoC, not CPU cache.
    //    If tables are still dirty in cache, the walker sees stale/zero data.
    // 2. Kernel image: IC IALLU only invalidates I-cache, not D-cache. The kernel
    //    code we loaded is still dirty in D-cache and must be cleaned to memory
    //    before it can be fetched as instructions.
    // 3. boot_info: After ERET to EL1, kernel might not see our EL2 cache writes.
    // UEFI identity maps physical memory, so phys addr = virt addr for DC ops.
    m6_arch::cache::cache_clean_range(pt_phys, PAGE_TABLE_ALLOC_SIZE);
    m6_arch::cache::cache_clean_range(kernel.phys_base, kernel.size as usize);
    m6_arch::cache::cache_clean_range(boot_info_phys, core::mem::size_of::<BootInfo>());

    // Enable MMU and jump to kernel
    // SAFETY: We've set up page tables and prepared everything
    unsafe {
        enable_mmu_and_jump(
            pt_result.tables.ttbr1,
            pt_result.tables.ttbr0,
            kernel.entry_virt,
            boot_info_phys,
            kernel.stack_virt,
        );
    }
}

/// Maximum DTB size for parsing
const DTB_MAX_SIZE: usize = 2 * 1024 * 1024; // 2MB max

/// Create DTB slice from physical address
///
/// # Safety
/// DTB address must come from UEFI config table and be valid
unsafe fn dtb_slice_from_phys(dtb_phys: u64) -> &'static [u8] {
    // SAFETY: DTB address comes from UEFI config table and is valid.
    // UEFI identity maps all physical memory.
    unsafe { core::slice::from_raw_parts(dtb_phys as *const u8, DTB_MAX_SIZE) }
}

/// Parse CPU count from Device Tree Blob
fn parse_cpu_count_from_dtb(dtb_phys: u64) -> u32 {
    // SAFETY: DTB address comes from UEFI config table
    let dtb_slice = unsafe { dtb_slice_from_phys(dtb_phys) };

    m6_pal::dtb::parse_cpu_count_from_slice(dtb_slice).unwrap_or(1)
}

/// Parse MMIO addresses from Device Tree Blob
fn parse_mmio_from_dtb(dtb_phys: u64) -> MmioConfig {
    // SAFETY: DTB address comes from UEFI config table
    let dtb_slice = unsafe { dtb_slice_from_phys(dtb_phys) };

    let (gic, uart) = m6_pal::dtb::parse_mmio_from_slice(dtb_slice)
        .expect("Failed to parse DTB or extract MMIO addresses");

    log::info!("DTB: GIC distributor at {:#x}", gic);
    log::info!("DTB: UART at {:#x}", uart);

    MmioConfig {
        gic_phys: gic,
        uart_phys: uart,
    }
}

/// Find ACPI RSDP from UEFI configuration tables
fn find_acpi_rsdp() -> u64 {
    for entry in system::with_config_table(|table| table.to_vec()) {
        if entry.guid == ConfigTableEntry::ACPI2_GUID || entry.guid == ConfigTableEntry::ACPI_GUID {
            return entry.address as u64;
        }
    }
    0
}

/// Find Device Tree Blob (DTB) from UEFI configuration tables
fn find_dtb() -> u64 {
    for entry in system::with_config_table(|table| table.to_vec()) {
        if entry.guid == FDT_GUID {
            return entry.address as u64;
        }
    }
    0
}

/// Panic handler
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("BOOTLOADER PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}
