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
    KERNEL_GIC_VIRT, KERNEL_STACK_SIZE, KERNEL_UART_VIRT, KERNEL_VIRT_BASE, PAGE_TABLE_ALLOC_SIZE,
};
use m6_boot::initrd_loader::load_initrd;
use m6_boot::kernel_loader::load_kernel;
use m6_boot::memory::{mark_region, translate_memory_map};
use m6_boot::page_table::{
    setup_initial_page_tables, BootPageAllocator, MmioConfig,
};
use m6_common::boot::{BootInfo, FramebufferInfo, BOOT_INFO_MAGIC, BOOT_INFO_VERSION};
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

    // Verify we're running at EL1 (required for configuring EL1 system registers)
    let _current_el = m6_arch::cpu::current_el();

    log::info!("M6 Bootloader starting...");
    log::info!("UEFI Firmware Vendor: {}", system::firmware_vendor());
    log::info!(
        "UEFI Firmware Revision: {:#x}",
        system::firmware_revision()
    );

    // Load the kernel
    let kernel = match load_kernel() {
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

    // Find device tree blob (DTB) from UEFI config table
    let dtb_address = find_dtb();
    if dtb_address == 0 {
        log::error!("Device tree blob not found - cannot determine platform configuration");
        return Status::NOT_FOUND;
    }
    log::info!("Device tree blob found at {:#x}", dtb_address);

    // Set up initial page tables
    // SAFETY: We just allocated this memory
    let mut pt_allocator =
        unsafe { BootPageAllocator::new(pt_phys as *mut u8, PAGE_TABLE_ALLOC_SIZE) };

    // Calculate stack base from stack top (stack_phys is top, we need base)
    let stack_base_phys = kernel.stack_phys - KERNEL_STACK_SIZE as u64;

    // Parse platform-specific MMIO physical addresses from DTB
    let mmio = parse_mmio_from_dtb(dtb_address);

    // Get memory map to determine how much physical memory to map
    // We need to do this before exit_boot_services, but the map may change slightly
    // when we exit boot services. The important thing is to get the highest address.
    let mmap_storage = boot::memory_map(MemoryType::LOADER_DATA).expect("Failed to get memory map");
    
    // Calculate the highest physical address we need to map
    let mut max_phys_addr: u64 = 0x4000_0000; // At least 1GB (covers MMIO)
    for descriptor in mmap_storage.entries().copied() {
        // Only consider conventional memory and reclaimable memory
        let is_ram = matches!(
            descriptor.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
                | MemoryType::LOADER_CODE
                | MemoryType::LOADER_DATA
        );
        if is_ram {
            let end_addr = descriptor.phys_start + (descriptor.page_count * 4096);
            max_phys_addr = max_phys_addr.max(end_addr);
        }
    }
    
    log::info!(
        "Detected physical memory up to {:#x} ({} MB)",
        max_phys_addr,
        max_phys_addr / (1024 * 1024)
    );

    let page_tables = match setup_initial_page_tables(
        &mut pt_allocator,
        &kernel,
        stack_base_phys,
        KERNEL_STACK_SIZE as u64,
        &mmio,
        max_phys_addr,
    ) {
        Some(pt) => pt,
        None => {
            log::error!("Failed to set up page tables");
            return Status::OUT_OF_RESOURCES;
        }
    };

    log::info!(
        "Page tables set up, TTBR0 = {:#x}, TTBR1 = {:#x}, used {} bytes",
        page_tables.ttbr0,
        page_tables.ttbr1,
        pt_allocator.bytes_used()
    );

    // Exit boot services and get final memory map
    log::info!("Exiting UEFI boot services...");

    // Exit boot services
    let uefi_mmap = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };

    // Translate memory map to M6 format
    let mut m6_mmap = translate_memory_map(&uefi_mmap);

    // Mark initrd region in memory map (so kernel doesn't reclaim it)
    if let Some(ref rd) = initrd {
        // Round up to page-aligned size
        let aligned_size = ((rd.size as usize).div_ceil(4096) * 4096) as u64;
        mark_region(&mut m6_mmap, rd.phys_base, aligned_size, M6MemoryType::InitRD);
    }

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
        (*ptr).page_table_base = PhysAddr::new(page_tables.ttbr1);
        (*ptr).memory_map = m6_mmap;
        (*ptr).framebuffer = FramebufferInfo::empty();
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
    }

    // Enable MMU and jump to kernel
    // SAFETY: We've set up page tables and prepared everything
    unsafe {
        enable_mmu_and_jump(
            page_tables.ttbr1,
            page_tables.ttbr0,
            kernel.entry_virt,
            boot_info_phys,
            kernel.stack_virt,
        );
    }
}

/// Parse MMIO addresses from Device Tree Blob
fn parse_mmio_from_dtb(dtb_phys: u64) -> MmioConfig {
    const DTB_MAX_SIZE: usize = 2 * 1024 * 1024; // 2MB max

    // Create slice from DTB physical address (UEFI identity maps everything)
    // SAFETY: DTB address comes from UEFI config table and is valid
    let dtb_slice = unsafe {
        core::slice::from_raw_parts(dtb_phys as *const u8, DTB_MAX_SIZE)
    };

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
