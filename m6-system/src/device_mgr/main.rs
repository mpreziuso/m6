//! M6 Device Manager
//!
//! Userspace service responsible for:
//! - Enumerating devices from the device tree blob (DTB)
//! - Matching devices to driver binaries
//! - Spawning driver processes with appropriate capabilities
//! - Providing a registry service for clients to discover and access drivers
//!
//! The device manager receives:
//! - DTB Frame capability containing the device tree
//! - InitRD Frame capability containing driver binaries
//! - Registry endpoint for client requests
//! - Supervisor notification for reporting driver deaths

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

extern crate alloc;

#[path = "../rt.rs"]
mod rt;

mod boot_info;
mod dtb;
mod ipc;
mod manifest;
mod pcie;
mod registry;
mod slots;
mod spawn;

// Re-use io module from parent crate
#[path = "../io.rs"]
mod io;

#[path = "../logger.rs"]
mod logger;

use m6_syscall::invoke::{ipc_set_send_caps, recv, reply_recv, sched_yield, signal};
use m6_syscall::slot_to_cptr;

use boot_info::DevMgrBootInfo;
use registry::{DeviceState, Registry};
use spawn::{DeviceInfo, DriverSpawnConfig};

/// Static storage for boot info pointer (set at startup).
/// Uses AtomicPtr to avoid `static mut` unsoundness.
static BOOT_INFO: core::sync::atomic::AtomicPtr<DevMgrBootInfo> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Get a reference to the boot info.
///
/// # Safety
///
/// Must only be called after _start has initialised BOOT_INFO.
#[inline]
pub unsafe fn get_boot_info() -> &'static DevMgrBootInfo {
    // SAFETY: Caller guarantees _start has stored a valid pointer.
    unsafe { &*BOOT_INFO.load(core::sync::atomic::Ordering::Relaxed) }
}

/// Entry point for device manager.
///
/// # Safety
///
/// Must be called only once as the entry point. Init must have provided
/// the required capabilities in the well-known slots and a valid
/// DevMgrBootInfo pointer in x0.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(boot_info_addr: u64) -> ! {
    logger::init("device-mgr");
    log::info!("Starting");

    // Store boot info pointer
    BOOT_INFO.store(boot_info_addr as *mut DevMgrBootInfo, core::sync::atomic::Ordering::Relaxed);

    // Validate boot info
    // SAFETY: The pointer was just stored from init's valid boot_info_addr.
    let boot_info = unsafe { get_boot_info() };
    if !boot_info.is_valid() {
        log::error!("Invalid boot info!");
        loop {
            sched_yield();
        }
    }

    // Initialise registry
    let mut registry = Registry::new(slots::FIRST_FREE_SLOT, boot_info.cnode_radix);

    // Parse DTB and enumerate devices
    match init_dtb(&mut registry, boot_info) {
        Ok(_count) => {}
        Err(e) => {
            log::error!("Failed to parse DTB: {}", e);
        }
    }

    // Spawn platform drivers proactively
    spawn_platform_drivers(&mut registry);

    log::info!("spawn_platform_drivers done, entering service_loop");

    // Enter main service loop
    service_loop(&mut registry);
}

/// Spawn drivers proactively during boot.
///
/// Platform drivers (UART, SMMU, etc.) and PCIe drivers (NVMe, etc.) are
/// spawned immediately during enumeration rather than waiting for ENSURE
/// requests. This ensures critical system services are available early.
///
/// Boot ordering is critical:
/// 1. First pass: SMMU drivers (required for IOSpace creation)
/// 2. Second pass: Non-DMA drivers (UART, PCIe host bridges)
/// 3. Third pass: DMA-capable drivers (USB, NVMe, VirtIO block)
///
/// This ensures SMMU is running before we try to create IOSpaces for
/// DMA-capable device drivers.
///
/// Note: Only one UART driver is spawned (the first one found, typically the
/// console UART) to avoid resource exhaustion on platforms with many UARTs.
fn spawn_platform_drivers(registry: &mut Registry) {
    let initrd = match get_initrd() {
        Some(data) => data,
        None => return,
    };

    let archive = match tar_no_std::TarArchiveRef::new(initrd) {
        Ok(a) => a,
        Err(_) => return,
    };

    // Track how many UART drivers we've spawned (limit to 1 for now)
    let mut uart_count = 0;
    const MAX_UART_DRIVERS: usize = 1;

    // Note: SMMU is handled by the kernel directly via syscalls (iospace_create,
    // iospace_bind_stream, etc.). The kernel creates SmmuControl capabilities during
    // bootstrap, and device-mgr uses those via syscalls. No userspace SMMU driver needed.
    //
    // Mark SMMU devices as "handled by kernel" so we don't try to spawn drivers for them.
    for i in 0..registry.device_count {
        let compat = registry.devices[i].compatible_str();
        if compat.contains("smmu") {
            registry.devices[i].state = DeviceState::Running; // Mark as handled
        }
    }

    // -- Pass 2: Spawn non-DMA drivers (UART, PCIe host bridges, etc.)
    for i in 0..registry.device_count {
        if registry.devices[i].state != DeviceState::Unbound {
            continue;
        }

        let compat = registry.devices[i].compatible_str();
        let virtio_id = registry.devices[i].virtio_device_id;

        if let Some(manifest) = manifest::find_driver(compat, virtio_id) {
            // Skip DMA-capable drivers for now (they need IOSpace)
            if manifest.needs_iommu {
                continue;
            }

            // Spawn platform drivers and PCIe drivers
            let is_pcie_device = compat.starts_with("pcie:");
            if !manifest.is_platform && !is_pcie_device {
                continue;
            }

            // Limit UART driver spawning
            let is_uart = compat.contains("uart") || compat.contains("serial");
            if is_uart {
                if uart_count >= MAX_UART_DRIVERS {
                    continue;
                }
                uart_count += 1;
            }

            let has_binary = archive
                .entries()
                .any(|e| e.filename().as_str() == Ok(manifest.binary_name));
            if has_binary {
                let _ = spawn_driver_for_device(registry, i);
            }
        }
    }

    // -- Pass 3: Spawn DMA-capable drivers (USB, NVMe, VirtIO block, etc.)
    for i in 0..registry.device_count {
        if registry.devices[i].state != DeviceState::Unbound {
            continue;
        }

        let compat = registry.devices[i].compatible_str();
        let virtio_id = registry.devices[i].virtio_device_id;

        if let Some(manifest) = manifest::find_driver(compat, virtio_id) {
            // Only DMA-capable drivers in this pass
            if !manifest.needs_iommu {
                continue;
            }

            // Spawn platform drivers and PCIe drivers
            let is_pcie_device = compat.starts_with("pcie:");
            if !manifest.is_platform && !is_pcie_device {
                continue;
            }

            let has_binary = archive
                .entries()
                .any(|e| e.filename().as_str() == Ok(manifest.binary_name));
            if has_binary {
                let _ = spawn_driver_for_device(registry, i);
            }
        }
    }
}

/// Initialise DTB parsing and enumerate devices.
fn init_dtb(registry: &mut Registry, boot_info: &DevMgrBootInfo) -> Result<usize, &'static str> {
    if !boot_info.has_dtb() {
        return Err("No DTB available");
    }

    // SAFETY: Init must have mapped the DTB frame before spawning us
    let dtb_data = unsafe { boot_info.dtb_slice() }.ok_or("DTB slice failed")?;

    let count = dtb::enumerate_devices(dtb_data, registry)?;

    // Probe VirtIO devices to determine their specific type
    probe_virtio_devices(registry);

    // Enumerate PCIe devices if any host bridges are present
    enumerate_pcie_devices(registry, dtb_data);

    Ok(count)
}

/// Enumerate PCIe devices from all host bridges found in DTB.
fn enumerate_pcie_devices(registry: &mut Registry, dtb_data: &[u8]) {
    use m6_syscall::invoke::unmap_frame;

    // SAFETY: _start has initialised BOOT_INFO
    let boot_info = unsafe { get_boot_info() };

    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, boot_info.cnode_radix);

    // Parse PCIe host bridges from DTB
    let pcie_hosts = pcie::parse_pcie_hosts(dtb_data);

    // Track which PCIe host we're scanning (for virtual address offset)
    let mut host_index = 0u64;

    for host in pcie_hosts.iter().flatten() {
        // For RK3588 DWC: Check link status via APBDBG registers.
        // The main M.2 NVMe slots (pcie3x4, pcie3x2) are typically initialized by UEFI.
        // Secondary controllers (pcie2x1) may be powered off - check link status first.
        //
        // If link is down and PHY initialization is needed, a drv-pcie-rk3588 driver
        // would need to be spawned to:
        // 1. Configure clocks via CRU registers
        // 2. Power up and reset the PHY
        // 3. Train the link (LTSSM state machine)
        // 4. Notify device-mgr to rescan this controller
        //
        // For now, we only enumerate controllers with link already up (UEFI-initialized).
        if host.host_type == pcie::PcieHostType::DesignWareDwc {
            // Check link status if APBDBG base is available
            if host.apbdbg_base != 0 {
                match check_rk3588_link_status(host.apbdbg_base, registry, boot_info, &cptr) {
                    Some(link_up) => {
                        if !link_up {
                            continue;
                        }
                    }
                    None => {
                        // Could not map APBDBG - fall back to safe behaviour
                        // Only try main M.2 slots which UEFI typically initialises
                        if host.config_base != 0xf000_0000 && host.config_base != 0xf100_0000 {
                            continue;
                        }
                    }
                }
            } else {
                // No APBDBG info - only try main M.2 slots
                if host.config_base != 0xf000_0000 && host.config_base != 0xf100_0000 {
                    continue;
                }
            }
        }

        // Log host details for diagnostics
        log::debug!(
            "PCIe host: config={:#x} mem32=[{:#x}->{:#x} sz={:#x}] mem64=[{:#x}->{:#x} sz={:#x}] iommu={:#x} sid_base={:#x}",
            host.config_base,
            host.mem32_pci, host.mem32_cpu, host.mem32_size,
            host.mem64_pci, host.mem64_cpu, host.mem64_size,
            host.iommu_phandle as u64,
            host.iommu_stream_base as u64,
        );

        // Map config space for enumeration
        // For large config spaces (256MB), we only map enough for scanning
        let config_size_to_map = core::cmp::min(host.config_size, 16 * 1024 * 1024) as usize;

        match map_pcie_region(
            host.config_base,
            config_size_to_map,
            registry,
            boot_info,
            &cptr,
            host_index,
        ) {
            Some((config_vaddr, _config_slot, _pt_slots, mapped_size)) => {
                host_index += 1; // Increment for next mapping to use different vaddr

                // SAFETY: Config space is mapped for mapped_size bytes
                let devices = unsafe { pcie::enumerate_devices(host, config_vaddr, mapped_size) };

                // Add discovered devices to registry
                for device in &devices {
                    if !device.is_valid() {
                        continue;
                    }

                    add_pcie_device_to_registry(registry, host, device);
                }

                // For DWC hosts: scan the secondary bus behind the root port.
                // The root port itself is the device at bus_start — check if any
                // device on that bus is a bridge with a secondary bus assigned.
                if host.host_type == pcie::PcieHostType::DesignWareDwc {
                    scan_dwc_secondary_bus(
                        host,
                        config_vaddr,
                        config_vaddr as u64, // pcie_probe_vaddr
                        registry,
                        boot_info,
                        &cptr,
                    );
                }

                // Unmap config space
                // Note: We keep individual device frames for later driver spawning
                if let Err(e) = unmap_frame(cptr(slots::ROOT_VSPACE), config_vaddr as u64) {
                    log::warn!("unmap config frame failed: {}", e.name());
                }
            }
            None => {
                log::debug!("PCIe: failed to map config space");
            }
        }
    }

    // Note: if no PCIe hosts found, that's normal for some platforms
}

/// Check RK3588 PCIe link status by temporarily mapping APBDBG registers.
///
/// Returns Some(true) if link is up, Some(false) if link is down,
/// or None if the mapping failed.
fn check_rk3588_link_status(
    apbdbg_base: u64,
    registry: &mut Registry,
    boot_info: &DevMgrBootInfo,
    cptr: &impl Fn(u64) -> u64,
) -> Option<bool> {
    use m6_cap::ObjectType;
    use m6_syscall::invoke::{map_frame, map_page_table, retype, unmap_frame};

    // Find device untyped covering this address
    let (device_untyped_slot, _untyped_size, untyped_base) =
        boot_info.find_device_untyped(apbdbg_base)?;

    // Allocate slot for the frame
    let frame_slot = registry.alloc_slot();

    // Calculate byte offset within the untyped region
    let aligned_base = apbdbg_base & !0xFFF;
    if aligned_base < untyped_base {
        return None;
    }
    let offset_in_untyped = aligned_base - untyped_base;

    // Retype to 4KB DeviceFrame
    if retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        frame_slot,
        offset_in_untyped,
    )
    .is_err()
    {
        return None;
    }

    // Calculate offset within the page for accessing registers
    let offset_within_page = (apbdbg_base & 0xFFF) as usize;

    // Map to a temporary virtual address
    const APBDBG_VADDR: u64 = 0x0000_B000_0000;

    // Create page tables for APBDBG_VADDR.
    // Multiple DWC hosts share the same L1/L2/L3 VA range, so subsequent
    // calls may return AlreadyMapped — that's fine, we ignore the error.
    let l1_slot = registry.alloc_slot();
    let _ = retype(
        cptr(slots::RAM_UNTYPED),
        5, // PageTableL1
        0,
        cptr(slots::ROOT_CNODE),
        l1_slot,
        1,
    );
    let l1_base = APBDBG_VADDR & !(512 * 1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l1_slot), l1_base, 1);

    let l2_slot = registry.alloc_slot();
    let _ = retype(
        cptr(slots::RAM_UNTYPED),
        6, // PageTableL2
        0,
        cptr(slots::ROOT_CNODE),
        l2_slot,
        1,
    );
    let l2_base = APBDBG_VADDR & !(1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l2_slot), l2_base, 2);

    let l3_slot = registry.alloc_slot();
    let _ = retype(
        cptr(slots::RAM_UNTYPED),
        7, // PageTableL3
        0,
        cptr(slots::ROOT_CNODE),
        l3_slot,
        1,
    );
    let l3_base = APBDBG_VADDR & !(2 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l3_slot), l3_base, 3);

    if map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(frame_slot),
        APBDBG_VADDR,
        0b011, // RW
        0,
    )
    .is_err()
    {
        return None;
    }

    // SAFETY: We just mapped the client register region
    let link_result = unsafe {
        pcie::check_rk3588_link_status((APBDBG_VADDR + offset_within_page as u64) as usize)
    };

    // Read the raw LTSSM status register for diagnostics
    let ltssm_vaddr = APBDBG_VADDR + offset_within_page as u64 + 0x300;
    let raw_status =
        unsafe { core::ptr::read_volatile(ltssm_vaddr as *const u32) };

    let link_str = match link_result {
        Some(true) => "LINK_UP",
        Some(false) => "LINK_DOWN",
        None => "UNKNOWN(clk?)",
    };
    log::debug!("APBDBG {:#x} LTSSM={:#x} {}", apbdbg_base, raw_status as u64, link_str);

    // Unmap
    if let Err(e) = unmap_frame(cptr(slots::ROOT_VSPACE), APBDBG_VADDR) {
        log::warn!("unmap APBDBG frame failed: {}", e.name());
    }

    // Return: Some(true) = link up, Some(false) = link confirmed down,
    // None = register not responding (caller should use fallback logic)
    link_result
}

/// Map a PCIe region (config space or DBI) for enumeration.
///
/// Returns (virtual_address, frame_slot, page_table_slots, mapped_size) or None on failure.
fn map_pcie_region(
    phys_base: u64,
    size: usize,
    registry: &mut Registry,
    boot_info: &DevMgrBootInfo,
    cptr: &impl Fn(u64) -> u64,
    host_index: u64,
) -> Option<(usize, u64, [u64; 3], usize)> {
    use m6_cap::ObjectType;
    use m6_syscall::invoke::{map_frame, map_page_table, retype};

    // Find device untyped covering this address
    let (device_untyped_slot, untyped_size, untyped_base) =
        boot_info.find_device_untyped(phys_base)?;

    // Virtual address for temporary mapping (PCIe probe region)
    // Each host uses a different 1GB region to avoid page table conflicts
    const PCIE_PROBE_VADDR_BASE: u64 = 0x0000_A000_0000;
    const PCIE_REGION_SIZE: u64 = 0x4000_0000; // 1GB per host
    let pcie_probe_vaddr = PCIE_PROBE_VADDR_BASE + (host_index * PCIE_REGION_SIZE);

    // Determine mapping size: prefer 2MB for comprehensive scanning, but check:
    // 1. Physical address is 2MB aligned
    // 2. Untyped is at least 2MB
    // 3. Requested size is at least 2MB
    const SIZE_2MB: usize = 2 * 1024 * 1024;
    const SIZE_4KB: usize = 4096;

    let phys_2mb_aligned = (phys_base & ((SIZE_2MB as u64) - 1)) == 0;
    let untyped_has_2mb = untyped_size >= SIZE_2MB as u64;
    let want_2mb = size >= SIZE_2MB;
    let use_2mb = phys_2mb_aligned && untyped_has_2mb && want_2mb;

    let (frame_size_bits, mapped_size) = if use_2mb {
        (21u8, SIZE_2MB) // 2MB block
    } else {
        (12u8, SIZE_4KB) // 4KB page
    };

    // Allocate slots for page tables and frame
    let l1_slot = registry.alloc_slot();
    let l2_slot = registry.alloc_slot();
    let l3_slot = registry.alloc_slot(); // Only used for 4KB mapping
    let frame_slot = registry.alloc_slot();

    // Create page tables for probe address region
    // L1 table (covers 512GB)
    if retype(
        cptr(slots::RAM_UNTYPED),
        5, // PageTableL1
        0,
        cptr(slots::ROOT_CNODE),
        l1_slot,
        1,
    )
    .is_err()
    {
        return None;
    }
    let l1_base = pcie_probe_vaddr & !(512 * 1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l1_slot), l1_base, 1);

    // L2 table (covers 1GB)
    if retype(
        cptr(slots::RAM_UNTYPED),
        6, // PageTableL2
        0,
        cptr(slots::ROOT_CNODE),
        l2_slot,
        1,
    )
    .is_err()
    {
        return None;
    }
    let l2_base = pcie_probe_vaddr & !(1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l2_slot), l2_base, 2);

    // L3 table only needed for 4KB mappings (2MB blocks go directly in L2)
    if !use_2mb {
        if retype(
            cptr(slots::RAM_UNTYPED),
            7, // PageTableL3
            0,
            cptr(slots::ROOT_CNODE),
            l3_slot,
            1,
        )
        .is_err()
        {
            return None;
        }
        let l3_base = pcie_probe_vaddr & !(2 * 1024 * 1024 - 1);
        let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l3_slot), l3_base, 3);
    }

    // Retype device untyped to DeviceFrame
    // Compute byte offset of the frame-aligned physical address within the untyped
    let frame_align = 1u64 << frame_size_bits;
    let aligned_base = phys_base & !(frame_align - 1);
    let offset = aligned_base.saturating_sub(untyped_base);
    if retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        frame_size_bits as u64,
        cptr(slots::ROOT_CNODE),
        frame_slot,
        offset,
    )
    .is_err()
    {
        return None;
    }

    // Map the frame
    if map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(frame_slot),
        pcie_probe_vaddr,
        0b011, // RW, device memory
        0,
    )
    .is_err()
    {
        return None;
    }

    Some((
        pcie_probe_vaddr as usize,
        frame_slot,
        [l1_slot, l2_slot, l3_slot],
        mapped_size,
    ))
}

/// Map a single 4KB device page and return the frame slot.
///
/// Assumes page tables already exist for `vaddr` (e.g. created by `map_pcie_region`).
fn map_pcie_page(
    phys_addr: u64,
    vaddr: u64,
    registry: &mut Registry,
    boot_info: &DevMgrBootInfo,
    cptr: &impl Fn(u64) -> u64,
) -> Option<u64> {
    use m6_cap::ObjectType;
    use m6_syscall::invoke::{map_frame, retype};

    let (device_untyped_slot, _size, untyped_base) =
        boot_info.find_device_untyped(phys_addr)?;
    let frame_slot = registry.alloc_slot();
    let offset = phys_addr.saturating_sub(untyped_base);
    retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        frame_slot,
        offset,
    )
    .ok()?;
    map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(frame_slot),
        vaddr,
        0b011, // RW, device memory
        0,
    )
    .ok()?;
    Some(frame_slot)
}

/// Scan the secondary bus behind a DWC PCIe root port.
///
/// On DWC controllers, the root port's config space is in the DBI registers
/// (not accessible via the ECAM window). This function:
/// 1. Maps the DBI config page to read the root port's Type 1 header
/// 2. Reads the secondary bus number from the bridge header
/// 3. Programmes the iATU for downstream config access
/// 4. Maps and scans the secondary bus for devices
fn scan_dwc_secondary_bus(
    host: &pcie::PcieHostBridge,
    _config_vaddr: usize,
    pcie_probe_vaddr: u64,
    registry: &mut Registry,
    boot_info: &DevMgrBootInfo,
    cptr: &impl Fn(u64) -> u64,
) {
    use m6_syscall::invoke::unmap_frame;

    // Resolve DBI base. The DBI provides direct access to the root port's
    // Type 1 configuration header and the iATU registers.
    // Prefer the DTB-provided dbi_base; if > 4GB and no device untyped
    // covers it, fall back to the low-address DBI derived from config_base.
    let dbi_base = if host.dbi_base != 0 {
        if boot_info.find_device_untyped(host.dbi_base).is_some() {
            Some(host.dbi_base)
        } else {
            pcie::dbi_low_addr_for_config(host.config_base)
        }
    } else {
        pcie::dbi_low_addr_for_config(host.config_base)
    };

    let Some(dbi_base) = dbi_base else {
        log::debug!("PCIe: no usable DBI base for secondary scan");
        return;
    };

    log::debug!("PCIe: DBI base={:#x}", dbi_base);

    // Map DBI config page (offset 0 = root port's PCIe config header)
    let dbi_config_vaddr = pcie_probe_vaddr + 0x3000;
    let Some(_dbi_config_slot) =
        map_pcie_page(dbi_base, dbi_config_vaddr, registry, boot_info, cptr)
    else {
        log::debug!("PCIe: failed to map DBI config page at {:#x}", dbi_base);
        return;
    };

    // Read bridge info from DBI. The DBI mirrors the root port's Type 1
    // config header at offset 0x000-0xFFF. Use rel_bus=0, dev=0, func=0
    // because the DBI page IS the root port's config space.
    // SAFETY: DBI config page is mapped at dbi_config_vaddr
    let bridge = unsafe { pcie::read_bridge_info(dbi_config_vaddr as usize, 0, 0, 0) };
    // Keep DBI config page mapped — we need it after enumeration to update
    // bridge memory windows for downstream device BAR forwarding.

    let Some(bridge) = bridge else {
        let _ = unmap_frame(cptr(slots::ROOT_VSPACE), dbi_config_vaddr);
        log::debug!("PCIe: DBI header is not a bridge");
        return;
    };

    let secondary_bus = if bridge.secondary_bus == 0 || bridge.secondary_bus == 0xFF {
        // Firmware didn't assign bus numbers. Programme them ourselves:
        // primary = bus_start, secondary = bus_start + 1, subordinate = bus_start + 1
        let (bus_start, _) = host.bus_range;
        let pri = bus_start;
        let sec = bus_start.wrapping_add(1);
        let sub = sec;
        let bus_reg = (pri as u32) | ((sec as u32) << 8) | ((sub as u32) << 16);
        // SAFETY: DBI config page is mapped at dbi_config_vaddr
        unsafe {
            pcie::cfg_write32(dbi_config_vaddr as usize, 0, 0, 0, 0x18, bus_reg);
        }
        log::debug!("PCIe: assigned bus numbers pri={} sec={} sub={}", pri, sec, sub);
        sec
    } else {
        bridge.secondary_bus
    };

    log::debug!("PCIe: root port bridge -> secondary bus {}", secondary_bus);

    // Enable Memory Space and Bus Master on the root port via DBI.
    // Without BME, the root complex drops inbound DMA TLPs from downstream
    // devices (NVMe, etc.), causing all DMA to silently fail.
    // SAFETY: DBI config page is mapped at dbi_config_vaddr
    unsafe {
        pcie::enable_bus_master(dbi_config_vaddr as usize, 0, 0, 0);
    }
    // Map iATU registers (DBI + 0x300000) for outbound ATU programming.
    let iatu_phys = dbi_base + pcie::IATU_OFFSET;
    let iatu_vaddr = pcie_probe_vaddr + 0x2000;
    let Some(_iatu_slot) = map_pcie_page(iatu_phys, iatu_vaddr, registry, boot_info, cptr) else {
        let _ = unmap_frame(cptr(slots::ROOT_VSPACE), dbi_config_vaddr);
        log::debug!("PCIe: failed to map iATU registers");
        return;
    };

    // Disable all inbound iATU windows that UEFI may have left enabled.
    // SAFETY: iATU registers are mapped at iatu_vaddr
    unsafe {
        pcie::disable_all_inbound_iatu(iatu_vaddr as usize);
    }

    // Programme ATU region 0 for CFG0 access to the secondary bus.
    // Use offset 1MB (slot 1) into the config window — slot 0 is the root
    // port itself (accessed via DBI internally). The ATU's target_bus tells
    // the hardware which PCIe bus to reach, regardless of the ECAM offset.
    // Note: UEFI may number buses differently from the DTB bus-range, so we
    // don't rely on bus_range.0 here.
    let sec_cpu_addr = host.config_base + (1u64 << 20);
    // SAFETY: iATU registers are mapped at iatu_vaddr
    unsafe {
        pcie::programme_iatu_for_config(
            iatu_vaddr as usize,
            0, // region 0
            pcie::IATU_TYPE_CFG0,
            sec_cpu_addr,
            1 << 20, // 1MB per bus
            secondary_bus,
        );
    }

    // Map a 4KB page of the secondary bus's config space
    let sec_config_phys = sec_cpu_addr;
    let sec_config_vaddr = pcie_probe_vaddr + 0x1000;
    let _sec_frame_slot =
        match map_pcie_page(sec_config_phys, sec_config_vaddr, registry, boot_info, cptr) {
            Some(slot) => slot,
            None => {
                log::debug!("PCIe: failed to map secondary bus config");
                let _ = unmap_frame(cptr(slots::ROOT_VSPACE), iatu_vaddr);
                let _ = unmap_frame(cptr(slots::ROOT_VSPACE), dbi_config_vaddr);
                return;
            }
        };

    // Scan the secondary bus for devices
    // SAFETY: secondary bus config page mapped at sec_config_vaddr for 4KB
    let sec_devices =
        unsafe { pcie::enumerate_devices_at(host, sec_config_vaddr as usize, secondary_bus, 4096) };

    let has_devices = sec_devices.iter().any(|d| d.is_valid());

    for device in &sec_devices {
        if device.is_valid() {
            add_pcie_device_to_registry(registry, host, device);
        }
    }

    // Enable MSI-X in config space while we still have the ATU in CFG0 mode
    // and the secondary bus config page mapped. This must happen here because
    // after the ATU is reprogrammed for MEM access, the device untyped regions
    // for iATU/config are consumed and cannot be re-retyped during driver spawn.
    for device in &sec_devices {
        if device.is_valid() && device.msix.present {
            let cap_vaddr = sec_config_vaddr as usize + device.msix.cap_offset as usize;
            // SAFETY: secondary config page is mapped at sec_config_vaddr,
            // cap_offset is within the 4KB page (validated during enumeration)
            unsafe {
                let msg_ctrl_addr = cap_vaddr + 2;
                let msg_ctrl = core::ptr::read_volatile(msg_ctrl_addr as *const u16);
                // Set MSI-X Enable (bit 15); leave Function Mask clear —
                // individual vector masks default to 1, so no spurious interrupts.
                let new_msg_ctrl = (msg_ctrl | (1 << 15)) & !(1 << 14);
                core::ptr::write_volatile(msg_ctrl_addr as *mut u16, new_msg_ctrl);

                let readback = core::ptr::read_volatile(msg_ctrl_addr as *const u16);
                if readback & (1 << 15) == 0 {
                    log::warn!(
                        "PCIe: MSI-X enable failed for BDF {:02x}:{:02x}.{:x}",
                        device.bdf.0, device.bdf.1, device.bdf.2,
                    );
                }
            }
        }
    }

    // If we found downstream devices, set up the root port for runtime access:
    // 1. Update bridge Memory Base/Limit so the root port forwards MEM TLPs
    // 2. Reprogram ATU region 0 for MEM (not CFG0) so CPU accesses translate
    //    to memory read/write TLPs rather than config TLPs
    if has_devices && host.mem32_size > 0 {
        // Bridge Memory Base/Limit uses PCI addresses (the address space seen
        // on the PCIe bus after ATU translation), not CPU addresses.
        let mem_base_pci = host.mem32_pci;
        let mem_limit_pci = host.mem32_pci + host.mem32_size - 1;

        // SAFETY: DBI config page is still mapped at dbi_config_vaddr
        unsafe {
            pcie::set_bridge_memory_window(
                dbi_config_vaddr as usize,
                mem_base_pci,
                mem_limit_pci,
            );
        }

        // SAFETY: iATU registers are still mapped at iatu_vaddr
        unsafe {
            pcie::programme_iatu_for_mem(
                iatu_vaddr as usize,
                0, // region 0 (was CFG0, now MEM)
                host.mem32_cpu,
                host.mem32_pci,
                host.mem32_size,
            );
        }

        // Inbound DMA path: on RK3588, the DWC PCIe RC passes all inbound
        // TLPs through to the AXI bus by default when no inbound iATU windows
        // are enabled. Linux's DWC core confirms this: when dma-ranges is
        // absent (as on RK3588), dw_pcie_iatu_setup() skips inbound iATU
        // programming entirely, and dw_pcie_setup_rc() zeroes BAR0 at the end.
        // DMA works through default pass-through behaviour.
        //
        // We already disabled all inbound iATU above. Match Linux: zero BAR0.
        // SAFETY: DBI config page is mapped
        unsafe { pcie::setup_rc_bar0_for_dma(dbi_config_vaddr as usize) };
    }

    // Clean up temporary mappings
    let _ = unmap_frame(cptr(slots::ROOT_VSPACE), sec_config_vaddr);
    let _ = unmap_frame(cptr(slots::ROOT_VSPACE), iatu_vaddr);
    let _ = unmap_frame(cptr(slots::ROOT_VSPACE), dbi_config_vaddr);
}

/// Add a PCIe device to the registry.
fn add_pcie_device_to_registry(
    registry: &mut Registry,
    host: &pcie::PcieHostBridge,
    device: &pcie::PcieDevice,
) {
    use registry::DeviceEntry;

    let mut entry = DeviceEntry::empty();

    // Build path string: "pcie:BB:DD.F"
    let (bus, dev, func) = device.bdf;
    let mut path_buf = [0u8; 16];
    path_buf[0..5].copy_from_slice(b"pcie:");
    path_buf[5] = hex_nibble(bus >> 4);
    path_buf[6] = hex_nibble(bus & 0xF);
    path_buf[7] = b':';
    path_buf[8] = hex_nibble(dev >> 4);
    path_buf[9] = hex_nibble(dev & 0xF);
    path_buf[10] = b'.';
    path_buf[11] = hex_nibble(func);
    let path_len = 12;
    entry.path[..path_len].copy_from_slice(&path_buf[..path_len]);
    entry.path_len = path_len;

    // Build compatible string: "pcie:CCSSPP" (class code)
    let class_str = device.format_class_code();
    let mut compat_buf = [0u8; 12];
    compat_buf[0..5].copy_from_slice(b"pcie:");
    compat_buf[5..11].copy_from_slice(&class_str);
    let compat_len = 11;
    entry.compatible[..compat_len].copy_from_slice(&compat_buf[..compat_len]);
    entry.compatible_len = compat_len;

    // Set physical address and size from BAR0
    entry.phys_base = device.bar0_cpu_addr;
    entry.size = device.bar0_size;

    // PCIe devices typically use MSI/MSI-X, IRQ will be set during driver init
    entry.irq = 0;

    // Set PCIe-specific fields
    entry.pcie_bdf = Some(device.bdf);
    entry.stream_id = device.stream_id;
    entry.smmu_phandle = host.iommu_phandle;

    // Copy MSI-X capability info if present
    if device.msix.present {
        entry.msix = registry::MsixInfo {
            present: true,
            table_size: device.msix.table_size,
            table_bir: device.msix.table_bir,
            table_offset: device.msix.table_offset,
            cap_offset: device.msix.cap_offset,
        };
    }

    entry.state = registry::DeviceState::Unbound;

    if registry.add_device(entry).is_none() {
        log::debug!("PCIe: registry full, cannot add device");
    }
}

/// Convert nibble (0-15) to hex character.
fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + n - 10 }
}

/// Probe all VirtIO MMIO devices to determine their device type.
///
/// This maps the VirtIO MMIO region once and probes each device by reading
/// the DeviceID register at its offset within the region.
///
/// VirtIO MMIO is only present on QEMU virt; on real hardware (e.g. Rock 5B+)
/// this function returns early.
fn probe_virtio_devices(registry: &mut Registry) {
    use m6_cap::ObjectType;
    use m6_syscall::invoke::{map_frame, map_page_table, retype, unmap_frame};

    // SAFETY: _start has initialised BOOT_INFO
    let boot_info = unsafe { get_boot_info() };

    // Check if any VirtIO devices were enumerated from DTB.
    // If not, skip probing entirely - this is the case on real hardware.
    let has_virtio_devices = (0..registry.device_count)
        .any(|i| dtb::is_virtio_mmio(registry.devices[i].compatible_str()));
    if !has_virtio_devices {
        return;
    }

    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, boot_info.cnode_radix);

    // Virtual address for temporary MMIO mapping
    const PROBE_VADDR: u64 = 0x0000_9000_0000;
    // VirtIO MMIO base address on QEMU virt
    const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
    // Number of 4KB frames to map (16KB total = 4 frames)
    const NUM_FRAMES: usize = 4;

    // Find the device untyped that covers VirtIO MMIO space
    let (device_untyped, _untyped_size, _untyped_base) =
        match boot_info.find_device_untyped(VIRTIO_MMIO_BASE) {
            Some((slot, size, base)) => (slot, size, base),
            None => {
                // VirtIO devices in DTB but no device untyped - this shouldn't happen
                // on a properly configured system, but handle gracefully.
                log::warn!("VirtIO devices in DTB but no device untyped");
                return;
            }
        };

    // Allocate slots for probe page tables and frames
    let l1_slot = registry.alloc_slot();
    let l2_slot = registry.alloc_slot();
    let l3_slot = registry.alloc_slot();
    let mut frame_slots = [0u64; NUM_FRAMES];
    for slot in &mut frame_slots {
        *slot = registry.alloc_slot();
    }

    // Create page tables for probe address region
    // L1 table (covers 512GB)
    if retype(
        cptr(slots::RAM_UNTYPED),
        5,
        0,
        cptr(slots::ROOT_CNODE),
        l1_slot,
        1,
    )
    .is_err()
    {
        log::error!("VirtIO probe L1 retype failed");
        return;
    }
    let l1_base = PROBE_VADDR & !(512 * 1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l1_slot), l1_base, 1);

    // L2 table (covers 1GB)
    if retype(
        cptr(slots::RAM_UNTYPED),
        6,
        0,
        cptr(slots::ROOT_CNODE),
        l2_slot,
        1,
    )
    .is_err()
    {
        log::error!("VirtIO probe L2 retype failed");
        return;
    }
    let l2_base = PROBE_VADDR & !(1024 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l2_slot), l2_base, 2);

    // L3 table (covers 2MB)
    if retype(
        cptr(slots::RAM_UNTYPED),
        7,
        0,
        cptr(slots::ROOT_CNODE),
        l3_slot,
        1,
    )
    .is_err()
    {
        log::error!("VirtIO probe L3 retype failed");
        return;
    }
    let l3_base = PROBE_VADDR & !(2 * 1024 * 1024 - 1);
    let _ = map_page_table(cptr(slots::ROOT_VSPACE), cptr(l3_slot), l3_base, 3);

    // Retype device untyped to DeviceFrames
    if retype(
        cptr(device_untyped),
        ObjectType::DeviceFrame as u64,
        12, // 4KB per frame
        cptr(slots::ROOT_CNODE),
        frame_slots[0],
        NUM_FRAMES as u64,
    )
    .is_err()
    {
        log::error!("VirtIO probe device retype failed");
        return;
    }

    // Map all frames contiguously
    for (i, &slot) in frame_slots.iter().enumerate() {
        let vaddr = PROBE_VADDR + (i * 4096) as u64;
        // Continue on failure - we may still probe some devices
        let _ = map_frame(cptr(slots::ROOT_VSPACE), cptr(slot), vaddr, 0b011, 0);
    }

    // Now probe each VirtIO device by its offset from the base
    for i in 0..registry.device_count {
        let compat_str: [u8; 64] = {
            let mut buf = [0u8; 64];
            let len = registry.devices[i].compatible_len.min(64);
            buf[..len].copy_from_slice(&registry.devices[i].compatible[..len]);
            buf
        };
        let compat_len = registry.devices[i].compatible_len.min(64);
        let compat = core::str::from_utf8(&compat_str[..compat_len]).unwrap_or("");
        let phys_base = registry.devices[i].phys_base;

        // Only probe VirtIO MMIO devices
        if !dtb::is_virtio_mmio(compat) {
            continue;
        }

        // Calculate offset from VirtIO base
        if phys_base < VIRTIO_MMIO_BASE {
            continue;
        }
        let offset = phys_base - VIRTIO_MMIO_BASE;

        // Check if within our mapped region (16KB)
        if offset >= (NUM_FRAMES * 4096) as u64 {
            continue;
        }

        // Probe the device type at this offset
        let probe_addr = PROBE_VADDR + offset;
        // SAFETY: We mapped this region above
        let device_id = unsafe { dtb::probe_virtio_device_type(probe_addr as *const u8) };

        // Store the device ID in the registry
        registry.devices[i].virtio_device_id = device_id;
    }

    // Unmap frames from device-mgr's address space (but keep capabilities for reuse)
    for (i, &_slot) in frame_slots.iter().enumerate() {
        let vaddr = PROBE_VADDR + (i * 4096) as u64;
        if let Err(e) = unmap_frame(cptr(slots::ROOT_VSPACE), vaddr) {
            log::warn!("unmap VirtIO frame failed: {}", e.name());
        }
    }

    // Store probe frame capabilities in registry for reuse when spawning drivers.
    // This avoids the "NoMemory" error from trying to retype the device untyped
    // again (seL4-style untyped watermark only moves forward, not reset on delete).
    for (i, &slot) in frame_slots.iter().enumerate() {
        let phys_base = VIRTIO_MMIO_BASE + (i * 4096) as u64;
        registry.add_virtio_probe_frame(phys_base, slot);
    }
}

/// Get the initrd data slice.
fn get_initrd() -> Option<&'static [u8]> {
    // SAFETY: _start has initialised BOOT_INFO
    let boot_info = unsafe { get_boot_info() };
    if !boot_info.has_initrd() {
        return None;
    }
    unsafe { boot_info.initrd_slice() }
}

/// Main service loop - handles client requests.
fn service_loop(registry: &mut Registry) -> ! {
    // Get CNode radix from boot info
    // SAFETY: _start has initialised BOOT_INFO
    let boot_info = unsafe { get_boot_info() };
    let radix = boot_info.cnode_radix;

    // Helper to convert slot to CPtr
    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, radix);

    let registry_cptr = cptr(slots::REGISTRY_EP);

    log::info!("Entering service loop, registry_cptr={:#x}", registry_cptr);

    // Wait for the first request
    let mut last_response: u64 = 0;
    let mut first_message = true;

    loop {
        let result = if first_message {
            // First iteration: just receive (no reply to send yet)
            first_message = false;
            recv(registry_cptr)
        } else {
            // Subsequent iterations: reply to previous caller and wait for next
            reply_recv(registry_cptr, last_response, 0, 0, 0)
        };

        match result {
            Ok(ipc_result) => {
                let sender_badge = ipc_result.badge;
                let label = ipc_result.label;
                let msg = &ipc_result.msg;

                log::debug!("MSG label={:#x} msg0={:#x}", label, msg[0]);

                // Handle the request and store response for next reply_recv
                last_response = handle_request(registry, sender_badge, label, msg);

                log::debug!("REPLY resp={:#x}", last_response);
            }
            Err(e) => {
                log::error!("Service loop error: {:?}", e);
                sched_yield();
                first_message = true; // Reset to recv mode
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(registry: &mut Registry, badge: u64, label: u64, msg: &[u64; 4]) -> u64 {
    match label {
        ipc::request::ENSURE => handle_ensure(registry, badge, msg),
        ipc::request::SUBSCRIBE => handle_subscribe(registry, badge, msg),
        ipc::request::UNSUBSCRIBE => handle_unsubscribe(registry, msg),
        ipc::request::LIST_DEVICES => handle_list_devices(registry, msg),
        ipc::request::GET_DEVICE_INFO => handle_get_device_info(registry, msg),
        ipc::request::RESTART_DECISION => handle_restart_decision(registry, msg),
        _ => ipc::response::ERR_INVALID_REQUEST,
    }
}

/// Handle ensure() request - spawn or return existing driver endpoint.
///
/// This is the main entry point for clients to get access to a device driver.
/// The request is idempotent: if the driver is already running, we just return
/// the existing endpoint.
///
/// Arguments:
///   msg[0]: device index (if non-zero, look up by index) OR class ID for service-based requests
///
/// Class IDs (values >= 0x1000) are used for service-based ENSURE:
///   - CLASS_USB_HID (0x1001): Request USB HID driver for keyboard/mouse input
fn handle_ensure(registry: &mut Registry, _badge: u64, msg: &[u64; 4]) -> u64 {
    let request_id = msg[0];

    // Check if this is a class-based request (class IDs start at 0x1000)
    if request_id >= 0x1000 {
        return handle_class_ensure(registry, request_id);
    }

    // Device-based request
    let device_hint = request_id as usize;

    // Find the device - either by hint or by heuristic
    let device_idx = if device_hint > 0 && device_hint <= registry.device_count {
        // Use provided device index (1-based in message, convert to 0-based)
        device_hint - 1
    } else {
        // Use heuristics: first try unbound devices, then running UART
        match find_first_unbound_device(registry) {
            Some(idx) => idx,
            None => {
                // No unbound devices - try to find running UART driver
                match find_running_uart(registry) {
                    Some(idx) => idx,
                    None => return ipc::response::ERR_DEVICE_NOT_FOUND,
                }
            }
        }
    };

    let device = &registry.devices[device_idx];

    // Check current state
    match device.state {
        DeviceState::Running => {
            // Driver already running - transfer endpoint to client
            let driver_idx = device.driver_idx;
            if driver_idx < registry.driver_count {
                let driver = &registry.drivers[driver_idx];
                // SAFETY: _start has initialised BOOT_INFO
                let boot_info = unsafe { get_boot_info() };
                let endpoint_cptr = slot_to_cptr(driver.endpoint_slot, boot_info.cnode_radix);

                // SAFETY: IPC buffer is mapped for device-mgr
                unsafe {
                    ipc_set_send_caps(&[endpoint_cptr]);
                }

                return ipc::response::OK;
            }
            ipc::response::ERR_DEVICE_NOT_FOUND
        }
        DeviceState::Starting => {
            // Driver starting - client should retry
            ipc::response::ERR_DRIVER_STARTING
        }
        DeviceState::Dead => {
            // Driver dead - waiting for supervisor decision
            ipc::response::ERR_DRIVER_DEAD
        }
        DeviceState::Unbound => {
            // Need to spawn driver
            spawn_driver_for_device(registry, device_idx)
        }
    }
}

/// Handle class-based ENSURE request.
///
/// This spawns service drivers on demand based on class ID rather than device path.
fn handle_class_ensure(registry: &mut Registry, class_id: u64) -> u64 {
    match class_id {
        ipc::class::USB_HID => handle_usb_hid_ensure(registry),
        ipc::class::FAT32 => handle_fat32_ensure(registry),
        _ => {
            log::warn!("Unknown class ID: {:#x}", class_id);
            ipc::response::ERR_DEVICE_NOT_FOUND
        }
    }
}

/// Handle USB HID driver ENSURE request.
///
/// The HID driver is a class driver that sits above the USB host controller.
/// It needs:
/// - USB host driver endpoint (to communicate with USB devices)
/// - Its own service endpoint (for clients like the shell)
fn handle_usb_hid_ensure(registry: &mut Registry) -> u64 {
    log::debug!("Handling USB HID ENSURE request");

    // Check if HID driver is already running
    if let Some(endpoint_slot) = registry.hid_driver_endpoint {
        // SAFETY: _start has initialised BOOT_INFO
        let boot_info = unsafe { get_boot_info() };
        let endpoint_cptr = slot_to_cptr(endpoint_slot, boot_info.cnode_radix);

        // Transfer endpoint to client
        unsafe {
            ipc_set_send_caps(&[endpoint_cptr]);
        }

        return ipc::response::OK;
    }

    // Find USB host driver (xHCI or DWC3)
    let usb_host_endpoint = find_usb_host_driver(registry);
    if usb_host_endpoint.is_none() {
        log::debug!("USB HID ENSURE: no USB host driver available");
        return ipc::response::ERR_NO_DRIVER;
    }
    let usb_host_ep_slot = usb_host_endpoint.unwrap();
    log::debug!("USB HID ENSURE: found USB host, spawning HID driver");

    // Spawn HID driver
    match spawn_hid_driver(registry, usb_host_ep_slot) {
        Ok(endpoint_slot) => {
            registry.hid_driver_endpoint = Some(endpoint_slot);

            // Transfer endpoint to client
            // SAFETY: _start has initialised BOOT_INFO
            let boot_info = unsafe { get_boot_info() };
            let endpoint_cptr = slot_to_cptr(endpoint_slot, boot_info.cnode_radix);

            unsafe {
                ipc_set_send_caps(&[endpoint_cptr]);
            }

            log::debug!("USB HID ENSURE: success, endpoint at slot {}", endpoint_slot);
            ipc::response::OK
        }
        Err(e) => {
            log::error!("USB HID ENSURE: spawn failed: {}", e);
            ipc::response::ERR_SPAWN_FAILED
        }
    }
}

/// Find a running USB host driver (xHCI or DWC3).
///
/// Returns the first running USB host driver's endpoint slot. We avoid making
/// blocking IPC calls to query drivers here because the device-mgr is
/// single-threaded — a blocking call to a driver that is still initialising
/// (or busy servicing bound notifications from IRQs) would deadlock the
/// entire device-mgr, preventing it from processing any other requests.
///
/// The HID driver probes connected devices lazily on first SUBSCRIBE, so
/// returning any running USB host is sufficient.
fn find_usb_host_driver(registry: &Registry) -> Option<u64> {
    for i in 0..registry.device_count {
        if registry.devices[i].state != DeviceState::Running {
            continue;
        }

        let compat = registry.devices[i].compatible_str();
        if !(compat.contains("xhci") || compat.contains("dwc3") || compat.contains("usb")) {
            continue;
        }

        let driver_idx = registry.devices[i].driver_idx;
        if driver_idx >= registry.driver_count {
            continue;
        }

        return Some(registry.drivers[driver_idx].endpoint_slot);
    }

    None
}

/// Spawn the USB HID driver.
fn spawn_hid_driver(registry: &mut Registry, usb_host_ep_slot: u64) -> Result<u64, &'static str> {
    // Find HID driver binary in initrd
    let initrd = get_initrd().ok_or("No initrd available")?;
    let archive = tar_no_std::TarArchiveRef::new(initrd).map_err(|_| "Failed to parse initrd")?;

    let elf_data = archive
        .entries()
        .find(|e| e.filename().as_str() == Ok("drv-usb-hid"))
        .map(|e| e.data())
        .ok_or("HID driver binary not found")?;

    // Spawn the HID driver as a class driver (no specific device)
    let result = spawn::spawn_class_driver(registry, elf_data, usb_host_ep_slot)?;

    Ok(result.endpoint_slot)
}

/// Handle FAT32 filesystem service ENSURE request.
fn handle_fat32_ensure(registry: &mut Registry) -> u64 {
    if let Some(endpoint_slot) = registry.fat32_ep_slot {
        // SAFETY: _start has initialised BOOT_INFO
        let boot_info = unsafe { get_boot_info() };
        let endpoint_cptr = slot_to_cptr(endpoint_slot, boot_info.cnode_radix);
        // SAFETY: IPC buffer is mapped at the fixed ABI address
        unsafe {
            ipc_set_send_caps(&[endpoint_cptr]);
        }
        return ipc::response::OK;
    }

    let nvme_ep_slot = match find_nvme_driver(registry) {
        Some(slot) => slot,
        None => {
            log::info!("No NVMe driver available for FAT32");
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    match spawn_fat32_from_nvme(registry, nvme_ep_slot) {
        Ok(endpoint_slot) => {
            registry.fat32_ep_slot = Some(endpoint_slot);
            // SAFETY: _start has initialised BOOT_INFO
            let boot_info = unsafe { get_boot_info() };
            let endpoint_cptr = slot_to_cptr(endpoint_slot, boot_info.cnode_radix);
            // SAFETY: IPC buffer is mapped at the fixed ABI address
            unsafe {
                ipc_set_send_caps(&[endpoint_cptr]);
            }
            ipc::response::OK
        }
        Err(e) => {
            log::error!("Failed to spawn FAT32 service: {}", e);
            ipc::response::ERR_SPAWN_FAILED
        }
    }
}

/// Find a running NVMe driver and return its endpoint slot.
fn find_nvme_driver(registry: &Registry) -> Option<u64> {
    for i in 0..registry.device_count {
        if registry.devices[i].state != DeviceState::Running {
            continue;
        }
        let compat = registry.devices[i].compatible_str();
        if !(compat.contains("nvme") || compat.contains("010802")) {
            continue;
        }
        let driver_idx = registry.devices[i].driver_idx;
        if driver_idx >= registry.driver_count {
            continue;
        }
        return Some(registry.drivers[driver_idx].endpoint_slot);
    }
    None
}

/// Spawn the FAT32 service and return its endpoint slot.
fn spawn_fat32_from_nvme(registry: &mut Registry, nvme_ep_slot: u64) -> Result<u64, &'static str> {
    let initrd = get_initrd().ok_or("No initrd available")?;
    let archive = tar_no_std::TarArchiveRef::new(initrd).map_err(|_| "Failed to parse initrd")?;

    let elf_data = archive
        .entries()
        .find(|e| e.filename().as_str() == Ok("svc-fat32"))
        .map(|e| e.data())
        .ok_or("svc-fat32 binary not found")?;

    let result = spawn::spawn_fat32_service(registry, elf_data, nvme_ep_slot)?;
    Ok(result.endpoint_slot)
}

/// Find first unbound device that has a driver available in the initrd.
fn find_first_unbound_device(registry: &Registry) -> Option<usize> {
    let initrd = get_initrd()?;
    let archive = tar_no_std::TarArchiveRef::new(initrd).ok()?;

    for i in 0..registry.device_count {
        if registry.devices[i].state == DeviceState::Unbound {
            // Check if driver exists for this device
            let compat = registry.devices[i].compatible_str();
            let virtio_id = registry.devices[i].virtio_device_id;
            if let Some(entry) = manifest::find_driver(compat, virtio_id) {
                // Check if binary exists in initrd
                let has_binary = archive
                    .entries()
                    .any(|e| e.filename().as_str() == Ok(entry.binary_name));
                if has_binary {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Find running UART driver (for init's console request).
fn find_running_uart(registry: &Registry) -> Option<usize> {
    for i in 0..registry.device_count {
        if registry.devices[i].state == DeviceState::Running {
            let compat = registry.devices[i].compatible_str();
            // Check if this is a UART device
            if compat.contains("pl011") || compat.contains("uart") {
                return Some(i);
            }
        }
    }
    None
}

/// Spawn a driver for a specific device.
fn spawn_driver_for_device(registry: &mut Registry, device_idx: usize) -> u64 {
    // Copy compatible string to avoid borrow issues
    let mut compat_buf = [0u8; 64];
    let compat_len;
    {
        let device = &registry.devices[device_idx];
        compat_len = device.compatible_len;
        compat_buf[..compat_len].copy_from_slice(&device.compatible[..compat_len]);
    }
    let compat = core::str::from_utf8(&compat_buf[..compat_len]).unwrap_or("");

    // Get virtio device ID (for type-specific driver matching)
    let virtio_id = registry.devices[device_idx].virtio_device_id;

    // Find driver in manifest
    let manifest_entry = match manifest::find_driver(compat, virtio_id) {
        Some(m) => m,
        None => {
            log::debug!("No driver for: {}", compat);
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    // Find driver binary in initrd
    let initrd = match get_initrd() {
        Some(data) => data,
        None => {
            log::error!("No initrd available");
            return ipc::response::ERR_NO_DRIVER;
        }
    };
    let archive = match tar_no_std::TarArchiveRef::new(initrd) {
        Ok(a) => a,
        Err(_) => {
            log::error!("Failed to parse initrd TAR");
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    let elf_data = match archive
        .entries()
        .find(|e| e.filename().as_str() == Ok(manifest_entry.binary_name))
    {
        Some(entry) => entry.data(),
        None => {
            log::error!("Driver binary not found: {}", manifest_entry.binary_name);
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    // Copy device info before modifying registry
    let device_info = DeviceInfo::from_entry(&registry.devices[device_idx]);

    // Mark device as starting
    registry.devices[device_idx].state = DeviceState::Starting;

    // Spawn the driver
    // Pass console endpoint if available (for drivers spawned after UART)
    let config = DriverSpawnConfig {
        elf_data,
        device_info,
        device_idx,
        manifest: manifest_entry,
        console_ep_slot: registry.console_ep_slot,
    };
    let spawn_result = spawn::spawn_driver(&config, registry);

    match spawn_result {
        Ok(result) => {
            // Update device state
            registry.devices[device_idx].state = DeviceState::Running;
            registry.devices[device_idx].driver_idx = result.driver_idx;

            log::info!("Spawned driver for: {}", compat);

            // If this is a UART driver, store its endpoint as the console
            // so subsequent drivers can use IPC-based console output
            if compat.contains("pl011") || compat.contains("uart") {
                registry.console_ep_slot = Some(result.endpoint_slot);
            }

            // Transfer endpoint to client
            // SAFETY: _start has initialised BOOT_INFO
            let boot_info = unsafe { get_boot_info() };
            let endpoint_cptr = slot_to_cptr(result.endpoint_slot, boot_info.cnode_radix);

            // SAFETY: IPC buffer is mapped for device-mgr
            unsafe {
                ipc_set_send_caps(&[endpoint_cptr]);
            }

            ipc::response::OK
        }
        Err(e) => {
            // Reset device state
            registry.devices[device_idx].state = DeviceState::Unbound;

            let reason: &str = match e {
                spawn::SpawnError::InvalidElf(_) => "invalid ELF",
                spawn::SpawnError::OutOfMemory => "out of memory",
                spawn::SpawnError::RetypeFailed(err) => err.name(),
                spawn::SpawnError::AsidAssignFailed(err) => err.name(),
                spawn::SpawnError::TcbConfigureFailed(err) => err.name(),
                spawn::SpawnError::TcbWriteRegistersFailed(err) => err.name(),
                spawn::SpawnError::TcbResumeFailed(err) => err.name(),
                spawn::SpawnError::FrameMapFailed(err) => err.name(),
                spawn::SpawnError::CapCopyFailed(err) => err.name(),
                spawn::SpawnError::IrqClaimFailed(err) => err.name(),
                spawn::SpawnError::NoSlots => "no slots",
                spawn::SpawnError::DriverNotFound => "driver not found",
                spawn::SpawnError::TooManyDrivers => "too many drivers",
                spawn::SpawnError::DeviceUntypedNotFound => "device untyped not found",
                spawn::SpawnError::IommuRequired => "IOMMU required but not available",
                spawn::SpawnError::MsiAllocateFailed(err) => err.name(),
                spawn::SpawnError::MsixSetupFailed => "MSI-X setup failed",
                spawn::SpawnError::InvalidDeviceConfig => "invalid device config (no MMIO address)",
                spawn::SpawnError::IOSpaceOpFailed(err) => err.name(),
            };
            log::error!("Failed to spawn driver: {}", reason);

            ipc::response::ERR_SPAWN_FAILED
        }
    }
}

/// Handle subscribe() request.
///
/// Arguments:
///   msg[0]: event mask (which events to subscribe to)
///
/// Returns subscription ID in the response.
fn handle_subscribe(registry: &mut Registry, _badge: u64, msg: &[u64; 4]) -> u64 {
    let event_mask = msg[0];

    // Find free subscription slot
    let sub_idx = match registry.find_free_subscription() {
        Some(idx) => idx,
        None => return ipc::response::ERR_ALREADY_SUBSCRIBED,
    };

    // Store subscription
    registry.subscriptions[sub_idx].active = true;
    registry.subscriptions[sub_idx].event_mask = if event_mask != 0 {
        event_mask
    } else {
        ipc::event::ALL
    };

    // Return subscription ID (offset by response code in high bits)
    // Low 16 bits = subscription ID, high bits = response
    (ipc::response::OK << 32) | (sub_idx as u64)
}

/// Handle unsubscribe() request.
///
/// Arguments:
///   msg[0]: subscription_id
fn handle_unsubscribe(registry: &mut Registry, msg: &[u64; 4]) -> u64 {
    let subscription_id = msg[0] as usize;

    if subscription_id >= registry::MAX_SUBSCRIPTIONS {
        return ipc::response::ERR_INVALID_SUBSCRIPTION;
    }

    if !registry.subscriptions[subscription_id].active {
        return ipc::response::ERR_INVALID_SUBSCRIPTION;
    }

    registry.subscriptions[subscription_id].active = false;
    registry.subscriptions[subscription_id].event_mask = 0;
    registry.subscriptions[subscription_id].notification_slot = 0;

    ipc::response::OK
}

/// Handle list_devices() request.
///
/// Arguments:
///   msg[0]: offset (for pagination, 0-based)
///   msg[1]: max_count (maximum devices to return info about)
///
/// Returns total device count. Device info would be written to IPC buffer
/// in a full implementation.
fn handle_list_devices(registry: &Registry, msg: &[u64; 4]) -> u64 {
    let offset = msg[0] as usize;
    let max_count = msg[1] as usize;

    // Calculate how many devices we can return
    let available = registry.device_count.saturating_sub(offset);
    let returned = available.min(max_count);

    // In a full implementation, we would write device summaries to IPC buffer here

    // Return format: total_count in low 32 bits, returned_count in high 32 bits
    ((returned as u64) << 32) | (registry.device_count as u64)
}

/// Handle get_device_info() request.
///
/// Arguments:
///   msg[0]: device index (1-based, 0 = invalid)
///
/// Returns device state and info. In a full implementation, additional
/// info would be written to IPC buffer.
fn handle_get_device_info(registry: &Registry, msg: &[u64; 4]) -> u64 {
    let device_index = msg[0] as usize;

    // Validate device index (1-based in message)
    if device_index == 0 || device_index > registry.device_count {
        return ipc::response::ERR_DEVICE_NOT_FOUND;
    }

    let device = &registry.devices[device_index - 1];

    // Convert state to IPC format
    let state = match device.state {
        DeviceState::Unbound => ipc::device_state::UNBOUND,
        DeviceState::Starting => ipc::device_state::STARTING,
        DeviceState::Running => ipc::device_state::RUNNING,
        DeviceState::Dead => ipc::device_state::DEAD,
    };

    // Return format: response in low 16 bits, state in next 16, irq in high 32
    // Additional info (phys_base, size) would be in IPC buffer
    ipc::response::OK | (state << 16) | ((device.irq as u64) << 32)
}

/// Handle restart_decision() from supervisor.
///
/// Arguments:
///   msg[0]: driver_id (index of the dead driver)
///   msg[1]: action (0 = do not restart, 1 = restart)
fn handle_restart_decision(registry: &mut Registry, msg: &[u64; 4]) -> u64 {
    let driver_id = msg[0] as usize;
    let action = msg[1];

    if driver_id >= registry.driver_count {
        return ipc::response::ERR_DEVICE_NOT_FOUND;
    }

    let driver = &registry.drivers[driver_id];
    if driver.alive {
        return ipc::response::OK;
    }

    if action == 1 {
        // Restart requested - find the device associated with this driver and respawn
        for i in 0..driver.device_count {
            let device_idx = driver.device_indices[i];
            if device_idx < registry.device_count {
                // Reset device state to unbound so it can be respawned
                registry.devices[device_idx].state = DeviceState::Unbound;
                registry.devices[device_idx].driver_idx = usize::MAX;

                // Attempt to spawn the driver again
                return spawn_driver_for_device(registry, device_idx);
            }
        }
    }

    ipc::response::OK
}

/// Handle driver death detection.
///
/// Called when we receive a fault notification for a driver.
fn handle_driver_death(registry: &mut Registry, fault_badge: u64) {
    let driver_idx = ipc::badge::driver_index_from_badge(fault_badge) as usize;

    if driver_idx >= registry.driver_count {
        return;
    }

    log::error!("Driver died: index {}", driver_idx);

    // Mark driver as dead
    registry.mark_driver_dead(driver_idx);

    // Notify supervisor
    let _ = signal(slots::SUPERVISOR_NOTIF);

    // Notify subscribed clients
    for sub in &registry.subscriptions {
        if sub.active && (sub.event_mask & ipc::event::DRIVER_DIED) != 0 {
            let _ = signal(sub.notification_slot);
        }
    }
}

// Panic handler is provided by m6-std
