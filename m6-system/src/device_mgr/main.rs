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

use m6_syscall::invoke::{call, ipc_set_send_caps, recv, reply_recv, sched_yield, signal};
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
    io::puts("[device-mgr] Starting\n");

    // Store boot info pointer
    BOOT_INFO.store(boot_info_addr as *mut DevMgrBootInfo, core::sync::atomic::Ordering::Relaxed);

    // Validate boot info
    // SAFETY: The pointer was just stored from init's valid boot_info_addr.
    let boot_info = unsafe { get_boot_info() };
    if !boot_info.is_valid() {
        io::puts("[device-mgr] ERROR: Invalid boot info!\n");
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
            io::puts("[device-mgr] ERROR: Failed to parse DTB: ");
            io::puts(e);
            io::newline();
        }
    }

    // Spawn platform drivers proactively
    spawn_platform_drivers(&mut registry);

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
            Some((config_vaddr, config_slot, _pt_slots, mapped_size)) => {
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

                // Unmap config space
                // Note: We keep individual device frames for later driver spawning
                if let Err(e) = unmap_frame(cptr(config_slot)) {
                    io::puts("[device-mgr] WARN: unmap config frame failed: ");
                    io::puts(e.name());
                    io::puts("\n");
                }
            }
            None => {
                io::puts("[device-mgr] PCIe: failed to map config space\n");
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
    use m6_syscall::invoke::{map_frame, retype, unmap_frame};

    // Find device untyped covering this address
    let (device_untyped_slot, _untyped_size, untyped_base) =
        boot_info.find_device_untyped(apbdbg_base)?;

    // Allocate slot for the frame
    let frame_slot = registry.alloc_slot();

    // Calculate offset within the untyped region (in pages)
    let aligned_base = apbdbg_base & !0xFFF;
    if aligned_base < untyped_base {
        return None;
    }
    let offset_in_untyped = aligned_base - untyped_base;
    let offset_in_pages = offset_in_untyped >> 12;

    // Retype to 4KB DeviceFrame
    // For DeviceFrame, the 6th argument is the offset within the device untyped (in pages)
    if retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        frame_slot,
        offset_in_pages,
    )
    .is_err()
    {
        return None;
    }

    // Calculate offset within the page for accessing registers
    let offset_within_page = (apbdbg_base & 0xFFF) as usize;

    // Map to a temporary virtual address
    const APBDBG_VADDR: u64 = 0x0000_B000_0000; // Temporary mapping address

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

    // Check link status
    // SAFETY: We just mapped the APBDBG region
    let link_up = unsafe {
        pcie::check_rk3588_link_status((APBDBG_VADDR + offset_within_page as u64) as usize)
    };

    // Unmap
    if let Err(e) = unmap_frame(cptr(frame_slot)) {
        io::puts("[device-mgr] WARN: unmap APBDBG frame failed: ");
        io::puts(e.name());
        io::puts("\n");
    }

    Some(link_up)
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
    let (device_untyped_slot, untyped_size, _untyped_base) =
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
    if retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        frame_size_bits as u64,
        cptr(slots::ROOT_CNODE),
        frame_slot,
        1,
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

/// Add a PCIe device to the registry.
fn add_pcie_device_to_registry(
    registry: &mut Registry,
    _host: &pcie::PcieHostBridge,
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
        io::puts("[device-mgr] PCIe: registry full, cannot add device\n");
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
                io::puts("[device-mgr] WARN: VirtIO devices in DTB but no device untyped\n");
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
        io::puts("[device-mgr] ERROR: VirtIO probe L1 retype failed\n");
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
        io::puts("[device-mgr] ERROR: VirtIO probe L2 retype failed\n");
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
        io::puts("[device-mgr] ERROR: VirtIO probe L3 retype failed\n");
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
        io::puts("[device-mgr] ERROR: VirtIO probe device retype failed\n");
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
    for &slot in &frame_slots {
        if let Err(e) = unmap_frame(cptr(slot)) {
            io::puts("[device-mgr] WARN: unmap VirtIO frame failed: ");
            io::puts(e.name());
            io::puts("\n");
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

                // Handle the request and store response for next reply_recv
                last_response = handle_request(registry, sender_badge, label, msg);
            }
            Err(_) => {
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
        _ => {
            io::puts("[device-mgr] Unknown class ID: ");
            io::put_hex(class_id);
            io::newline();
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
        io::puts("[device-mgr] No USB host driver available for HID\n");
        return ipc::response::ERR_NO_DRIVER;
    }
    let usb_host_ep_slot = usb_host_endpoint.unwrap();

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

            ipc::response::OK
        }
        Err(e) => {
            io::puts("[device-mgr] Failed to spawn HID driver: ");
            io::puts(e);
            io::newline();
            ipc::response::ERR_SPAWN_FAILED
        }
    }
}

/// Find a running USB host driver (xHCI or DWC3) that has connected devices.
///
/// On platforms with multiple USB controllers (e.g. RK3588 with three DWC3),
/// the keyboard may be on any of them. We query each running USB host via
/// LIST_DEVICES IPC and return the first one that reports connected devices.
/// Falls back to the first running USB host if none report devices yet.
fn find_usb_host_driver(registry: &Registry) -> Option<u64> {
    // SAFETY: _start has initialised BOOT_INFO
    let boot_info = unsafe { get_boot_info() };
    let cptr = |slot: u64| slot_to_cptr(slot, boot_info.cnode_radix);

    // USB host IPC label for LIST_DEVICES
    const LIST_DEVICES: u64 = 0x0020;

    let mut fallback_slot: Option<u64> = None;

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

        let ep_slot = registry.drivers[driver_idx].endpoint_slot;

        // Remember the first USB host as fallback
        if fallback_slot.is_none() {
            fallback_slot = Some(ep_slot);
        }

        // Query this USB host for connected device count
        if let Ok(result) = call(cptr(ep_slot), LIST_DEVICES, 0, 0, 0) {
            let device_count = (result.label >> 16) & 0xFFFF;
            if device_count > 0 {
                return Some(ep_slot);
            }
        }
    }

    fallback_slot
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
            io::puts("[device-mgr] No driver for: ");
            io::puts(compat);
            io::newline();
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    // Find driver binary in initrd
    let initrd = match get_initrd() {
        Some(data) => data,
        None => {
            io::puts("[device-mgr] No initrd available\n");
            return ipc::response::ERR_NO_DRIVER;
        }
    };
    let archive = match tar_no_std::TarArchiveRef::new(initrd) {
        Ok(a) => a,
        Err(_) => {
            io::puts("[device-mgr] Failed to parse initrd TAR\n");
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    let elf_data = match archive
        .entries()
        .find(|e| e.filename().as_str() == Ok(manifest_entry.binary_name))
    {
        Some(entry) => entry.data(),
        None => {
            io::puts("[device-mgr] Driver binary not found: ");
            io::puts(manifest_entry.binary_name);
            io::newline();
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

            io::puts("[device-mgr] Spawned driver for: ");
            io::puts(compat);
            io::newline();

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

            io::puts("[device-mgr] Failed to spawn driver: ");
            match e {
                spawn::SpawnError::InvalidElf(_) => io::puts("invalid ELF"),
                spawn::SpawnError::OutOfMemory => io::puts("out of memory"),
                spawn::SpawnError::RetypeFailed(err) => {
                    io::puts("retype failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::AsidAssignFailed(err) => {
                    io::puts("ASID assign failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::TcbConfigureFailed(err) => {
                    io::puts("TCB config failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::TcbWriteRegistersFailed(err) => {
                    io::puts("TCB write regs failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::TcbResumeFailed(err) => {
                    io::puts("TCB resume failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::FrameMapFailed(err) => {
                    io::puts("frame map failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::CapCopyFailed(err) => {
                    io::puts("cap copy failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::IrqClaimFailed(err) => {
                    io::puts("IRQ claim failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::NoSlots => io::puts("no slots"),
                spawn::SpawnError::DriverNotFound => io::puts("driver not found"),
                spawn::SpawnError::TooManyDrivers => io::puts("too many drivers"),
                spawn::SpawnError::DeviceUntypedNotFound => io::puts("device untyped not found"),
                spawn::SpawnError::IommuRequired => io::puts("IOMMU required but not available"),
                spawn::SpawnError::MsiAllocateFailed(err) => {
                    io::puts("MSI allocate failed: ");
                    io::puts(err.name());
                }
                spawn::SpawnError::MsixSetupFailed => io::puts("MSI-X setup failed"),
                spawn::SpawnError::InvalidDeviceConfig => {
                    io::puts("invalid device config (no MMIO address)")
                }
                spawn::SpawnError::IOSpaceOpFailed(err) => {
                    io::puts("IOSpace operation failed: ");
                    io::puts(err.name());
                }
            }
            io::newline();

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

    io::puts("[device-mgr] Driver died: index ");
    io::put_u64(driver_idx as u64);
    io::newline();

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
