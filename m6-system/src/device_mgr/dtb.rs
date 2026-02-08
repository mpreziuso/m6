//! Device tree blob (DTB) parsing and device enumeration.
//!
//! Uses the `fdt` crate to parse the device tree and extract device information.

use crate::registry::{DeviceEntry, DeviceState, Registry};

// -- VirtIO MMIO constants for device type probing

/// VirtIO MMIO magic value ("virt" in little-endian)
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// VirtIO MMIO register offsets
mod virtio_regs {
    /// Magic value register (must be 0x74726976)
    pub const MAGIC: usize = 0x000;
    /// Device ID register (1=net, 2=blk, 3=console, etc.)
    pub const DEVICE_ID: usize = 0x008;
}

/// Known VirtIO device IDs
pub mod virtio_device_ids {
    /// Network device
    pub const NET: u32 = 1;
    /// Block device
    pub const BLK: u32 = 2;
    /// Console device
    pub const CONSOLE: u32 = 3;
    /// Entropy source
    pub const RNG: u32 = 4;
    /// GPU device
    pub const GPU: u32 = 16;
    /// Input device
    pub const INPUT: u32 = 18;
}

/// Devices we care about enumerating.
/// These compatible strings map to known drivers.
const INTERESTING_COMPATIBLES: &[&str] = &[
    // Serial
    "ns16550a",         // NS16550 UART (QEMU)
    "arm,pl011",        // ARM PL011 UART
    "snps,dw-apb-uart", // Synopsys DesignWare UART (RK3588)
    // VirtIO
    "virtio,mmio", // VirtIO MMIO devices
    // Storage
    "nvme", // NVMe controller
    // USB
    "generic-xhci", // Generic xHCI USB controller
    "snps,dwc3",    // Synopsys DWC3 USB controller
    // PCIe
    "pci-host-generic",      // Generic PCIe host
    "pci-host-ecam-generic", // PCIe ECAM
    // RK3588 specific
    "rockchip,rk3588-dwc3", // RK3588 USB
    "rockchip,rk3588-pcie", // RK3588 PCIe
    // IOMMU
    "arm,smmu-v3", // ARM SMMUv3
];

/// Enumerate devices from the FDT and populate the registry.
///
/// # Arguments
/// * `fdt_data` - Raw FDT bytes (mapped from DTB Frame cap)
/// * `registry` - Registry to populate
///
/// # Returns
/// Number of devices enumerated, or error message
pub fn enumerate_devices(fdt_data: &[u8], registry: &mut Registry) -> Result<usize, &'static str> {
    let fdt = fdt::Fdt::new(fdt_data).map_err(|_| "Invalid FDT")?;

    let mut count = 0;

    // Walk all nodes in the FDT
    for node in fdt.all_nodes() {
        // Check if this node has an interesting compatible string
        if let Some(compatible) = node.compatible() {
            for compat_str in compatible.all() {
                if is_interesting_device(compat_str)
                    && let Some(entry) = parse_device_node(&node, compat_str)
                    && registry.add_device(entry).is_some()
                {
                    count += 1;
                    break;
                }
            }
        }
    }

    Ok(count)
}

/// Check if a compatible string matches a device we care about.
fn is_interesting_device(compat: &str) -> bool {
    INTERESTING_COMPATIBLES.iter().any(|c| compat.contains(c))
}

/// Parse a device node and create a DeviceEntry.
fn parse_device_node(node: &fdt::node::FdtNode, compat: &str) -> Option<DeviceEntry> {
    let mut entry = DeviceEntry::empty();

    // Get full node name as path
    entry.set_path(node.name);

    // Set compatible string
    entry.set_compatible(compat);

    // Extract reg property (physical address and size)
    if let Some(mut reg) = node.reg()
        && let Some(first_region) = reg.next()
    {
        entry.phys_base = first_region.starting_address as u64;
        entry.size = first_region.size.unwrap_or(0) as u64;
    }

    // Extract interrupts property
    // GIC interrupt encoding varies, but commonly:
    // - 3 cells: type (SPI=0, PPI=1), number, flags
    // - We extract the interrupt number (second cell for SPI)
    if let Some(interrupts) = node.property("interrupts") {
        let value = interrupts.value;
        // Minimum 12 bytes for 3 u32 cells
        if value.len() >= 12 {
            // Read as big-endian u32s
            let irq_type = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            let irq_num = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);

            // SPI interrupts start at 32 in GIC numbering
            entry.irq = if irq_type == 0 {
                irq_num + 32 // SPI offset
            } else {
                irq_num + 16 // PPI offset
            };
        } else if value.len() >= 4 {
            // Simple single-cell interrupt number
            entry.irq = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        }
    }

    // Platform devices don't have PCIe BDF
    entry.pcie_bdf = None;

    // For snps,dwc3, if interrupts property was not found on this node,
    // fall back to hardcoded IRQ numbers based on base address.
    // RK3588 USB3 OTG controllers use SPI interrupts 220-222.
    if compat.contains("snps,dwc3") && entry.irq == 0 {
        // RK3588 USB3 OTG IRQ numbers (SPI + 32 = GIC IRQ)
        entry.irq = match entry.phys_base {
            0xFC00_0000 => 220 + 32, // USB3OTG_0: SPI 220
            0xFC40_0000 => 221 + 32, // USB3OTG_1: SPI 221
            0xFCD0_0000 => 222 + 32, // USB3OTG_2: SPI 222
            _ => 0,
        };
    }

    // Parse stream ID and SMMU phandle for devices with iommus property
    // The iommus property format is: [phandle, stream_id]
    // For RK3588 USB controllers, this indicates which SMMU stream ID to use
    if compat.contains("snps,dwc3") {
        // First try parsing from DTB, fall back to hardcoded IDs based on base address
        let fallback_id = match entry.phys_base {
            0xFC00_0000 => 0x10, // USB3OTG_0
            0xFC40_0000 => 0x11, // USB3OTG_1
            0xFCD0_0000 => 0x12, // USB3OTG_2
            _ => 0,
        };

        // Hardcoded PHP SMMU phandle for RK3588 (from linux-kernel DTS: mmu600_php)
        // This is SMMU #1 at 0xfcb00000
        let fallback_phandle = 0x191u32;

        // Try to parse iommus property to get SMMU phandle and stream ID
        if let Some((smmu_phandle, stream_id)) = parse_iommus_info(node) {
            entry.stream_id = stream_id;
            entry.smmu_phandle = smmu_phandle;
        } else {
            // Use hardcoded fallback for RK3588 USB
            entry.stream_id = fallback_id;
            entry.smmu_phandle = if entry.phys_base >= 0xFC00_0000
                && entry.phys_base < 0xFCE0_0000
            {
                fallback_phandle
            } else {
                0
            };
        }
    } else if let Some((smmu_phandle, stream_id)) = parse_iommus_info(node) {
        // Other devices with iommus property
        entry.stream_id = stream_id;
        entry.smmu_phandle = smmu_phandle;
    } else {
        entry.stream_id = 0;
        entry.smmu_phandle = 0;
    }

    entry.state = DeviceState::Unbound;
    Some(entry)
}

/// Parse stream ID and SMMU phandle from the iommus property.
///
/// The iommus property is formatted as: [phandle (4 bytes), stream_id (4 bytes)]
/// Returns (smmu_phandle, stream_id) if present, or None if the property is missing or malformed.
fn parse_iommus_info(node: &fdt::node::FdtNode) -> Option<(u32, u32)> {
    let iommus = node.property("iommus")?;
    let data = iommus.value;

    // Need at least 8 bytes (phandle + stream_id)
    if data.len() < 8 {
        return None;
    }

    // Extract SMMU phandle (first u32, bytes 0-3)
    let smmu_phandle = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Extract stream ID (second u32, bytes 4-7)
    let stream_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    Some((smmu_phandle, stream_id))
}

/// Parse stream ID from the iommus property (discarding phandle).
///
/// Returns just the stream ID for backward compatibility.
fn parse_iommus_stream_id(node: &fdt::node::FdtNode) -> Option<u32> {
    parse_iommus_info(node).map(|(_, stream_id)| stream_id)
}

/// Get the platform name from DTB root node.
pub fn get_platform_name(fdt_data: &[u8]) -> Option<&str> {
    let fdt = fdt::Fdt::new(fdt_data).ok()?;
    let root = fdt.root();
    let model = root.model();
    if !model.is_empty() {
        return Some(model);
    }
    // Fallback to compatible string
    root.compatible().all().next()
}

/// Get memory information from DTB.
pub fn get_memory_info(fdt_data: &[u8]) -> Option<(u64, u64)> {
    let fdt = fdt::Fdt::new(fdt_data).ok()?;

    for node in fdt.all_nodes() {
        if node.name.starts_with("memory")
            && let Some(mut reg) = node.reg()
            && let Some(region) = reg.next()
        {
            return Some((
                region.starting_address as u64,
                region.size.unwrap_or(0) as u64,
            ));
        }
    }
    None
}

/// Check if a compatible string indicates a VirtIO MMIO device.
pub fn is_virtio_mmio(compatible: &str) -> bool {
    compatible.contains("virtio,mmio")
}

/// Probe a VirtIO MMIO device to determine its device type.
///
/// This reads the DeviceID register from a mapped VirtIO MMIO region.
///
/// # Arguments
/// * `mmio_base` - Virtual address where the VirtIO MMIO region is mapped
///
/// # Returns
/// The VirtIO device ID (1=net, 2=blk, 3=console, etc.) or 0 if invalid/not present.
///
/// # Safety
/// The caller must ensure `mmio_base` points to a valid, mapped VirtIO MMIO region.
pub unsafe fn probe_virtio_device_type(mmio_base: *const u8) -> u32 {
    // SAFETY: Caller guarantees mmio_base is valid and mapped.
    // All operations within this function are valid because of this precondition.
    unsafe {
        // Read magic value to verify this is a valid VirtIO device
        let magic_ptr = mmio_base.add(virtio_regs::MAGIC) as *const u32;
        let magic = core::ptr::read_volatile(magic_ptr);

        if magic != VIRTIO_MMIO_MAGIC {
            return 0; // Not a valid VirtIO device
        }

        // Read device ID
        let device_id_ptr = mmio_base.add(virtio_regs::DEVICE_ID) as *const u32;
        core::ptr::read_volatile(device_id_ptr)
    }
}

/// Get a human-readable name for a VirtIO device ID.
pub fn virtio_device_name(device_id: u32) -> &'static str {
    match device_id {
        0 => "reserved",
        virtio_device_ids::NET => "network",
        virtio_device_ids::BLK => "block",
        virtio_device_ids::CONSOLE => "console",
        virtio_device_ids::RNG => "entropy",
        virtio_device_ids::GPU => "gpu",
        virtio_device_ids::INPUT => "input",
        _ => "unknown",
    }
}

/// Resolve a phandle value to its corresponding device node.
///
/// This walks all nodes in the FDT to find the node with the matching phandle property.
/// Returns the node if found, or None if no node has the specified phandle.
fn resolve_phandle<'a>(fdt: &'a fdt::Fdt, phandle: u32) -> Option<fdt::node::FdtNode<'a, 'a>> {
    for node in fdt.all_nodes() {
        if let Some(prop) = node.property("phandle") {
            let value = prop.value;
            if value.len() >= 4 {
                let node_phandle = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                if node_phandle == phandle {
                    return Some(node);
                }
            }
        }
    }
    None
}

/// Parse additional MMIO frames needed by USB DWC3 driver from DTB.
///
/// Looks for phandle references to GRF, CRU, and PHY nodes in the USB device node.
/// Returns a vector of (physical_address, size, name) tuples.
///
/// This function attempts to dynamically discover register regions from the device tree
/// rather than relying on hardcoded addresses. Falls back to static addresses if
/// DTB parsing fails or references are missing.
pub fn parse_usb_additional_frames(
    fdt: &fdt::Fdt,
    usb_node: &fdt::node::FdtNode,
) -> alloc::vec::Vec<(u64, usize, &'static str)> {
    use alloc::vec::Vec;

    let mut frames = Vec::new();

    // Parse GRF reference (rockchip,grf property)
    if let Some(grf_prop) = usb_node.property("rockchip,grf") {
        let data = grf_prop.value;
        if data.len() >= 4 {
            let phandle = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if let Some(grf_node) = resolve_phandle(fdt, phandle)
                && let Some(mut reg) = grf_node.reg()
                && let Some(region) = reg.next()
            {
                frames.push((
                    region.starting_address as u64,
                    region.size.unwrap_or(0x1000),
                    "GRF",
                ));
            }
        }
    }

    // Parse PHY references (phys property with multiple phandles)
    if let Some(phys_prop) = usb_node.property("phys") {
        let data = phys_prop.value;
        // Each phandle is 4 bytes
        for chunk in data.chunks_exact(4) {
            let phandle = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if let Some(phy_node) = resolve_phandle(fdt, phandle)
                && let Some(mut reg) = phy_node.reg()
                && let Some(region) = reg.next()
            {
                frames.push((
                    region.starting_address as u64,
                    region.size.unwrap_or(0x4000),
                    "PHY",
                ));
            }
        }
    }

    // Note: CRU (clock) reference parsing via "clocks" property is more complex
    // and requires understanding the clock binding. For now, fall back to static CRU address.

    frames
}
