//! Device tree blob (DTB) parsing and device enumeration.
//!
//! Uses the `fdt` crate to parse the device tree and extract device information.

use crate::registry::{DeviceEntry, DeviceState, Registry};

/// Devices we care about enumerating.
/// These compatible strings map to known drivers.
const INTERESTING_COMPATIBLES: &[&str] = &[
    // Serial
    "ns16550a",        // NS16550 UART (QEMU)
    "arm,pl011",       // ARM PL011 UART
    "snps,dw-apb-uart", // Synopsys DesignWare UART (RK3588)
    // VirtIO
    "virtio,mmio",     // VirtIO MMIO devices
    // Storage
    "nvme",            // NVMe controller
    // USB
    "generic-xhci",    // Generic xHCI USB controller
    "snps,dwc3",       // Synopsys DWC3 USB controller
    // PCIe
    "pci-host-generic", // Generic PCIe host
    "pci-host-ecam-generic", // PCIe ECAM
    // RK3588 specific
    "rockchip,rk3588-dwc3", // RK3588 USB
    "rockchip,rk3588-pcie", // RK3588 PCIe
    // IOMMU
    "arm,smmu-v3",     // ARM SMMUv3
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

    entry.state = DeviceState::Unbound;
    Some(entry)
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
