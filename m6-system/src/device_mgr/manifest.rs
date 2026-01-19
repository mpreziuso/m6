//! Driver manifest for matching compatible strings to driver binaries.
//!
//! The manifest is a static table compiled into device-mgr.
//! It maps device compatible strings to driver binary names in the initrd.

/// Driver manifest entry
#[derive(Clone, Copy)]
pub struct DriverManifest {
    /// Compatible string prefix to match
    pub compatible: &'static str,
    /// Binary name in initrd TAR
    pub binary_name: &'static str,
    /// Whether driver needs IRQ capability
    pub needs_irq: bool,
    /// Whether driver needs IOMMU/IOSpace capability
    pub needs_iommu: bool,
    /// Whether this is a platform device (vs PCIe)
    pub is_platform: bool,
    /// VirtIO device ID filter (0 = match any/non-virtio device)
    /// Only relevant for virtio,mmio compatible devices.
    pub virtio_device_id: u32,
}

/// Static driver manifest.
///
/// Order matters - first match wins. More specific compatible strings
/// should come before generic ones.
pub static DRIVER_MANIFEST: &[DriverManifest] = &[
    // -- IOMMU drivers (high priority - must be running before DMA devices)
    DriverManifest {
        compatible: "arm,smmu-v3",
        binary_name: "drv-smmu",
        needs_irq: true,    // Event queue interrupt
        needs_iommu: false, // SMMU doesn't use itself
        is_platform: true,
        virtio_device_id: 0,
    },
    // -- Serial drivers
    DriverManifest {
        compatible: "arm,pl011",
        binary_name: "drv-uart-pl011",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "ns16550a",
        binary_name: "drv-uart-ns16550",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "snps,dw-apb-uart",
        binary_name: "drv-uart-dw",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
    // -- VirtIO drivers (type-specific entries first, then generic fallback)
    DriverManifest {
        compatible: "virtio,mmio",
        binary_name: "drv-virtio-blk",
        needs_irq: true,
        needs_iommu: true, // Block devices perform DMA
        is_platform: true,
        virtio_device_id: 2, // VirtIO block device
    },
    // Generic VirtIO fallback for unhandled device types
    DriverManifest {
        compatible: "virtio,mmio",
        binary_name: "drv-virtio-mmio",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0, // Match any (fallback)
    },
    // -- Storage drivers (PCIe class code matching)
    // NVMe: class=01 (storage), subclass=08 (NVMe), prog_if=02 (NVMe)
    DriverManifest {
        compatible: "pcie:010802",
        binary_name: "drv-nvme",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
        virtio_device_id: 0,
    },
    // Platform NVMe (DTB-enumerated)
    DriverManifest {
        compatible: "nvme",
        binary_name: "drv-nvme",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
        virtio_device_id: 0,
    },
    // SATA AHCI: class=01 (storage), subclass=06 (SATA), prog_if=01 (AHCI)
    DriverManifest {
        compatible: "pcie:010601",
        binary_name: "drv-ahci",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
        virtio_device_id: 0,
    },
    // -- USB drivers (PCIe class code matching)
    // xHCI: class=0c (serial bus), subclass=03 (USB), prog_if=30 (xHCI)
    DriverManifest {
        compatible: "pcie:0c0330",
        binary_name: "drv-usb-xhci",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
        virtio_device_id: 0,
    },
    // Platform xHCI (DTB-enumerated)
    DriverManifest {
        compatible: "generic-xhci",
        binary_name: "drv-usb-xhci",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "snps,dwc3",
        binary_name: "drv-usb-dwc3",
        needs_irq: true,
        needs_iommu: true,
        is_platform: true,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "rockchip,rk3588-dwc3",
        binary_name: "drv-usb-dwc3",
        needs_irq: true,
        needs_iommu: true,
        is_platform: true,
        virtio_device_id: 0,
    },
    // -- PCIe drivers
    DriverManifest {
        compatible: "pci-host-generic",
        binary_name: "drv-pcie-ecam",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "pci-host-ecam-generic",
        binary_name: "drv-pcie-ecam",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
    DriverManifest {
        compatible: "rockchip,rk3588-pcie",
        binary_name: "drv-pcie-rk3588",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
        virtio_device_id: 0,
    },
];

/// Find driver manifest for a compatible string.
///
/// Returns the first matching manifest entry, or None if no driver is registered.
/// For non-virtio devices, pass `virtio_device_id = 0`.
pub fn find_driver(compatible: &str, virtio_device_id: u32) -> Option<&'static DriverManifest> {
    DRIVER_MANIFEST.iter().find(|m| {
        if !compatible.contains(m.compatible) {
            return false;
        }
        // For virtio devices, match specific device ID or fallback (0)
        if m.virtio_device_id != 0 {
            m.virtio_device_id == virtio_device_id
        } else {
            // virtio_device_id == 0 means "match any" (fallback)
            true
        }
    })
}

/// Find all drivers matching a compatible string.
pub fn find_all_drivers(compatible: &str) -> impl Iterator<Item = &'static DriverManifest> {
    DRIVER_MANIFEST
        .iter()
        .filter(move |m| compatible.contains(m.compatible))
}

/// Check if a driver binary exists in the manifest.
pub fn has_driver(binary_name: &str) -> bool {
    DRIVER_MANIFEST.iter().any(|m| m.binary_name == binary_name)
}
