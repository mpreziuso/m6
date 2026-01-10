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
}

/// Static driver manifest.
///
/// Order matters - first match wins. More specific compatible strings
/// should come before generic ones.
pub static DRIVER_MANIFEST: &[DriverManifest] = &[
    // -- Serial drivers
    DriverManifest {
        compatible: "arm,pl011",
        binary_name: "drv-uart-pl011",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    DriverManifest {
        compatible: "ns16550a",
        binary_name: "drv-uart-ns16550",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    DriverManifest {
        compatible: "snps,dw-apb-uart",
        binary_name: "drv-uart-dw",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    // -- VirtIO drivers
    DriverManifest {
        compatible: "virtio,mmio",
        binary_name: "drv-virtio-mmio",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    // -- Storage drivers
    DriverManifest {
        compatible: "nvme",
        binary_name: "drv-nvme",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
    },
    // -- USB drivers
    DriverManifest {
        compatible: "generic-xhci",
        binary_name: "drv-usb-xhci",
        needs_irq: true,
        needs_iommu: true,
        is_platform: false,
    },
    DriverManifest {
        compatible: "snps,dwc3",
        binary_name: "drv-usb-dwc3",
        needs_irq: true,
        needs_iommu: true,
        is_platform: true,
    },
    DriverManifest {
        compatible: "rockchip,rk3588-dwc3",
        binary_name: "drv-usb-dwc3",
        needs_irq: true,
        needs_iommu: true,
        is_platform: true,
    },
    // -- PCIe drivers
    DriverManifest {
        compatible: "pci-host-generic",
        binary_name: "drv-pcie-ecam",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    DriverManifest {
        compatible: "pci-host-ecam-generic",
        binary_name: "drv-pcie-ecam",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
    DriverManifest {
        compatible: "rockchip,rk3588-pcie",
        binary_name: "drv-pcie-rk3588",
        needs_irq: true,
        needs_iommu: false,
        is_platform: true,
    },
];

/// Find driver manifest for a compatible string.
///
/// Returns the first matching manifest entry, or None if no driver is registered.
pub fn find_driver(compatible: &str) -> Option<&'static DriverManifest> {
    DRIVER_MANIFEST
        .iter()
        .find(|m| compatible.contains(m.compatible))
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
