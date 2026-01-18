//! DTB-based device region discovery
//!
//! Parses the Device Tree Blob to discover MMIO device regions that should
//! be provided to userspace as device untyped capabilities.

use fdt::Fdt;
use m6_common::PhysAddr;
use m6_common::boot::{DeviceRegion, DeviceType, MAX_DEVICE_REGIONS};

/// Result of parsing device regions from DTB.
pub struct DeviceRegionResult {
    /// Discovered device regions.
    pub regions: [DeviceRegion; MAX_DEVICE_REGIONS],
    /// Number of valid regions.
    pub count: usize,
}

impl DeviceRegionResult {
    /// Create an empty result.
    fn new() -> Self {
        Self {
            regions: [DeviceRegion::empty(); MAX_DEVICE_REGIONS],
            count: 0,
        }
    }

    /// Add a device region if there's space.
    fn add(&mut self, region: DeviceRegion) {
        if self.count < MAX_DEVICE_REGIONS {
            self.regions[self.count] = region;
            self.count += 1;
        }
    }
}

/// RAM region for overlap checking.
#[derive(Clone, Copy)]
pub struct RamRegion {
    pub start: u64,
    pub end: u64,
}

/// Collection of RAM regions.
pub struct RamRegionList {
    pub regions: [RamRegion; 64],
    pub count: usize,
}

impl Default for RamRegionList {
    fn default() -> Self {
        Self::new()
    }
}

impl RamRegionList {
    /// Create an empty list.
    pub fn new() -> Self {
        Self {
            regions: [RamRegion { start: 0, end: 0 }; 64],
            count: 0,
        }
    }

    /// Add a RAM region.
    pub fn add(&mut self, start: u64, end: u64) {
        if self.count < 64 {
            self.regions[self.count] = RamRegion { start, end };
            self.count += 1;
        }
    }

    /// Check if an address range overlaps with any RAM region.
    fn overlaps_ram(&self, start: u64, end: u64) -> bool {
        for i in 0..self.count {
            let ram = &self.regions[i];
            // Overlap exists if: start < ram.end AND end > ram.start
            if start < ram.end && end > ram.start {
                return true;
            }
        }
        false
    }
}

/// Parse device regions from a DTB slice.
///
/// # Arguments
/// * `dtb_slice` - Raw DTB data
/// * `ram_regions` - RAM regions from UEFI memory map (to skip overlapping regions)
///
/// # Returns
/// Device regions discovered from the DTB, or None if parsing fails.
pub fn parse_device_regions(
    dtb_slice: &[u8],
    ram_regions: &RamRegionList,
) -> Option<DeviceRegionResult> {
    let fdt = Fdt::new(dtb_slice).ok()?;
    let mut result = DeviceRegionResult::new();

    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible() {
            let compat_list: alloc::vec::Vec<&str> = compatible.all().collect();

            // Determine device type from compatible strings
            let device_type = classify_device(&compat_list);
            if device_type == DeviceType::Unknown {
                continue;
            }

            // Extract reg property
            if let Some(mut reg_iter) = node.reg() {
                // For most devices, take the first reg entry
                // For GIC, we might want distributor + redistributor, but that's handled specially
                if let Some(reg) = reg_iter.next() {
                    let phys_base = reg.starting_address as u64;
                    let raw_size = reg.size.unwrap_or(0x1000) as u64;

                    // Page-align: round down base, round up size
                    let aligned_base = phys_base & !0xFFF;
                    let base_offset = phys_base - aligned_base;
                    let aligned_size = ((raw_size + base_offset + 0xFFF) & !0xFFF).max(0x1000);

                    // Compute size_bits (ceil log2), minimum 12
                    let size_bits = compute_size_bits(aligned_size);

                    // Skip if overlaps RAM
                    let region_end = aligned_base + aligned_size;
                    if ram_regions.overlaps_ram(aligned_base, region_end) {
                        log::debug!(
                            "Skipping device region at {:#x} (overlaps RAM): {}",
                            aligned_base,
                            node.name
                        );
                        continue;
                    }

                    let region = DeviceRegion {
                        phys_base: PhysAddr::new(aligned_base),
                        size: aligned_size,
                        size_bits,
                        device_type,
                        _reserved: [0; 6],
                    };

                    log::debug!(
                        "Found device region: {} at {:#x}, size {:#x} (2^{}), type {:?}",
                        node.name,
                        aligned_base,
                        aligned_size,
                        size_bits,
                        device_type
                    );

                    result.add(region);

                    // For GIC, also add redistributor region if present
                    if device_type == DeviceType::Gic
                        && let Some(redist_reg) = reg_iter.next()
                    {
                        let redist_phys = redist_reg.starting_address as u64;
                        let redist_raw_size = redist_reg.size.unwrap_or(0x1000) as u64;

                        let redist_aligned_base = redist_phys & !0xFFF;
                        let redist_offset = redist_phys - redist_aligned_base;
                        let redist_aligned_size =
                            ((redist_raw_size + redist_offset + 0xFFF) & !0xFFF).max(0x1000);
                        let redist_size_bits = compute_size_bits(redist_aligned_size);

                        if !ram_regions.overlaps_ram(
                            redist_aligned_base,
                            redist_aligned_base + redist_aligned_size,
                        ) {
                            let redist_region = DeviceRegion {
                                phys_base: PhysAddr::new(redist_aligned_base),
                                size: redist_aligned_size,
                                size_bits: redist_size_bits,
                                device_type: DeviceType::Gic,
                                _reserved: [0; 6],
                            };

                            log::debug!(
                                "Found GIC redistributor region at {:#x}, size {:#x} (2^{})",
                                redist_aligned_base,
                                redist_aligned_size,
                                redist_size_bits
                            );

                            result.add(redist_region);
                        }
                    }
                }
            }
        }
    }

    log::info!("Discovered {} device regions from DTB", result.count);
    Some(result)
}

/// Classify a device based on its compatible strings.
fn classify_device(compat_list: &[&str]) -> DeviceType {
    for compat in compat_list {
        // UART
        if *compat == "arm,pl011" || *compat == "snps,dw-apb-uart" {
            return DeviceType::Uart;
        }

        // GIC
        if *compat == "arm,gic-v3" || *compat == "arm,gic-400" || *compat == "arm,cortex-a15-gic" {
            return DeviceType::Gic;
        }

        // SMMU
        if *compat == "arm,smmu-v3" {
            return DeviceType::Smmu;
        }

        // VirtIO MMIO
        if *compat == "virtio,mmio" {
            return DeviceType::VirtioMmio;
        }

        // PCIe (wildcard match)
        if compat.contains("pcie") || compat.contains("pci") {
            return DeviceType::Pcie;
        }

        // USB (wildcard match)
        if compat.contains("usb") || compat.contains("dwc3") || compat.contains("xhci") {
            return DeviceType::Usb;
        }
    }

    DeviceType::Unknown
}

/// Compute size_bits (ceil log2 of size), minimum 12 for 4KB pages.
fn compute_size_bits(size: u64) -> u8 {
    if size == 0 {
        return 12;
    }

    // Find the position of the highest set bit
    let highest_bit = 63 - size.leading_zeros();

    // If size is not a power of 2, we need to round up
    let size_bits = if size.is_power_of_two() {
        highest_bit as u8
    } else {
        (highest_bit + 1) as u8
    };

    // Minimum 12 for 4KB pages
    size_bits.max(12)
}

extern crate alloc;
