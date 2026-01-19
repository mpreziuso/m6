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

    /// Add a device region, deduplicating by base address.
    ///
    /// If a region with the same base address already exists, the new region
    /// is merged (taking the larger size). This handles cases like VirtIO MMIO
    /// devices that share the same page after alignment.
    fn add(&mut self, region: DeviceRegion) {
        let new_base = region.phys_base.as_u64();

        // Check for existing region with same base address
        for i in 0..self.count {
            if self.regions[i].phys_base.as_u64() == new_base {
                // Merge: take the larger size
                if region.size > self.regions[i].size {
                    self.regions[i].size = region.size;
                    self.regions[i].size_bits = region.size_bits;
                }
                // Keep original device_type (first one wins)
                return;
            }
        }

        // No duplicate found, add new region
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
                // For PCIe controllers, create device untypeds for ALL reg entries
                // RK3588 has multiple regions: APBDBG, DBI, Config space
                if device_type == DeviceType::Pcie {
                    for reg in reg_iter {
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
                                "Skipping PCIe reg at {:#x} (overlaps RAM): {}",
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
                            "Found PCIe reg: {} at {:#x}, size {:#x} (2^{})",
                            node.name,
                            aligned_base,
                            aligned_size,
                            size_bits
                        );

                        result.add(region);
                    }

                    // Also add memory windows from ranges property
                    // These are where device BARs are mapped
                    if let Some(ranges_prop) = node.property("ranges") {
                        parse_pcie_ranges(ranges_prop.value, ram_regions, &mut result);
                    }
                } else if let Some(reg) = reg_iter.next() {
                    // For other devices, take the first reg entry
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

/// Parse PCIe ranges property to extract memory windows as device regions.
///
/// The ranges property format is:
/// `<pci_hi pci_mid pci_lo cpu_hi cpu_lo size_hi size_lo>`
///
/// pci_hi bits:
/// - bits 25:24 = Space type (0=config, 1=IO, 2=mem32, 3=mem64)
/// - bit 30 = Prefetchable
fn parse_pcie_ranges(data: &[u8], ram_regions: &RamRegionList, result: &mut DeviceRegionResult) {
    // Each entry is 28 bytes (7 × 4-byte cells)
    let entry_size = 28;
    if data.len() < entry_size {
        return;
    }

    let read_u32 = |offset: usize| -> u32 {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    };

    let mut offset = 0;
    while offset + entry_size <= data.len() {
        let pci_hi = read_u32(offset);
        let _pci_mid = read_u32(offset + 4);
        let _pci_lo = read_u32(offset + 8);
        let cpu_hi = read_u32(offset + 12);
        let cpu_lo = read_u32(offset + 16);
        let size_hi = read_u32(offset + 20);
        let size_lo = read_u32(offset + 24);

        offset += entry_size;

        // Extract space type from pci_hi bits [25:24]
        let space_type = (pci_hi >> 24) & 0x03;

        // Only create device regions for memory windows (32-bit or 64-bit)
        if space_type != 0x02 && space_type != 0x03 {
            continue;
        }

        let cpu_addr = ((cpu_hi as u64) << 32) | (cpu_lo as u64);
        let size = ((size_hi as u64) << 32) | (size_lo as u64);

        // Skip very small or very large regions
        if !(0x1000..=(1 << 40)).contains(&size) {
            continue;
        }

        // Skip if overlaps RAM
        if ram_regions.overlaps_ram(cpu_addr, cpu_addr + size) {
            log::debug!(
                "Skipping PCIe memory window at {:#x} (overlaps RAM)",
                cpu_addr
            );
            continue;
        }

        // Create device region for this memory window
        // For large windows, we cap the size_bits to something reasonable
        // The kernel will handle sub-allocation from large untypeds
        let size_bits = compute_size_bits(size).min(40); // Cap at 1TB

        let region = DeviceRegion {
            phys_base: PhysAddr::new(cpu_addr),
            size,
            size_bits,
            device_type: DeviceType::Pcie,
            _reserved: [0; 6],
        };

        log::debug!(
            "Found PCIe memory window at {:#x}, size {:#x} (2^{})",
            cpu_addr,
            size,
            size_bits
        );

        result.add(region);
    }
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
