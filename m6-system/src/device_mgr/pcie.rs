//! PCIe device enumeration support.
//!
//! This module handles:
//! - Parsing PCIe host bridge information from DTB
//! - Scanning config space to discover PCIe devices
//! - Translating BAR addresses from PCI to CPU address space
//!
//! Supported host bridge types:
//! - ECAM (Enhanced Configuration Access Mechanism) - QEMU virt
//! - DesignWare Core (DWC) - RK3588

use crate::io;

// -- PCIe config space register offsets (Type 0 header)

/// Vendor ID (16-bit) at offset 0x00
const CFG_VENDOR_ID: u16 = 0x00;
/// Device ID (16-bit) at offset 0x02
const CFG_DEVICE_ID: u16 = 0x02;
/// Command register (16-bit) at offset 0x04
const CFG_COMMAND: u16 = 0x04;
/// Revision ID (8-bit) at offset 0x08
const CFG_REVISION: u16 = 0x08;
/// Class code (24-bit) at offset 0x09
const CFG_CLASS_CODE: u16 = 0x09;
/// Header type (8-bit) at offset 0x0E
const CFG_HEADER_TYPE: u16 = 0x0E;
/// BAR0 at offset 0x10
const CFG_BAR0: u16 = 0x10;

/// Invalid vendor ID (device not present)
const VENDOR_ID_INVALID: u16 = 0xFFFF;

/// Header type mask for multi-function bit
const HEADER_MULTIFUNCTION: u8 = 0x80;
/// Header type mask for type field
const HEADER_TYPE_MASK: u8 = 0x7F;
/// Type 0: endpoint
const HEADER_TYPE_ENDPOINT: u8 = 0x00;
/// Type 1: bridge
const HEADER_TYPE_BRIDGE: u8 = 0x01;

/// Maximum devices to enumerate
pub const MAX_PCIE_DEVICES: usize = 32;
/// Maximum host bridges to support
pub const MAX_PCIE_HOSTS: usize = 4;

// -- PCIe capability register offsets

/// Capabilities pointer at offset 0x34 (Type 0 header)
const CFG_CAP_PTR: u16 = 0x34;
/// Status register at offset 0x06 (bit 4 = capabilities list exists)
const CFG_STATUS: u16 = 0x06;
/// Status bit indicating capabilities list is present
const STATUS_CAP_LIST: u16 = 1 << 4;

// -- PCIe capability IDs

/// MSI-X capability ID
const CAP_ID_MSIX: u8 = 0x11;
/// MSI capability ID (legacy, less preferred)
#[allow(dead_code)]
const CAP_ID_MSI: u8 = 0x05;

// -- RK3588 DesignWare Core registers

/// PCIE_CLIENT_LTSSM_STATUS register offset (in APBDBG region)
const RK3588_LTSSM_STATUS: usize = 0x150;
/// RDLH_LINK_UP bit in LTSSM status
const RK3588_RDLH_LINK_UP: u32 = 1 << 17;
/// SMLH_LINK_UP bit in LTSSM status
const RK3588_SMLH_LINK_UP: u32 = 1 << 16;

/// PCIe host bridge type (determines config space access method)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieHostType {
    /// Standard ECAM (QEMU virt, generic)
    Ecam,
    /// DesignWare Core (RK3588)
    DesignWareDwc,
}

/// PCIe host bridge information parsed from DTB
#[derive(Debug, Clone)]
pub struct PcieHostBridge {
    /// Host controller type
    pub host_type: PcieHostType,
    /// Config space base physical address
    pub config_base: u64,
    /// Config space size
    pub config_size: u64,
    /// DBI registers base (RK3588 only, 0 for ECAM)
    pub dbi_base: u64,
    /// APBDBG/client registers base (RK3588 only, for link status check)
    pub apbdbg_base: u64,
    /// Valid bus number range (start, end)
    pub bus_range: (u8, u8),
    /// CPU address for PCIe memory window (from ranges)
    pub mem_window_cpu: u64,
    /// PCI address for PCIe memory window
    pub mem_window_pci: u64,
    /// Size of PCIe memory window
    pub mem_window_size: u64,
    /// Whether link is trained (for DWC, always true for ECAM)
    pub link_up: bool,
}

impl PcieHostBridge {
    /// Create an empty host bridge entry.
    pub const fn empty() -> Self {
        Self {
            host_type: PcieHostType::Ecam,
            config_base: 0,
            config_size: 0,
            dbi_base: 0,
            apbdbg_base: 0,
            bus_range: (0, 0),
            mem_window_cpu: 0,
            mem_window_pci: 0,
            mem_window_size: 0,
            link_up: false,
        }
    }
}

/// MSI-X capability information discovered from PCIe config space
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixInfo {
    /// Whether MSI-X capability was found
    pub present: bool,
    /// Number of MSI-X vectors available (table size)
    pub table_size: u16,
    /// BAR index containing MSI-X table (0-5)
    pub table_bir: u8,
    /// Offset of MSI-X table within the BAR
    pub table_offset: u32,
    /// BAR index containing PBA (Pending Bit Array)
    pub pba_bir: u8,
    /// Offset of PBA within the BAR
    pub pba_offset: u32,
    /// Config space offset of MSI-X capability (for enabling)
    pub cap_offset: u8,
}

impl MsixInfo {
    /// Create an empty MSI-X info (no capability present).
    pub const fn empty() -> Self {
        Self {
            present: false,
            table_size: 0,
            table_bir: 0,
            table_offset: 0,
            pba_bir: 0,
            pba_offset: 0,
            cap_offset: 0,
        }
    }
}

/// PCIe device information discovered during enumeration
#[derive(Debug, Clone, Copy)]
pub struct PcieDevice {
    /// Bus/Device/Function address
    pub bdf: (u8, u8, u8),
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Class code (class << 16 | subclass << 8 | prog_if)
    pub class_code: u32,
    /// BAR0 translated to CPU address
    pub bar0_cpu_addr: u64,
    /// BAR0 size (determined by BAR sizing)
    pub bar0_size: u64,
    /// Stream ID for IOMMU (from iommu-map property)
    pub stream_id: u32,
    /// MSI-X capability information
    pub msix: MsixInfo,
}

impl PcieDevice {
    /// Create an empty device entry.
    pub const fn empty() -> Self {
        Self {
            bdf: (0, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            bar0_cpu_addr: 0,
            bar0_size: 0,
            stream_id: 0,
            msix: MsixInfo::empty(),
        }
    }

    /// Check if this device entry is valid (vendor_id != 0).
    pub const fn is_valid(&self) -> bool {
        self.vendor_id != 0
    }

    /// Format class code as "CCSSPP" string (class, subclass, prog_if).
    pub fn format_class_code(&self) -> [u8; 6] {
        let class = ((self.class_code >> 16) & 0xFF) as u8;
        let subclass = ((self.class_code >> 8) & 0xFF) as u8;
        let prog_if = (self.class_code & 0xFF) as u8;

        fn nibble_to_hex(n: u8) -> u8 {
            if n < 10 { b'0' + n } else { b'a' + n - 10 }
        }

        [
            nibble_to_hex(class >> 4),
            nibble_to_hex(class & 0xF),
            nibble_to_hex(subclass >> 4),
            nibble_to_hex(subclass & 0xF),
            nibble_to_hex(prog_if >> 4),
            nibble_to_hex(prog_if & 0xF),
        ]
    }
}

/// Calculate ECAM address for a config register.
///
/// ECAM addressing: base + (rel_bus << 20) | (dev << 15) | (func << 12) | reg
/// Note: rel_bus is relative to the host's starting bus number
#[inline]
fn ecam_addr(base: u64, rel_bus: u8, dev: u8, func: u8, reg: u16) -> u64 {
    base + (((rel_bus as u64) << 20) | ((dev as u64) << 15) | ((func as u64) << 12) | (reg as u64))
}

/// Read an 8-bit value from PCIe config space.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn cfg_read8(config_vaddr: usize, bus: u8, dev: u8, func: u8, reg: u16) -> u8 {
    let addr = ecam_addr(config_vaddr as u64, bus, dev, func, reg);
    // SAFETY: Caller guarantees config space is mapped.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Read a 16-bit value from PCIe config space.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn cfg_read16(config_vaddr: usize, bus: u8, dev: u8, func: u8, reg: u16) -> u16 {
    let addr = ecam_addr(config_vaddr as u64, bus, dev, func, reg);
    // SAFETY: Caller guarantees config space is mapped.
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Read a 32-bit value from PCIe config space.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn cfg_read32(config_vaddr: usize, bus: u8, dev: u8, func: u8, reg: u16) -> u32 {
    let addr = ecam_addr(config_vaddr as u64, bus, dev, func, reg);
    // SAFETY: Caller guarantees config space is mapped.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to PCIe config space.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn cfg_write32(config_vaddr: usize, bus: u8, dev: u8, func: u8, reg: u16, val: u32) {
    let addr = ecam_addr(config_vaddr as u64, bus, dev, func, reg);
    // SAFETY: Caller guarantees config space is mapped.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Write a 16-bit value to PCIe config space.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn cfg_write16(config_vaddr: usize, bus: u8, dev: u8, func: u8, reg: u16, val: u16) {
    let addr = ecam_addr(config_vaddr as u64, bus, dev, func, reg);
    // SAFETY: Caller guarantees config space is mapped.
    unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
}

/// Discover MSI-X capability for a PCIe function.
///
/// Walks the capability chain in config space looking for MSI-X (cap ID 0x11).
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn discover_msix(config_vaddr: usize, bus: u8, dev: u8, func: u8) -> MsixInfo {
    // Check if capabilities list is present (status register bit 4)
    // SAFETY: config space is mapped by caller
    let status = unsafe { cfg_read16(config_vaddr, bus, dev, func, CFG_STATUS) };
    if (status & STATUS_CAP_LIST) == 0 {
        return MsixInfo::empty();
    }

    // Get capabilities pointer (byte at offset 0x34)
    // SAFETY: config space is mapped by caller
    let mut cap_ptr = unsafe { cfg_read8(config_vaddr, bus, dev, func, CFG_CAP_PTR) };

    // Walk capability chain (max 48 capabilities to prevent infinite loops)
    for _ in 0..48 {
        // Cap pointer must be DWORD aligned and in valid range
        if cap_ptr == 0 || cap_ptr < 0x40 || (cap_ptr & 0x3) != 0 {
            break;
        }

        // Read capability header: [cap_id (8), next_ptr (8)]
        // SAFETY: config space is mapped by caller
        let cap_id = unsafe { cfg_read8(config_vaddr, bus, dev, func, cap_ptr as u16) };
        let next_ptr = unsafe { cfg_read8(config_vaddr, bus, dev, func, cap_ptr as u16 + 1) };

        if cap_id == CAP_ID_MSIX {
            // Found MSI-X capability
            // Layout at cap_ptr:
            //   +0: cap_id (8), next_ptr (8)
            //   +2: msg_ctrl (16)
            //   +4: table_offset_bir (32)
            //   +8: pba_offset_bir (32)

            // SAFETY: config space is mapped by caller
            let msg_ctrl = unsafe { cfg_read16(config_vaddr, bus, dev, func, cap_ptr as u16 + 2) };
            let table_offset_bir =
                unsafe { cfg_read32(config_vaddr, bus, dev, func, cap_ptr as u16 + 4) };
            let pba_offset_bir =
                unsafe { cfg_read32(config_vaddr, bus, dev, func, cap_ptr as u16 + 8) };

            // Table size is bits [10:0] of msg_ctrl, encoded as N-1
            let table_size = (msg_ctrl & 0x7FF) + 1;

            return MsixInfo {
                present: true,
                table_size,
                table_bir: (table_offset_bir & 0x7) as u8,
                table_offset: table_offset_bir & !0x7,
                pba_bir: (pba_offset_bir & 0x7) as u8,
                pba_offset: pba_offset_bir & !0x7,
                cap_offset: cap_ptr,
            };
        }

        cap_ptr = next_ptr;
    }

    MsixInfo::empty()
}

/// Enable MSI-X for a PCIe function.
///
/// This sets the MSI-X Enable bit in the Message Control register.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
/// The MSI-X table must be properly configured before calling this.
pub unsafe fn enable_msix(config_vaddr: usize, bus: u8, dev: u8, func: u8, cap_offset: u8) {
    // Read current msg_ctrl
    // SAFETY: config space is mapped by caller
    let msg_ctrl = unsafe { cfg_read16(config_vaddr, bus, dev, func, cap_offset as u16 + 2) };

    // Set MSI-X Enable (bit 15), clear Function Mask (bit 14)
    let new_msg_ctrl = (msg_ctrl | (1 << 15)) & !(1 << 14);

    // SAFETY: config space is mapped by caller
    unsafe {
        cfg_write16(
            config_vaddr,
            bus,
            dev,
            func,
            cap_offset as u16 + 2,
            new_msg_ctrl,
        )
    };
}

/// Disable MSI-X for a PCIe function.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
pub unsafe fn disable_msix(config_vaddr: usize, bus: u8, dev: u8, func: u8, cap_offset: u8) {
    // SAFETY: config space is mapped by caller
    let msg_ctrl = unsafe { cfg_read16(config_vaddr, bus, dev, func, cap_offset as u16 + 2) };

    // Clear MSI-X Enable (bit 15)
    let new_msg_ctrl = msg_ctrl & !(1 << 15);

    // SAFETY: config space is mapped by caller
    unsafe {
        cfg_write16(
            config_vaddr,
            bus,
            dev,
            func,
            cap_offset as u16 + 2,
            new_msg_ctrl,
        )
    };
}

/// Parse PCIe host bridges from FDT.
///
/// Returns an array of up to MAX_PCIE_HOSTS host bridges.
pub fn parse_pcie_hosts(fdt_data: &[u8]) -> [Option<PcieHostBridge>; MAX_PCIE_HOSTS] {
    let mut hosts: [Option<PcieHostBridge>; MAX_PCIE_HOSTS] = [const { None }; MAX_PCIE_HOSTS];
    let mut host_count = 0;

    let fdt = match fdt::Fdt::new(fdt_data) {
        Ok(f) => f,
        Err(_) => return hosts,
    };

    for node in fdt.all_nodes() {
        if host_count >= MAX_PCIE_HOSTS {
            break;
        }

        let Some(compatible) = node.compatible() else {
            continue;
        };

        // Check for supported PCIe host compatible strings
        let mut host_type = None;
        for compat in compatible.all() {
            if compat.contains("pci-host-ecam-generic") || compat.contains("pci-host-generic") {
                host_type = Some(PcieHostType::Ecam);
                break;
            } else if compat.contains("rockchip,rk3588-pcie") {
                host_type = Some(PcieHostType::DesignWareDwc);
                break;
            }
        }

        let Some(ht) = host_type else {
            continue;
        };

        let mut host = PcieHostBridge::empty();
        host.host_type = ht;

        // Parse reg property for config space (and DBI for RK3588)
        if let Some(mut reg) = node.reg() {
            match ht {
                PcieHostType::Ecam => {
                    // ECAM: single reg entry for config space
                    if let Some(region) = reg.next() {
                        host.config_base = region.starting_address as u64;
                        host.config_size = region.size.unwrap_or(0x10000000) as u64;
                    }
                }
                PcieHostType::DesignWareDwc => {
                    // RK3588 has varying reg layouts depending on DT version:
                    // - Some: <APBDBG> <DBI>
                    // - Some: <APBDBG> <DBI> <Config>
                    // APBDBG is at 0xfe1X0000, DBI is often at high addresses (0xa40000000+)
                    // Config space is typically at 0xfX000000 range
                    //
                    // We identify regions by address characteristics:
                    // - 0xfe1X0000 range = APBDBG (client registers, for link status)
                    // - 0xfX000000 range = Config space
                    // - High addresses (> 4GB) = DBI
                    for region in reg {
                        let addr = region.starting_address as u64;
                        let size = region.size.unwrap_or(0x10000) as u64;

                        if addr >= 0x1_0000_0000 {
                            // High address (> 4GB) - this is DBI
                            host.dbi_base = addr;
                        } else if (addr & 0xFF000000) == 0xFE000000 {
                            // 0xfeXX0000 range - APBDBG (client registers)
                            host.apbdbg_base = addr;
                        } else if (addr & 0xF0000000) == 0xF0000000 {
                            // 0xfX000000 range - Config space
                            host.config_base = addr;
                            host.config_size = size;
                        }
                    }
                }
            }
        }

        // Parse bus-range property
        if let Some(bus_range_prop) = node.property("bus-range") {
            let val = bus_range_prop.value;
            if val.len() >= 8 {
                let start = u32::from_be_bytes([val[0], val[1], val[2], val[3]]) as u8;
                let end = u32::from_be_bytes([val[4], val[5], val[6], val[7]]) as u8;
                host.bus_range = (start, end);
            }
        } else {
            // Default bus range
            host.bus_range = (0, 255);
        }

        // Parse ranges property for memory window
        // Format: <pci_hi pci_mid pci_lo cpu_hi cpu_lo size_hi size_lo>
        if let Some(ranges_prop) = node.property("ranges") {
            parse_ranges_property(ranges_prop.value, &mut host);
        }

        // For ECAM, link is always considered up
        host.link_up = ht == PcieHostType::Ecam;

        hosts[host_count] = Some(host);
        host_count += 1;
    }

    hosts
}

/// Parse the DTB ranges property to extract memory window mapping.
///
/// The ranges property maps PCI addresses to CPU addresses.
/// Format varies but typically: pci_addr (3 cells) | cpu_addr (1-2 cells) | size (2 cells)
fn parse_ranges_property(data: &[u8], host: &mut PcieHostBridge) {
    // We need at least 28 bytes for a minimal entry (7 u32 cells)
    if data.len() < 28 {
        return;
    }

    // Read big-endian u32 at offset
    let read_u32 = |offset: usize| -> u32 {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    };

    // Scan through ranges entries looking for memory windows
    // Each entry: pci_hi (4) + pci_mid (4) + pci_lo (4) + cpu_hi (4) + cpu_lo (4) + size_hi (4) + size_lo (4)
    // = 28 bytes minimum, but can be 24 if cpu addr is single cell
    //
    // pci_hi bits:
    //   [31:24] = space type: 0x00 = config, 0x01 = IO, 0x02 = mem32, 0x03 = mem64
    //   [30] = prefetchable

    let entry_size = 28; // Assume 2-cell CPU address (common)
    let mut offset = 0;

    while offset + entry_size <= data.len() {
        let pci_hi = read_u32(offset);
        let pci_mid = read_u32(offset + 4);
        let pci_lo = read_u32(offset + 8);
        let cpu_hi = read_u32(offset + 12);
        let cpu_lo = read_u32(offset + 16);
        let size_hi = read_u32(offset + 20);
        let size_lo = read_u32(offset + 24);

        let space_type = (pci_hi >> 24) & 0x03;

        // Look for 32-bit memory space (0x02) or 64-bit memory space (0x03)
        if space_type == 0x02 || space_type == 0x03 {
            // Found a memory window
            let pci_addr = ((pci_mid as u64) << 32) | (pci_lo as u64);
            let cpu_addr = ((cpu_hi as u64) << 32) | (cpu_lo as u64);
            let size = ((size_hi as u64) << 32) | (size_lo as u64);

            // Use the first (or largest) memory window
            if host.mem_window_size == 0 || size > host.mem_window_size {
                host.mem_window_pci = pci_addr;
                host.mem_window_cpu = cpu_addr;
                host.mem_window_size = size;
            }
        }

        offset += entry_size;
    }
}

/// Check link status for a RK3588 PCIe controller via APBDBG registers.
///
/// # Safety
/// The APBDBG registers must be mapped at `apbdbg_vaddr`.
pub unsafe fn check_rk3588_link_status(apbdbg_vaddr: usize) -> bool {
    // Read LTSSM status register
    // SAFETY: Caller guarantees APBDBG region is mapped.
    let status =
        unsafe { core::ptr::read_volatile((apbdbg_vaddr + RK3588_LTSSM_STATUS) as *const u32) };
    // Link is up when both RDLH and SMLH link up bits are set
    (status & RK3588_RDLH_LINK_UP) != 0 && (status & RK3588_SMLH_LINK_UP) != 0
}

/// Enumerate PCIe devices on a host bridge.
///
/// # Arguments
/// * `host` - The PCIe host bridge information
/// * `config_vaddr` - Virtual address where config space is mapped
/// * `mapped_size` - Size of mapped config space in bytes
///
/// # Returns
/// Array of discovered devices (check is_valid() for valid entries)
///
/// # Safety
/// The config space must be mapped at `config_vaddr` for `mapped_size` bytes.
pub unsafe fn enumerate_devices(
    host: &PcieHostBridge,
    config_vaddr: usize,
    mapped_size: usize,
) -> [PcieDevice; MAX_PCIE_DEVICES] {
    let mut devices = [const { PcieDevice::empty() }; MAX_PCIE_DEVICES];
    let mut dev_count = 0;

    let (bus_start, bus_end) = host.bus_range;

    // Calculate how many buses/devices we can safely scan based on mapped size
    // ECAM: each device is at offset (bus << 20) | (dev << 15) | (func << 12)
    // Device N on bus 0 starts at offset N * 32KB
    // Bus N starts at offset N * 1MB
    let max_buses = (mapped_size / (1 << 20)).max(1) as u8;
    let max_devs_per_bus = (mapped_size / (1 << 15)).clamp(1, 32) as u8;

    let scan_bus_end = bus_start.saturating_add(max_buses - 1).min(bus_end);

    io::puts("[device-mgr] PCIe: scanning bus ");
    io::put_u64(bus_start as u64);
    io::puts("-");
    io::put_u64(scan_bus_end as u64);
    io::puts(" (mapped ");
    io::put_u64((mapped_size / 1024) as u64);
    io::puts("KB)...\n");

    // Scan buses in range
    for bus in bus_start..=scan_bus_end {
        if dev_count >= MAX_PCIE_DEVICES {
            break;
        }

        // Determine how many devices we can scan on this bus
        // Each device's function 0 is at offset (bus << 20) | (dev << 15)
        // With 4KB we can scan device 0 func 0; with 32KB we can scan device 0 all funcs
        // With 64KB we can scan devices 0-1; etc.
        let bus_offset = ((bus - bus_start) as usize) << 20;
        let remaining = mapped_size.saturating_sub(bus_offset);

        // We need at least 4KB to read function 0 of any device
        // Each additional device needs 32KB offset from the previous
        // devs_this_bus = 1 + (remaining - 4KB) / 32KB, clamped to [0, 32]
        let devs_this_bus = if remaining >= (1 << 12) {
            // At least 4KB - can scan device 0
            let extra_devs = remaining.saturating_sub(1 << 12) / (1 << 15);
            ((1 + extra_devs).min(32) as u8).min(max_devs_per_bus)
        } else {
            0
        };

        if devs_this_bus == 0 {
            break;
        }

        // Scan devices on this bus
        // rel_bus is the relative bus number for ECAM addressing (config space starts at 0)
        let rel_bus = bus - bus_start;

        for dev in 0..devs_this_bus {
            if dev_count >= MAX_PCIE_DEVICES {
                break;
            }

            // Calculate if we can scan all functions of this device
            // Each device needs 32KB (8 functions × 4KB) for full function scan
            let dev_offset = bus_offset + ((dev as usize) << 15);
            let dev_remaining = mapped_size.saturating_sub(dev_offset);
            let can_scan_functions = dev_remaining >= (8 << 12); // 32KB for all 8 functions

            // SAFETY: config space is mapped by caller for this range
            // Pass absolute bus for BDF reporting, relative bus for ECAM access
            unsafe {
                probe_device(
                    host,
                    config_vaddr,
                    bus,     // absolute bus for BDF
                    rel_bus, // relative bus for ECAM
                    dev,
                    &mut devices,
                    &mut dev_count,
                    can_scan_functions,
                )
            };
        }
    }

    io::puts("[device-mgr] PCIe: found ");
    io::put_u64(dev_count as u64);
    io::puts(" device(s)\n");

    devices
}

/// Probe a single device and potentially its functions.
///
/// # Arguments
/// * `host` - PCIe host bridge info
/// * `config_vaddr` - Virtual address where config space is mapped
/// * `abs_bus` - Absolute bus number (for BDF reporting)
/// * `rel_bus` - Relative bus number (for ECAM addressing, = abs_bus - bus_start)
/// * `dev` - Device number
/// * `devices` - Output array for discovered devices
/// * `dev_count` - Current count of discovered devices
/// * `can_scan_functions` - Whether we have enough mapped space to scan functions 1-7
///
/// # Safety
/// The config space must be mapped at `config_vaddr` for at least device 0 function 0.
/// If `can_scan_functions` is true, all 8 functions must be accessible.
#[allow(clippy::too_many_arguments)]
unsafe fn probe_device(
    host: &PcieHostBridge,
    config_vaddr: usize,
    abs_bus: u8,
    rel_bus: u8,
    dev: u8,
    devices: &mut [PcieDevice; MAX_PCIE_DEVICES],
    dev_count: &mut usize,
    can_scan_functions: bool,
) -> Option<()> {
    // Check function 0 first
    // SAFETY: config space is mapped by caller
    // Use rel_bus for ECAM access
    io::puts("[device-mgr] PCIe: probing ");
    io::put_u64(abs_bus as u64);
    io::puts(":");
    io::put_u64(dev as u64);
    io::puts(".0\n");

    let vendor_id = unsafe { cfg_read16(config_vaddr, rel_bus, dev, 0, CFG_VENDOR_ID) };

    io::puts("[device-mgr] PCIe: vendor=");
    io::put_hex16(vendor_id);
    io::newline();
    if vendor_id == VENDOR_ID_INVALID || vendor_id == 0 {
        return None;
    }

    // Found a device at function 0
    // SAFETY: config space is mapped by caller
    // Use abs_bus for BDF in the device record
    if let Some(device) = unsafe { probe_function(host, config_vaddr, abs_bus, rel_bus, dev, 0) }
        && *dev_count < MAX_PCIE_DEVICES
    {
        devices[*dev_count] = device;
        *dev_count += 1;

        print_device_info(&device);
    }

    // Only scan additional functions if we have enough mapped space
    if !can_scan_functions {
        return Some(());
    }

    // Check if multi-function device
    // SAFETY: config space is mapped by caller
    let header_type = unsafe { cfg_read16(config_vaddr, rel_bus, dev, 0, CFG_HEADER_TYPE) } as u8;
    if (header_type & HEADER_MULTIFUNCTION) == 0 {
        return Some(());
    }

    // Scan functions 1-7
    for func in 1..8u8 {
        if *dev_count >= MAX_PCIE_DEVICES {
            break;
        }

        // SAFETY: config space is mapped by caller for all functions
        let vendor_id = unsafe { cfg_read16(config_vaddr, rel_bus, dev, func, CFG_VENDOR_ID) };
        if vendor_id == VENDOR_ID_INVALID || vendor_id == 0 {
            continue;
        }

        // SAFETY: config space is mapped by caller
        if let Some(device) =
            unsafe { probe_function(host, config_vaddr, abs_bus, rel_bus, dev, func) }
        {
            devices[*dev_count] = device;
            *dev_count += 1;

            print_device_info(&device);
        }
    }

    Some(())
}

/// Probe a single function and extract device information.
///
/// # Arguments
/// * `abs_bus` - Absolute bus number (for BDF and stream_id)
/// * `rel_bus` - Relative bus number (for ECAM addressing)
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn probe_function(
    host: &PcieHostBridge,
    config_vaddr: usize,
    abs_bus: u8,
    rel_bus: u8,
    dev: u8,
    func: u8,
) -> Option<PcieDevice> {
    // SAFETY: config space is mapped by caller
    // Use rel_bus for ECAM access
    let vendor_id = unsafe { cfg_read16(config_vaddr, rel_bus, dev, func, CFG_VENDOR_ID) };
    let device_id = unsafe { cfg_read16(config_vaddr, rel_bus, dev, func, CFG_DEVICE_ID) };

    if vendor_id == VENDOR_ID_INVALID || vendor_id == 0 {
        return None;
    }

    // Read class code (3 bytes starting at offset 0x09)
    // Class at 0x0B, Subclass at 0x0A, ProgIF at 0x09
    let revision_class = unsafe { cfg_read32(config_vaddr, rel_bus, dev, func, CFG_REVISION) };
    let class_code = revision_class >> 8; // Shift out revision byte

    // Read header type to determine BAR layout
    let header_type = (unsafe { cfg_read16(config_vaddr, rel_bus, dev, func, CFG_HEADER_TYPE) }
        as u8)
        & HEADER_TYPE_MASK;

    // Only probe BARs and capabilities for endpoints (Type 0 headers)
    let (bar0_cpu_addr, bar0_size, msix) = if header_type == HEADER_TYPE_ENDPOINT {
        // SAFETY: config space is mapped by caller
        let (bar0_addr, bar0_sz) = unsafe { probe_bar0(host, config_vaddr, rel_bus, dev, func) };

        // Discover MSI-X capability
        // SAFETY: config space is mapped by caller
        let msix_info = unsafe { discover_msix(config_vaddr, rel_bus, dev, func) };

        (bar0_addr, bar0_sz, msix_info)
    } else {
        (0, 0, MsixInfo::empty())
    };

    // Calculate stream ID for IOMMU
    // Default: Requester ID = (bus << 8) | (dev << 3) | func
    // Use absolute bus for the actual BDF/stream ID
    let stream_id = ((abs_bus as u32) << 8) | ((dev as u32) << 3) | (func as u32);

    Some(PcieDevice {
        bdf: (abs_bus, dev, func), // Use absolute bus for BDF
        vendor_id,
        device_id,
        class_code,
        bar0_cpu_addr,
        bar0_size,
        stream_id,
        msix,
    })
}

/// Probe BAR0 to get its CPU address and size.
///
/// # Safety
/// The config space must be mapped at `config_vaddr`.
unsafe fn probe_bar0(
    host: &PcieHostBridge,
    config_vaddr: usize,
    bus: u8,
    dev: u8,
    func: u8,
) -> (u64, u64) {
    // Read current BAR0 value
    // SAFETY: config space is mapped by caller
    let bar0 = unsafe { cfg_read32(config_vaddr, bus, dev, func, CFG_BAR0) };

    if bar0 == 0 || bar0 == 0xFFFFFFFF {
        return (0, 0);
    }

    // Check if 64-bit BAR (bit 2:1 = 10)
    let is_64bit = (bar0 & 0x6) == 0x4;

    // Get current address (may be assigned by UEFI/firmware)
    let bar1_orig = if is_64bit {
        // SAFETY: config space is mapped by caller
        unsafe { cfg_read32(config_vaddr, bus, dev, func, CFG_BAR0 + 4) }
    } else {
        0
    };

    let pci_addr = if is_64bit {
        ((bar1_orig as u64) << 32) | ((bar0 & !0xF) as u64)
    } else {
        (bar0 & !0xF) as u64
    };

    // Size the BAR by writing all 1s and reading back
    // SAFETY: config space is mapped by caller
    unsafe {
        cfg_write32(config_vaddr, bus, dev, func, CFG_BAR0, 0xFFFFFFFF);
    }
    let size_mask_lo = unsafe { cfg_read32(config_vaddr, bus, dev, func, CFG_BAR0) };

    // Restore BAR0
    // SAFETY: config space is mapped by caller
    unsafe {
        cfg_write32(config_vaddr, bus, dev, func, CFG_BAR0, bar0);
    }

    let size_mask_hi = if is_64bit {
        // SAFETY: config space is mapped by caller
        unsafe {
            cfg_write32(config_vaddr, bus, dev, func, CFG_BAR0 + 4, 0xFFFFFFFF);
        }
        let mask_hi = unsafe { cfg_read32(config_vaddr, bus, dev, func, CFG_BAR0 + 4) };
        // Restore BAR1
        unsafe {
            cfg_write32(config_vaddr, bus, dev, func, CFG_BAR0 + 4, bar1_orig);
        }
        mask_hi
    } else {
        0xFFFFFFFF // For 32-bit BARs, treat upper bits as all 1s
    };

    // Calculate size from mask
    // Clear type bits from lower mask
    let size_mask_lo = size_mask_lo & !0xF;
    if size_mask_lo == 0 && size_mask_hi == 0xFFFFFFFF {
        return (0, 0);
    }

    // Combine into 64-bit mask and calculate size
    // For 32-bit BAR: upper bits are 0xFFFFFFFF, lower is the actual mask
    // For 64-bit BAR: both halves come from the BAR
    let full_mask = ((size_mask_hi as u64) << 32) | (size_mask_lo as u64);
    let size = (!full_mask).wrapping_add(1);

    // Sanity check: size should be at least 16 bytes and power of 2
    if size == 0 || size > (1 << 40) {
        // Invalid size (> 1TB is unreasonable)
        return (0, 0);
    }

    // Translate PCI address to CPU address using the memory window
    let cpu_addr = if pci_addr >= host.mem_window_pci
        && pci_addr < host.mem_window_pci + host.mem_window_size
    {
        // Within memory window - translate
        pci_addr - host.mem_window_pci + host.mem_window_cpu
    } else if pci_addr == 0 {
        // Not programmed yet - firmware may not have assigned it
        0
    } else {
        // Assume identity mapping for addresses outside window
        pci_addr
    };

    (cpu_addr, size)
}

/// Print device information to console.
fn print_device_info(device: &PcieDevice) {
    let (bus, dev, func) = device.bdf;
    let class_str = device.format_class_code();

    io::puts("[device-mgr] PCIe: found ");
    // Format BDF as XX:XX.X
    io::put_hex_byte(bus);
    io::puts(":");
    io::put_hex_byte(dev);
    io::puts(".");
    io::put_u64(func as u64);
    io::puts(" vendor=");
    io::put_hex16(device.vendor_id);
    io::puts(" device=");
    io::put_hex16(device.device_id);
    io::puts(" class=");
    // SAFETY: class_str is valid UTF-8 (only hex digits)
    io::puts(core::str::from_utf8(&class_str).unwrap_or("??????"));

    // Print class description
    let class = (device.class_code >> 16) & 0xFF;
    let subclass = (device.class_code >> 8) & 0xFF;
    io::puts(" (");
    io::puts(class_name(class as u8, subclass as u8));
    io::puts(")");

    if device.bar0_cpu_addr != 0 {
        io::puts("\n[device-mgr] PCIe:   BAR0 at ");
        io::put_hex(device.bar0_cpu_addr);
        io::puts(" (");
        io::put_u64(device.bar0_size / 1024);
        io::puts("KB)");
    }

    // Print MSI-X info if present
    if device.msix.present {
        io::puts("\n[device-mgr] PCIe:   MSI-X: ");
        io::put_u64(device.msix.table_size as u64);
        io::puts(" vectors, table in BAR");
        io::put_u64(device.msix.table_bir as u64);
        io::puts("+0x");
        io::put_hex32(device.msix.table_offset);
    }

    io::newline();
}

/// Get human-readable name for a PCIe class code.
fn class_name(class: u8, subclass: u8) -> &'static str {
    match (class, subclass) {
        (0x01, 0x08) => "NVMe",
        (0x01, 0x06) => "SATA",
        (0x01, 0x01) => "IDE",
        (0x01, _) => "Storage",
        (0x02, 0x00) => "Ethernet",
        (0x02, 0x80) => "Network",
        (0x02, _) => "Network",
        (0x03, 0x00) => "VGA",
        (0x03, _) => "Display",
        (0x04, 0x00) => "Video",
        (0x04, 0x01) => "Audio",
        (0x04, 0x03) => "HDAudio",
        (0x04, _) => "Multimedia",
        (0x06, 0x00) => "Host Bridge",
        (0x06, 0x01) => "ISA Bridge",
        (0x06, 0x04) => "PCI Bridge",
        (0x06, _) => "Bridge",
        (0x0C, 0x03) => "USB",
        (0x0C, _) => "Serial Bus",
        _ => "Unknown",
    }
}
