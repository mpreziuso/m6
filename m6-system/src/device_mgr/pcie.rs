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
/// Maximum host bridges to support.
/// RK3588 has 5 PCIe controllers (3x pcie2x1 + pcie3x2 + pcie3x4).
pub const MAX_PCIE_HOSTS: usize = 8;

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

/// PCIE_CLIENT_LTSSM_STATUS register offset (in client register block).
/// Linux: drivers/pci/controller/dwc/pcie-dw-rockchip.c PCIE_CLIENT_LTSSM_STATUS = 0x0300.
const RK3588_LTSSM_STATUS: usize = 0x300;
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
    /// CPU address for 32-bit non-prefetchable memory window (from ranges)
    pub mem32_cpu: u64,
    /// PCI address for 32-bit non-prefetchable memory window
    pub mem32_pci: u64,
    /// Size of 32-bit memory window
    pub mem32_size: u64,
    /// CPU address for 64-bit prefetchable memory window (from ranges)
    pub mem64_cpu: u64,
    /// PCI address for 64-bit prefetchable memory window
    pub mem64_pci: u64,
    /// Size of 64-bit memory window
    pub mem64_size: u64,
    /// IOMMU (SMMU) phandle from iommu-map property (0 = none)
    pub iommu_phandle: u32,
    /// Stream ID base from iommu-map (added to raw BDF to get SMMU stream ID)
    pub iommu_stream_base: u32,
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
            mem32_cpu: 0,
            mem32_pci: 0,
            mem32_size: 0,
            mem64_cpu: 0,
            mem64_pci: 0,
            mem64_size: 0,
            iommu_phandle: 0,
            iommu_stream_base: 0,
            link_up: false,
        }
    }

    /// Translate a PCI BAR address to CPU address using memory windows.
    ///
    /// Checks the 32-bit window first, then the 64-bit window.
    /// Falls back to identity mapping for addresses outside both windows.
    pub fn pci_to_cpu(&self, pci_addr: u64) -> u64 {
        if pci_addr == 0 {
            return 0;
        }
        // Check 32-bit non-prefetchable window
        if self.mem32_size > 0
            && pci_addr >= self.mem32_pci
            && pci_addr < self.mem32_pci + self.mem32_size
        {
            return pci_addr - self.mem32_pci + self.mem32_cpu;
        }
        // Check 64-bit prefetchable window
        if self.mem64_size > 0
            && pci_addr >= self.mem64_pci
            && pci_addr < self.mem64_pci + self.mem64_size
        {
            return pci_addr - self.mem64_pci + self.mem64_cpu;
        }
        // Identity mapping for addresses outside known windows
        pci_addr
    }

    /// Check if a PCI address falls within a known memory window.
    pub fn is_in_memory_window(&self, pci_addr: u64) -> bool {
        if pci_addr == 0 {
            return false;
        }
        if self.mem32_size > 0
            && pci_addr >= self.mem32_pci
            && pci_addr < self.mem32_pci + self.mem32_size
        {
            return true;
        }
        if self.mem64_size > 0
            && pci_addr >= self.mem64_pci
            && pci_addr < self.mem64_pci + self.mem64_size
        {
            return true;
        }
        false
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
pub(super) unsafe fn cfg_write32(
    config_vaddr: usize,
    bus: u8,
    dev: u8,
    func: u8,
    reg: u16,
    val: u32,
) {
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

        // Parse ranges property for memory windows
        // Format: <pci_hi pci_mid pci_lo cpu_hi cpu_lo size_hi size_lo>
        if let Some(ranges_prop) = node.property("ranges") {
            parse_ranges_property(ranges_prop.value, &mut host);
        }

        // Parse iommu-map property for SMMU phandle and stream ID base
        // Format: <rid_base smmu_phandle stream_id_base length>
        // e.g., <0x0 0x190 0x10000 0x10000> → phandle 0x190, stream base 0x10000
        // The hardware adds stream_id_base to the raw BDF to produce the
        // SMMU stream ID. Each PCIe controller has a unique base.
        if let Some(iommu_map_prop) = node.property("iommu-map") {
            let val = iommu_map_prop.value;
            if val.len() >= 16 {
                host.iommu_phandle = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
                host.iommu_stream_base = u32::from_be_bytes([val[8], val[9], val[10], val[11]]);
            }
        }

        // RK3588 DWC: always use hardware-defined stream bases from the TRM.
        // EDK2 DTBs provide iommu-map with stream_id_base=0 for ALL controllers,
        // but the hardware requires per-controller bases (pcie3x2=0x10000, etc).
        // Without this, the SMMU STE is configured at the wrong stream index
        // and DMA is silently GBPA-aborted.
        if ht == PcieHostType::DesignWareDwc {
            if host.iommu_phandle == 0 {
                host.iommu_phandle = 0x190;
            }
            host.iommu_stream_base = iommu_stream_base_for_config(host.config_base);
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

        let pci_addr = ((pci_mid as u64) << 32) | (pci_lo as u64);
        let cpu_addr = ((cpu_hi as u64) << 32) | (cpu_lo as u64);
        let size = ((size_hi as u64) << 32) | (size_lo as u64);

        match space_type {
            0x02 => {
                // 32-bit non-prefetchable memory window
                if size > host.mem32_size {
                    host.mem32_pci = pci_addr;
                    host.mem32_cpu = cpu_addr;
                    host.mem32_size = size;
                }
            }
            0x03 => {
                // 64-bit prefetchable memory window
                if size > host.mem64_size {
                    host.mem64_pci = pci_addr;
                    host.mem64_cpu = cpu_addr;
                    host.mem64_size = size;
                }
            }
            _ => {}
        }

        offset += entry_size;
    }
}

/// Check link status for a RK3588 PCIe controller via client registers.
///
/// Returns `Some(true)` if link is up, `Some(false)` if link is confirmed down,
/// or `None` if the register reads all zeros (clocks likely not enabled).
///
/// # Safety
/// The client register block must be mapped at `apbdbg_vaddr`.
pub unsafe fn check_rk3588_link_status(apbdbg_vaddr: usize) -> Option<bool> {
    // Read LTSSM status register
    // SAFETY: Caller guarantees register region is mapped.
    let status =
        unsafe { core::ptr::read_volatile((apbdbg_vaddr + RK3588_LTSSM_STATUS) as *const u32) };

    // If the entire register reads zero, the PCIe controller's APB clock is
    // likely not enabled — treat as "status unknown" so the caller can fall
    // back to a safe default.
    if status == 0 {
        return None;
    }

    // Link is up when both RDLH and SMLH link up bits are set
    Some((status & RK3588_RDLH_LINK_UP) != 0 && (status & RK3588_SMLH_LINK_UP) != 0)
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

    log::info!(
        "PCIe: scanning bus {}-{} (mapped {}KB)...",
        bus_start,
        scan_bus_end,
        mapped_size / 1024
    );

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

    log::info!("PCIe: found {} device(s)", dev_count);

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
    log::debug!("PCIe: probing {}:{}.0", abs_bus, dev);

    let vendor_id = unsafe { cfg_read16(config_vaddr, rel_bus, dev, 0, CFG_VENDOR_ID) };

    log::debug!("PCIe: vendor={:#06x}", vendor_id);
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
    // The hardware stream ID = iommu_stream_base + raw BDF.
    // Each PCIe controller has a unique stream_base so their stream IDs
    // don't collide in the shared SMMU. On RK3588, these bases come from
    // the iommu-map DTB property (or the iommu_stream_base_for_config fallback).
    let bdf = ((abs_bus as u32) << 8) | ((dev as u32) << 3) | (func as u32);
    let stream_id = host.iommu_stream_base + bdf;

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

    log::debug!("PCIe: BAR0 raw={:#x}", bar0);

    if bar0 == 0 || bar0 == 0xFFFFFFFF {
        log::debug!("PCIe: BAR0 empty");
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

    log::debug!(
        "PCIe: BAR1 raw={:#x} ({})",
        bar1_orig,
        if is_64bit { "64-bit" } else { "32-bit" }
    );

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

    // If BAR0 PCI address is outside all known memory windows, reassign it
    // to the mem32 window. This happens when UEFI assigns BARs to addresses
    // not described by the DTB ranges property (e.g. RK3588 pcie3x2 where
    // UEFI uses 0xF1000000 but DTB mem32 starts at 0xF1200000).
    let mut pci_addr = pci_addr;
    if pci_addr != 0 && !host.is_in_memory_window(pci_addr) && host.mem32_size > 0 {
        // Align to BAR size within mem32 window
        let aligned = (host.mem32_pci + size - 1) & !(size - 1);
        if aligned + size <= host.mem32_pci + host.mem32_size {
            log::info!(
                "PCIe: BAR0 at {:#x} outside memory windows, reassigning to {:#x}",
                pci_addr,
                aligned
            );

            // Write new BAR0 value (preserve type bits from original)
            let bar0_new = (aligned as u32 & !0xF) | (bar0 & 0xF);
            // SAFETY: config space is mapped by caller
            unsafe {
                cfg_write32(config_vaddr, bus, dev, func, CFG_BAR0, bar0_new);
            }
            if is_64bit {
                // SAFETY: config space is mapped by caller
                unsafe {
                    cfg_write32(
                        config_vaddr,
                        bus,
                        dev,
                        func,
                        CFG_BAR0 + 4,
                        (aligned >> 32) as u32,
                    );
                }
            }

            pci_addr = aligned;
        }
    }

    // Enable Memory Space and Bus Master in Command register.
    // Required for endpoints to respond to MMIO reads and initiate DMA.
    // SAFETY: config space is mapped by caller
    let cmd = unsafe { cfg_read16(config_vaddr, bus, dev, func, CFG_COMMAND) };
    if cmd & 0x06 != 0x06 {
        unsafe {
            cfg_write16(config_vaddr, bus, dev, func, CFG_COMMAND, cmd | 0x06);
        }
    }
    // Read back and log Command register to verify BME is actually set
    let cmd_rb = unsafe { cfg_read16(config_vaddr, bus, dev, func, CFG_COMMAND) };
    log::debug!(
        "PCIe: CMD={:#x}{}{}",
        cmd_rb,
        if cmd_rb & 0x04 != 0 { " BME" } else { " !BME" },
        if cmd_rb & 0x02 != 0 { " MEM" } else { " !MEM" }
    );

    // Translate PCI address to CPU address using memory windows
    let cpu_addr = host.pci_to_cpu(pci_addr);

    log::debug!(
        "PCIe: BAR0 pci_addr={:#x} cpu_addr={:#x} size={:#x}",
        pci_addr,
        cpu_addr,
        size
    );

    (cpu_addr, size)
}

/// Print device information to console.
fn print_device_info(device: &PcieDevice) {
    let (bus, dev, func) = device.bdf;
    let class_str = device.format_class_code();
    // SAFETY: class_str is valid UTF-8 (only hex digits)
    let class_str = core::str::from_utf8(&class_str).unwrap_or("??????");

    let class = (device.class_code >> 16) & 0xFF;
    let subclass = (device.class_code >> 8) & 0xFF;

    log::info!(
        "PCIe: found {:02x}:{:02x}.{} vendor={:#06x} device={:#06x} class={} ({})",
        bus,
        dev,
        func,
        device.vendor_id,
        device.device_id,
        class_str,
        class_name(class as u8, subclass as u8)
    );

    if device.bar0_cpu_addr != 0 {
        log::info!(
            "PCIe:   BAR0 at {:#x} ({}KB)",
            device.bar0_cpu_addr,
            device.bar0_size / 1024
        );
    }

    if device.msix.present {
        log::info!(
            "PCIe:   MSI-X: {} vectors, table in BAR{}+{:#x}",
            device.msix.table_size,
            device.msix.table_bir,
            device.msix.table_offset
        );
    }
}

// -- Type 1 header (PCI-PCI bridge) register offsets

/// Primary/Secondary/Subordinate bus number register (32-bit at offset 0x18)
const CFG_BUS_NUMBERS: u16 = 0x18;
/// Memory Base / Memory Limit register (32-bit at offset 0x20)
/// Bits 15:4 = Memory Base upper 12 bits (1MB aligned), Bits 31:20 = Memory Limit upper 12 bits
const CFG_MEMORY_BASE_LIMIT: u16 = 0x20;

/// Bridge information parsed from a Type 1 header
#[derive(Debug, Clone, Copy)]
pub struct BridgeInfo {
    pub primary_bus: u8,
    pub secondary_bus: u8,
    pub subordinate_bus: u8,
}

/// Read bridge information from a Type 1 (PCI-PCI bridge) header.
///
/// Returns `None` if the device at the given BDF is not a bridge.
///
/// # Safety
/// Config space must be mapped at `config_vaddr`.
pub unsafe fn read_bridge_info(
    config_vaddr: usize,
    rel_bus: u8,
    dev: u8,
    func: u8,
) -> Option<BridgeInfo> {
    // SAFETY: config space is mapped by caller
    let header_type =
        unsafe { cfg_read8(config_vaddr, rel_bus, dev, func, CFG_HEADER_TYPE) } & 0x7F;
    if header_type != HEADER_TYPE_BRIDGE {
        return None;
    }
    // SAFETY: config space is mapped by caller
    let bus_reg = unsafe { cfg_read32(config_vaddr, rel_bus, dev, func, CFG_BUS_NUMBERS) };
    Some(BridgeInfo {
        primary_bus: bus_reg as u8,
        secondary_bus: (bus_reg >> 8) as u8,
        subordinate_bus: (bus_reg >> 16) as u8,
    })
}

/// Programme the root port's Memory Base/Limit window via DBI.
///
/// The DBI mirrors the root port's Type 1 config header. The Memory Base
/// register (offset 0x20) controls which memory-mapped transactions the
/// bridge forwards downstream. Without this, the root port won't forward
/// MEM TLPs to the device's BAR0.
///
/// `mem_base` and `mem_limit` are **PCI addresses** (1MB-aligned), not CPU
/// addresses. The root port checks incoming TLP addresses against this range.
///
/// # Safety
/// `dbi_config_vaddr` must point to the mapped DBI config page.
pub unsafe fn set_bridge_memory_window(dbi_config_vaddr: usize, mem_base: u64, mem_limit: u64) {
    // Memory Base: bits 15:4 = address bits 31:20 (1MB granularity)
    // Memory Limit: bits 31:20 = address bits 31:20 of the top of the range
    let base_field = ((mem_base >> 16) & 0xFFF0) as u32;
    let limit_field = ((mem_limit >> 16) & 0xFFF0) as u32;
    let val = base_field | (limit_field << 16);
    // SAFETY: DBI config space is mapped by caller; bus=0, dev=0, func=0 is the root port
    unsafe {
        cfg_write32(dbi_config_vaddr, 0, 0, 0, CFG_MEMORY_BASE_LIMIT, val);
    }
}

// -- DWC iATU registers (unrolled layout, offset from DBI base)

/// Offset of iATU register block from DBI base
pub const IATU_OFFSET: u64 = 0x300000;
/// Stride between iATU regions (512 bytes per region)
const IATU_REGION_STRIDE: usize = 0x200;

// Per-region register offsets
const IATU_REGION_CTRL1: usize = 0x00;
const IATU_REGION_CTRL2: usize = 0x04;
const IATU_LOWER_BASE: usize = 0x08;
const IATU_UPPER_BASE: usize = 0x0C;
const IATU_LOWER_LIMIT: usize = 0x10;
const IATU_LOWER_TARGET: usize = 0x14;
const IATU_UPPER_TARGET: usize = 0x18;
const IATU_UPPER_LIMIT: usize = 0x20;

/// ATU type for Type 0 config access (direct children on secondary bus)
pub const IATU_TYPE_CFG0: u32 = 0x4;
/// ATU type for Type 1 config access (devices behind switches)
#[allow(dead_code)]
pub const IATU_TYPE_CFG1: u32 = 0x5;

// Inbound region offset within each iATU region block
const IATU_INBOUND_OFFSET: usize = 0x100;

// ATU control bits
const IATU_ENABLE: u32 = 1 << 31;
const IATU_CFG_SHIFT_MODE: u32 = 1 << 28;

/// Maximum number of iATU regions to probe/disable.
const IATU_MAX_REGIONS: usize = 8;

/// Disable all inbound iATU windows.
///
/// UEFI may leave inbound iATU windows enabled from its own DMA setup.
/// On DWC PCIe, enabling ANY inbound iATU window disables the hardware's
/// default 1:1 pass-through for inbound TLPs. We must explicitly disable
/// all inbound windows to restore the default pass-through.
///
/// # Safety
///
/// `iatu_vaddr` must point to the mapped iATU register block.
pub unsafe fn disable_all_inbound_iatu(iatu_vaddr: usize) {
    for region in 0..IATU_MAX_REGIONS {
        let ctrl2_addr =
            iatu_vaddr + region * IATU_REGION_STRIDE + IATU_INBOUND_OFFSET + IATU_REGION_CTRL2;
        // SAFETY: iATU registers are mapped by caller
        unsafe {
            let ctrl2 = core::ptr::read_volatile(ctrl2_addr as *const u32);
            if ctrl2 & IATU_ENABLE != 0 {
                core::ptr::write_volatile(ctrl2_addr as *mut u32, ctrl2 & !IATU_ENABLE);
            }
        }
    }
}

/// Configure an inbound iATU region in address-match mode.
///
/// Creates a pass-through window that accepts inbound DMA TLPs within
/// [`base`..`limit`] and translates them to AXI address `target + (addr - base)`.
/// For identity mapping, set `target == base`.
///
/// On DWC PCIe, the hardware default 1:1 pass-through only works if NO
/// inbound iATU region is enabled. However, RK3588 UEFI may leave stale
/// inbound regions from its own DMA setup. Disabling those without providing
/// a replacement can leave the RC with no inbound acceptance window at all,
/// silently dropping all DMA TLPs from downstream devices.
///
/// Configure RC BAR0 matching Linux's `dw_pcie_setup_rc()`.
///
/// Linux writes BAR0=0x4 (64-bit type) then zeroes it at the end.
/// On RK3588 with no `dma-ranges`, Linux leaves all inbound iATU disabled
/// and zeroes BAR0 — the DWC RC passes all inbound TLPs through by default.
///
/// # Safety
///
/// `dbi_vaddr` must point to the mapped DBI config page (root port config space).
pub unsafe fn setup_rc_bar0_for_dma(dbi_vaddr: usize) {
    const DBI_RO_WR_EN: usize = 0x8BC;

    // Enable DBI write access to read-only registers
    unsafe {
        let misc = core::ptr::read_volatile((dbi_vaddr + DBI_RO_WR_EN) as *const u32);
        core::ptr::write_volatile((dbi_vaddr + DBI_RO_WR_EN) as *mut u32, misc | 1);
    }

    // Write BAR0=0x4 (64-bit type), BAR1=0x0 — then zero BAR0 at end.
    // This matches Linux dw_pcie_setup_rc() exactly.
    unsafe {
        core::ptr::write_volatile((dbi_vaddr + 0x10) as *mut u32, 0x0000_0004);
        core::ptr::write_volatile((dbi_vaddr + 0x14) as *mut u32, 0x0000_0000);
        core::ptr::write_volatile((dbi_vaddr + 0x10) as *mut u32, 0x0000_0000);
    }

    // Disable DBI write access to read-only registers
    unsafe {
        let misc = core::ptr::read_volatile((dbi_vaddr + DBI_RO_WR_EN) as *const u32);
        core::ptr::write_volatile((dbi_vaddr + DBI_RO_WR_EN) as *mut u32, misc & !1);
    }
}

/// Enable Memory Space and Bus Master on a device via config space.
///
/// Required for endpoints to respond to MMIO and initiate DMA,
/// and for bridges to forward transactions.
///
/// # Safety
/// Config space must be mapped at `config_vaddr`.
pub unsafe fn enable_bus_master(config_vaddr: usize, bus: u8, dev: u8, func: u8) {
    let cmd = unsafe { cfg_read16(config_vaddr, bus, dev, func, CFG_COMMAND) };
    unsafe { cfg_write16(config_vaddr, bus, dev, func, CFG_COMMAND, cmd | 0x06) };
}

/// Programme an outbound iATU region for config space access.
///
/// # Safety
/// `iatu_vaddr` must point to mapped iATU registers.
pub unsafe fn programme_iatu_for_config(
    iatu_vaddr: usize,
    region_index: usize,
    atu_type: u32,
    cpu_base: u64,
    size: u64,
    target_bus: u8,
) {
    let region_base = iatu_vaddr + region_index * IATU_REGION_STRIDE;

    // SAFETY: caller guarantees iATU registers are mapped at iatu_vaddr
    unsafe {
        // Disable region first
        core::ptr::write_volatile((region_base + IATU_REGION_CTRL2) as *mut u32, 0);

        // Set base address (CPU address that triggers translation)
        core::ptr::write_volatile((region_base + IATU_LOWER_BASE) as *mut u32, cpu_base as u32);
        core::ptr::write_volatile(
            (region_base + IATU_UPPER_BASE) as *mut u32,
            (cpu_base >> 32) as u32,
        );

        // Set limit (base + size - 1)
        let limit = cpu_base + size - 1;
        core::ptr::write_volatile((region_base + IATU_LOWER_LIMIT) as *mut u32, limit as u32);
        core::ptr::write_volatile(
            (region_base + IATU_UPPER_LIMIT) as *mut u32,
            (limit >> 32) as u32,
        );

        // Set target (BDF encoding for config access)
        let target = (target_bus as u32) << 24;
        core::ptr::write_volatile((region_base + IATU_LOWER_TARGET) as *mut u32, target);
        core::ptr::write_volatile((region_base + IATU_UPPER_TARGET) as *mut u32, 0);

        // Set type and enable with CFG_SHIFT_MODE
        core::ptr::write_volatile((region_base + IATU_REGION_CTRL1) as *mut u32, atu_type);
        core::ptr::write_volatile(
            (region_base + IATU_REGION_CTRL2) as *mut u32,
            IATU_ENABLE | IATU_CFG_SHIFT_MODE,
        );
    }

    // Poll for enable (hardware may take a few cycles)
    for _ in 0..1000 {
        // SAFETY: caller guarantees iATU registers are mapped
        let ctrl2 =
            unsafe { core::ptr::read_volatile((region_base + IATU_REGION_CTRL2) as *const u32) };
        if ctrl2 & IATU_ENABLE != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Programme an outbound iATU region for memory (BAR MMIO) access.
///
/// After PCIe enumeration, reprogramme an ATU region so that CPU accesses
/// to the memory window are translated into PCI MEM TLPs, allowing drivers
/// to reach device BARs.
///
/// # Safety
/// `iatu_vaddr` must point to mapped iATU registers.
pub unsafe fn programme_iatu_for_mem(
    iatu_vaddr: usize,
    region_index: usize,
    cpu_base: u64,
    pci_base: u64,
    size: u64,
) {
    let region_base = iatu_vaddr + region_index * IATU_REGION_STRIDE;

    // SAFETY: caller guarantees iATU registers are mapped at iatu_vaddr
    unsafe {
        // Disable region first
        core::ptr::write_volatile((region_base + IATU_REGION_CTRL2) as *mut u32, 0);

        // Set base address (CPU address that triggers translation)
        core::ptr::write_volatile((region_base + IATU_LOWER_BASE) as *mut u32, cpu_base as u32);
        core::ptr::write_volatile(
            (region_base + IATU_UPPER_BASE) as *mut u32,
            (cpu_base >> 32) as u32,
        );

        // Set limit (base + size - 1)
        let limit = cpu_base + size - 1;
        core::ptr::write_volatile((region_base + IATU_LOWER_LIMIT) as *mut u32, limit as u32);
        core::ptr::write_volatile(
            (region_base + IATU_UPPER_LIMIT) as *mut u32,
            (limit >> 32) as u32,
        );

        // Set target (PCI base address for the memory window)
        core::ptr::write_volatile(
            (region_base + IATU_LOWER_TARGET) as *mut u32,
            pci_base as u32,
        );
        core::ptr::write_volatile(
            (region_base + IATU_UPPER_TARGET) as *mut u32,
            (pci_base >> 32) as u32,
        );

        // Type 0 = MEM read/write, enable without CFG_SHIFT_MODE
        core::ptr::write_volatile((region_base + IATU_REGION_CTRL1) as *mut u32, 0x0);
        core::ptr::write_volatile((region_base + IATU_REGION_CTRL2) as *mut u32, IATU_ENABLE);
    }

    // Poll for enable
    for _ in 0..1000 {
        // SAFETY: caller guarantees iATU registers are mapped
        let ctrl2 =
            unsafe { core::ptr::read_volatile((region_base + IATU_REGION_CTRL2) as *const u32) };
        if ctrl2 & IATU_ENABLE != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Look up the low-address DBI base for an RK3588 PCIe controller.
///
/// RK3588 has both high-address (> 4GB) and low-address DBI mappings.
/// If the DTB provides the high-address DBI but no device untyped covers it,
/// this returns the low-address alternative derived from the TRM.
pub fn dbi_low_addr_for_config(config_base: u64) -> Option<u64> {
    match config_base {
        0xF000_0000 => Some(0xF500_0000),
        0xF100_0000 => Some(0xF540_0000),
        0xF200_0000 => Some(0xF580_0000),
        0xF300_0000 => Some(0xF5C0_0000),
        0xF400_0000 => Some(0xF600_0000),
        _ => None,
    }
}

/// Look up the SMMU iommu-map stream ID base for an RK3588 PCIe controller.
///
/// When the EDK2 DTB doesn't include iommu-map, this provides the hardware-
/// defined stream ID base from the RK3588 TRM. Each PCIe controller has a
/// unique base so their stream IDs don't collide in the shared SMMU.
fn iommu_stream_base_for_config(config_base: u64) -> u32 {
    // From rk3588-extra.dtsi / rk3588-base.dtsi iommu-map entries (upstream):
    //   pcie3x4:   <0x0000 &mmu600_pcie 0x0000 0x1000>
    //   pcie3x2:   <0x1000 &mmu600_pcie 0x1000 0x1000>
    //   pcie2x1l0: <0x2000 &its0        0x2000 0x1000>
    //   pcie2x1l1: <0x3000 &mmu600_pcie 0x3000 0x1000>
    //   pcie2x1l2: <0x4000 &mmu600_pcie 0x4000 0x1000>
    //
    // The hardware adds the controller's rid_base to local BDFs, producing
    // RIDs that the SMMU sees directly. With identity iommu-map (rid_base
    // == iommu_base), the stream ID = iommu_base + local_BDF.
    match config_base {
        0xF000_0000 => 0x0000, // pcie3x4
        0xF100_0000 => 0x1000, // pcie3x2
        0xF200_0000 => 0x2000, // pcie2x1l0
        0xF300_0000 => 0x3000, // pcie2x1l1
        0xF400_0000 => 0x4000, // pcie2x1l2
        _ => 0,
    }
}

/// Scan a single bus for devices at the given config space virtual address.
///
/// Unlike `enumerate_devices`, this scans exactly one bus. The config page
/// at `config_vaddr` must cover the target bus. `abs_bus` is used for BDF
/// reporting; ECAM addressing uses rel_bus=0 (the config page IS the bus).
///
/// # Safety
/// Config space must be mapped at `config_vaddr` for at least `mapped_size` bytes.
pub unsafe fn enumerate_devices_at(
    host: &PcieHostBridge,
    config_vaddr: usize,
    abs_bus: u8,
    mapped_size: usize,
) -> [PcieDevice; MAX_PCIE_DEVICES] {
    let mut devices = [const { PcieDevice::empty() }; MAX_PCIE_DEVICES];
    let mut dev_count = 0;

    // How many devices can we scan? Each device occupies 32KB in ECAM space.
    let max_devs = (mapped_size / (1 << 15)).clamp(1, 32) as u8;

    log::info!(
        "PCIe: scanning secondary bus {} (mapped {}KB)...",
        abs_bus,
        mapped_size / 1024
    );

    for dev in 0..max_devs {
        if dev_count >= MAX_PCIE_DEVICES {
            break;
        }

        let dev_offset = (dev as usize) << 15;
        let dev_remaining = mapped_size.saturating_sub(dev_offset);
        let can_scan_functions = dev_remaining >= (8 << 12);

        // SAFETY: config space is mapped by caller
        // rel_bus=0 because config_vaddr points directly at this bus's config page
        unsafe {
            probe_device(
                host,
                config_vaddr,
                abs_bus, // absolute bus for BDF
                0,       // rel_bus=0: config page IS this bus
                dev,
                &mut devices,
                &mut dev_count,
                can_scan_functions,
            )
        };
    }

    log::info!("PCIe: found {} device(s) on secondary bus", dev_count);

    devices
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
