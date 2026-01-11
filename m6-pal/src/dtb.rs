//! Device Tree Blob parsing for platform configuration
//!
//! This module handles parsing the Device Tree Blob to extract platform
//! configuration details like GIC addresses, UART base, RAM configuration, etc.
//! The parsed DTB is kept in static storage for later access by other modules
//! (e.g., device manager service).

use fdt::Fdt;
use m6_common::boot::{BootInfo, KERNEL_PHYS_MAP_BASE};
use once_cell_no_std::OnceCell;
use crate::dtb_platform::{DtbPlatform, GicVersion, SmmuConfig, UartType};

/// Maximum DTB size (2MB should accommodate most device trees)
const DTB_MAX_SIZE: usize = 2 * 1024 * 1024;

/// Parse result errors
#[derive(Debug, Clone, Copy)]
pub enum DtbError {
    /// No DTB address provided in BootInfo
    NoDtbAddress,
    /// DTB parsing failed (invalid magic, checksum, etc.)
    InvalidDtb,
    /// Required node not found in device tree
    MissingNode(&'static str),
    /// Required property not found in node
    MissingProperty(&'static str),
    /// Property data is invalid or malformed
    InvalidData,
}

/// Storage for parsed DTB (kept after parsing for device manager access)
static PARSED_DTB: OnceCell<&'static Fdt<'static>> = OnceCell::new();

/// Storage for platform name (copied from DTB due to lifetime constraints)
static DTB_PLATFORM_NAME: OnceCell<[u8; 128]> = OnceCell::new();
/// Length of platform name stored in DTB_PLATFORM_NAME
static DTB_PLATFORM_NAME_LEN: OnceCell<usize> = OnceCell::new();
/// Storage for compatible string (fallback if model not available)
static DTB_COMPATIBLE_NAME: OnceCell<[u8; 128]> = OnceCell::new();
/// Length of compatible string stored in DTB_COMPATIBLE_NAME
static DTB_COMPATIBLE_NAME_LEN: OnceCell<usize> = OnceCell::new();

/// Parse DTB and create platform configuration
pub fn parse_dtb(boot_info: &'static BootInfo) -> Result<DtbPlatform, DtbError> {
    let dtb_phys = boot_info.dtb_address.as_u64();
    if dtb_phys == 0 {
        return Err(DtbError::NoDtbAddress);
    }

    // Convert physical to virtual using direct physmap
    let dtb_virt = (KERNEL_PHYS_MAP_BASE + dtb_phys) as *const u8;

    // SAFETY: DTB virtual address is within kernel's direct physical map,
    // which is set up by the bootloader to map all physical memory.
    let dtb_slice = unsafe {
        core::slice::from_raw_parts(dtb_virt, DTB_MAX_SIZE)
    };

    // Parse DTB with fdt crate
    let fdt = Fdt::new(dtb_slice).map_err(|_| DtbError::InvalidDtb)?;

    // Store parsed FDT for later access (e.g., by device manager)
    // SAFETY: We're storing a reference to the FDT which lives in the bootloader's
    // memory that is never deallocated. The 'static lifetime is appropriate here.
    let _ = unsafe {
        let fdt_static: &'static Fdt<'static> = core::mem::transmute(&fdt);
        PARSED_DTB.set(fdt_static)
    };

    // Extract configuration from DTB
    let (gic_dist, gic_cpu, gic_redist, gic_version) = parse_gic(&fdt)?;
    let uart_base = parse_uart(&fdt)?;
    let (ram_base, ram_size) = parse_memory(&fdt)?;
    let timer_irq = parse_timer(&fdt)?;
    let name = parse_platform_name(&fdt)?;
    let smmu_config = parse_smmu(&fdt);
    let cpu_count = parse_cpu_count(&fdt);

    Ok(DtbPlatform {
        name,
        gic_distributor_base: gic_dist,
        gic_cpu_base: gic_cpu,
        gic_redistributor_base: gic_redist,
        gic_version,
        timer_irq,
        uart_base,
        uart_type: UartType::Pl011,
        ram_base,
        ram_size,
        smmu_config,
        cpu_count,
    })
}

/// Get the parsed DTB for later use (e.g., by device manager)
pub fn get_parsed_dtb() -> Option<&'static Fdt<'static>> {
    PARSED_DTB.get().copied()
}

/// Parse GIC distributor address from FDT
///
/// This is a public utility function that can be used by the bootloader
/// and other components that need to extract GIC address from DTB.
pub fn parse_gic_address(fdt: &Fdt) -> Result<u64, DtbError> {
    let (gic_dist, _cpu, _redist, _version) = parse_gic(fdt)?;
    Ok(gic_dist)
}

/// Parse UART base address from FDT
///
/// This is a public utility function that can be used by the bootloader
/// and other components that need to extract UART address from DTB.
pub fn parse_uart_address(fdt: &Fdt) -> Result<u64, DtbError> {
    parse_uart(fdt)
}

/// Parse GIC and UART addresses from raw DTB slice
///
/// This is a convenience function for the bootloader that takes a raw DTB
/// slice and returns both GIC and UART addresses.
///
/// Returns (gic_address, uart_address)
pub fn parse_mmio_from_slice(dtb_slice: &[u8]) -> Result<(u64, u64), DtbError> {
    let fdt = Fdt::new(dtb_slice).map_err(|_| DtbError::InvalidDtb)?;

    let gic = parse_gic_address(&fdt)?;
    let uart = parse_uart_address(&fdt)?;

    Ok((gic, uart))
}

/// Parse GIC (Generic Interrupt Controller) configuration
///
/// Returns (distributor_base, cpu_base, redistributor_base, gic_version)
fn parse_gic(fdt: &Fdt) -> Result<(u64, u64, u64, GicVersion), DtbError> {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible() {
            // Check for GICv3
            if compatible.all().any(|c| c == "arm,gic-v3") {
                let mut reg = node.reg().ok_or(DtbError::MissingProperty("reg"))?;
                let dist = reg.next().ok_or(DtbError::InvalidData)?;
                let redist = reg.next().ok_or(DtbError::InvalidData)?;
                return Ok((
                    dist.starting_address as u64,
                    0, // No CPU interface in GICv3
                    redist.starting_address as u64,
                    GicVersion::V3,
                ));
            }

            // Check for GICv2
            if compatible.all().any(|c| {
                c.contains("cortex") && c.contains("gic") && !c.contains("gic-v3")
            }) {
                let mut reg = node.reg().ok_or(DtbError::MissingProperty("reg"))?;
                let dist = reg.next().ok_or(DtbError::InvalidData)?;
                let cpu = reg.next().ok_or(DtbError::InvalidData)?;
                return Ok((
                    dist.starting_address as u64,
                    cpu.starting_address as u64,
                    0, // No redistributor in GICv2
                    GicVersion::V2,
                ));
            }
        }
    }
    Err(DtbError::MissingNode("gic"))
}

/// Parse UART (serial console) configuration
fn parse_uart(fdt: &Fdt) -> Result<u64, DtbError> {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible()
            && compatible.all().any(|c| c == "arm,pl011")
        {
            let reg = node.reg()
                .ok_or(DtbError::MissingProperty("reg"))?
                .next()
                .ok_or(DtbError::InvalidData)?;
            return Ok(reg.starting_address as u64);
        }
    }
    Err(DtbError::MissingNode("uart"))
}

/// Parse memory configuration
///
/// Returns (base_address, size)
fn parse_memory(fdt: &Fdt) -> Result<(u64, u64), DtbError> {
    for node in fdt.all_nodes() {
        if node.name.starts_with("memory") {
            let reg = node.reg()
                .ok_or(DtbError::MissingProperty("reg"))?
                .next()
                .ok_or(DtbError::InvalidData)?;
            let size = reg.size.ok_or(DtbError::InvalidData)?;
            return Ok((reg.starting_address as u64, size as u64));
        }
    }
    Err(DtbError::MissingNode("memory"))
}

/// Parse timer configuration
fn parse_timer(fdt: &Fdt) -> Result<u32, DtbError> {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible()
            && compatible.all().any(|c| c == "arm,armv8-timer")
        {
            // ARM timer interrupts property contains multiple IRQs
            // Format: [secure_phys_irq, phys_irq, virt_irq, hyp_irq]
            // We typically want the virtual timer (index 2)
            if let Some(mut interrupts) = node.interrupts() {
                // Skip to virtual timer interrupt (3rd entry, index 2)
                let virt_irq = interrupts.nth(2)
                    .ok_or(DtbError::InvalidData)? as u32;
                return Ok(virt_irq);
            }
        }
    }

    // Default to 27 if not found (standard ARM virtual timer PPI)
    Ok(27)
}

/// Parse platform name/identification
fn parse_platform_name(fdt: &Fdt) -> Result<&'static str, DtbError> {
    let root = fdt.root();

    // Try to get model string first
    let model = root.model();
    if !model.is_empty() {
        // Store in static buffer
        let mut name_buf = [0u8; 128];
        let bytes = model.as_bytes();
        let len = bytes.len().min(127);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let _ = DTB_PLATFORM_NAME.set(name_buf);
        let _ = DTB_PLATFORM_NAME_LEN.set(len);

        // Return reference to static storage
        if let (Some(stored), Some(len)) = (DTB_PLATFORM_NAME.get(), DTB_PLATFORM_NAME_LEN.get()) {
            let s = core::str::from_utf8(&stored[..*len])
                .unwrap_or("Unknown DTB Platform");
            // SAFETY: This is pointing to static storage that lives for 'static
            return Ok(unsafe { core::mem::transmute::<&str, &str>(s) });
        }
    }

    // Fallback to compatible string (need to store in static buffer due to lifetime)
    let compatible = root.compatible();
    if let Some(first) = compatible.all().next() {
        // Store in static buffer
        let mut compat_buf = [0u8; 128];
        let bytes = first.as_bytes();
        let len = bytes.len().min(127);
        compat_buf[..len].copy_from_slice(&bytes[..len]);

        let _ = DTB_COMPATIBLE_NAME.set(compat_buf);
        let _ = DTB_COMPATIBLE_NAME_LEN.set(len);

        // Return reference to static storage
        if let (Some(stored), Some(len)) = (DTB_COMPATIBLE_NAME.get(), DTB_COMPATIBLE_NAME_LEN.get()) {
            let s = core::str::from_utf8(&stored[..*len])
                .unwrap_or("Unknown DTB Platform");
            // SAFETY: This is pointing to static storage that lives for 'static
            return Ok(unsafe { core::mem::transmute::<&str, &str>(s) });
        }
    }

    Ok("Unknown Platform")
}

/// Parse CPU count from DTB /cpus node
///
/// Counts the number of CPU nodes under /cpus with device_type = "cpu".
/// Returns 1 if no CPUs are found (single-CPU fallback).
pub fn parse_cpu_count(fdt: &Fdt) -> u32 {
    let mut count = 0u32;

    for node in fdt.all_nodes() {
        // CPU nodes are typically named "cpu@N" under /cpus
        if node.name.starts_with("cpu@") || node.name == "cpu" {
            // Verify it's actually a CPU by checking device_type
            if let Some(device_type) = node.property("device_type") {
                if device_type.as_str() == Some("cpu") {
                    count += 1;
                }
            } else {
                // Some DTBs don't have device_type, assume it's a CPU if under /cpus
                count += 1;
            }
        }
    }

    // Ensure at least 1 CPU
    if count == 0 { 1 } else { count }
}

/// Parse CPU count from raw DTB slice
///
/// Convenience function for the bootloader.
pub fn parse_cpu_count_from_slice(dtb_slice: &[u8]) -> Result<u32, DtbError> {
    let fdt = Fdt::new(dtb_slice).map_err(|_| DtbError::InvalidDtb)?;
    Ok(parse_cpu_count(&fdt))
}

/// Parse SMMU (System Memory Management Unit) configuration
///
/// Returns Some(SmmuConfig) if an SMMUv3 is found, None otherwise.
/// SMMU is optional - the system can run without it (but userspace drivers
/// will be disabled for security).
fn parse_smmu(fdt: &Fdt) -> Option<SmmuConfig> {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible() {
            // Check for ARM SMMUv3
            if compatible.all().any(|c| c == "arm,smmu-v3") {
                let reg = node.reg()?.next()?;
                let base_addr = reg.starting_address as u64;
                let size = reg.size.unwrap_or(0x20000) as u64;

                // Parse interrupts (SMMUv3 typically has: eventq, gerror, cmdq-sync)
                // The interrupt property format depends on the interrupt controller
                let mut event_irq = 0u32;
                let mut gerror_irq = 0u32;
                let mut cmdq_sync_irq = 0u32;

                if let Some(mut interrupts) = node.interrupts() {
                    if let Some(irq) = interrupts.next() {
                        event_irq = irq as u32;
                    }
                    if let Some(irq) = interrupts.next() {
                        gerror_irq = irq as u32;
                    }
                    if let Some(irq) = interrupts.next() {
                        cmdq_sync_irq = irq as u32;
                    }
                }

                return Some(SmmuConfig {
                    base_addr,
                    size,
                    event_irq,
                    gerror_irq,
                    cmdq_sync_irq,
                });
            }
        }
    }
    None
}
