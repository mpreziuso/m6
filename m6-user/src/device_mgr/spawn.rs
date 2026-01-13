//! Driver process spawning with capability construction.
//!
//! This module handles creating driver processes with the appropriate
//! capabilities for their device (MMIO access, IRQ, IOSpace for DMA).

use m6_cap::ObjectType;
use m6_syscall::{error::SyscallError, invoke::*, slot_to_cptr};

use crate::registry::{DeviceEntry, DriverEntry, Registry};
use crate::manifest::DriverManifest;
use crate::slots;

// Re-use ELF parser from parent
#[path = "../elf.rs"]
mod elf;

use elf::{Elf64, ElfError};

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Error codes for driver spawning
#[derive(Debug, Clone, Copy)]
pub enum SpawnError {
    /// Invalid ELF binary
    InvalidElf(ElfError),
    /// Not enough untyped memory
    OutOfMemory,
    /// Failed to retype untyped memory
    RetypeFailed(SyscallError),
    /// Failed to assign ASID
    AsidAssignFailed(SyscallError),
    /// Failed to configure TCB
    TcbConfigureFailed(SyscallError),
    /// Failed to write TCB registers
    TcbWriteRegistersFailed(SyscallError),
    /// Failed to resume TCB
    TcbResumeFailed(SyscallError),
    /// Failed to map frame
    FrameMapFailed(SyscallError),
    /// Failed to copy capability
    CapCopyFailed(SyscallError),
    /// Failed to claim IRQ
    IrqClaimFailed(SyscallError),
    /// No free slots available
    NoSlots,
    /// Driver not found in initrd
    DriverNotFound,
    /// Too many drivers
    TooManyDrivers,
    /// No device untyped capability covers the required address
    DeviceUntypedNotFound,
}

impl From<ElfError> for SpawnError {
    fn from(e: ElfError) -> Self {
        Self::InvalidElf(e)
    }
}

/// Device information needed for spawning (copied to avoid borrow issues)
#[derive(Clone)]
pub struct DeviceInfo {
    /// Physical base address
    pub phys_base: u64,
    /// Size of MMIO region
    pub size: u64,
    /// IRQ number
    pub irq: u32,
    /// Stream ID for IOMMU/SMMU (None if device doesn't have one, e.g. VirtIO MMIO)
    pub stream_id: Option<u32>,
}

impl DeviceInfo {
    /// Create from a DeviceEntry
    pub fn from_entry(entry: &DeviceEntry) -> Self {
        Self {
            phys_base: entry.phys_base,
            size: entry.size,
            irq: entry.irq,
            // VirtIO MMIO devices typically don't have stream IDs
            // PCIe devices would extract this from device tree "iommu-map" property
            stream_id: None,
        }
    }
}

/// Configuration for spawning a driver
pub struct DriverSpawnConfig<'a> {
    /// ELF binary data
    pub elf_data: &'a [u8],
    /// Device information (copied)
    pub device_info: DeviceInfo,
    /// Device index in registry
    pub device_idx: usize,
    /// Driver manifest entry
    pub manifest: &'a DriverManifest,
    /// Optional console endpoint slot to copy to driver (for IPC console)
    pub console_ep_slot: Option<u64>,
}

/// Result of successful driver spawn
pub struct DriverSpawnResult {
    /// TCB capability slot
    pub tcb_slot: u64,
    /// VSpace capability slot
    pub vspace_slot: u64,
    /// CSpace capability slot
    pub cspace_slot: u64,
    /// Driver's service endpoint slot
    pub endpoint_slot: u64,
    /// Driver index in registry
    pub driver_idx: usize,
}

/// Memory mapping rights
#[derive(Debug, Clone, Copy)]
pub struct MapRights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MapRights {
    pub const R: Self = Self { read: true, write: false, execute: false };
    pub const RW: Self = Self { read: true, write: true, execute: false };
    pub const RX: Self = Self { read: true, write: false, execute: true };

    pub fn to_bits(self) -> u64 {
        let mut bits = 0u64;
        if self.read { bits |= 1; }
        if self.write { bits |= 2; }
        if self.execute { bits |= 4; }
        bits
    }
}

/// Spawn a driver process.
///
/// This creates:
/// 1. VSpace with ELF loaded
/// 2. CSpace with initial capabilities
/// 3. TCB configured and running
///
/// Initial capabilities granted to driver:
/// - Slot 0: Root CNode (self-reference)
/// - Slot 1: Root TCB
/// - Slot 2: Root VSpace
/// - Slot 10: DeviceFrame for MMIO region
/// - Slot 11: IRQHandler (if needed)
/// - Slot 12: Service endpoint (for clients)
/// - Slot 13: IOSpace (if needed)
pub fn spawn_driver(
    config: &DriverSpawnConfig,
    registry: &mut Registry,
) -> Result<DriverSpawnResult, SpawnError> {
    // Get CNode radix for CPtr conversion
    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };
    let cptr = |slot: u64| slot_to_cptr(slot, boot_info.cnode_radix);

    // Parse ELF binary
    let elf = Elf64::parse(config.elf_data)?;

    // Allocate capability slots in device-mgr's CSpace
    let vspace_slot = registry.alloc_slot();
    let cspace_slot = registry.alloc_slot();
    let tcb_slot = registry.alloc_slot();
    let ipc_buf_slot = registry.alloc_slot();
    let driver_ep_slot = registry.alloc_slot();
    let fault_ep_slot = registry.alloc_slot();

    // Optionally allocate device-specific slots
    let device_frame_slot = registry.alloc_slot();
    let irq_handler_slot = if config.manifest.needs_irq && config.device_info.irq != 0 {
        Some(registry.alloc_slot())
    } else {
        None
    };
    // Allocate notification for IRQ delivery if driver needs IRQ
    let irq_notif_slot = if config.manifest.needs_irq && config.device_info.irq != 0 {
        Some(registry.alloc_slot())
    } else {
        None
    };
    let iospace_slot = if config.manifest.needs_iommu {
        Some(registry.alloc_slot())
    } else {
        None
    };
    // Note: SmmuControl is at device-mgr's slot 18, we don't allocate a new slot for it
    let has_smmu_control = config.manifest.needs_iommu;

    // Allocate DMA buffer frames for DMA-capable drivers (virtio, etc.)
    let dma_buffer_slots: Option<[u64; slots::driver::DMA_BUFFER_COUNT]> = if config.manifest.needs_iommu {
        let mut dma_slots = [0u64; slots::driver::DMA_BUFFER_COUNT];
        for slot in &mut dma_slots {
            *slot = registry.alloc_slot();
        }
        Some(dma_slots)
    } else {
        None
    };

    // Create VSpace (page table root)
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::VSpace as u64,
        0,
        cptr(slots::ROOT_CNODE),
        vspace_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    asid_pool_assign(cptr(slots::ASID_POOL), cptr(vspace_slot))
        .map_err(SpawnError::AsidAssignFailed)?;

    // Create CSpace (radix 10 = 1024 slots for drivers)
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::CNode as u64,
        10, // radix
        cptr(slots::ROOT_CNODE),
        cspace_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create TCB
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::TCB as u64,
        0,
        cptr(slots::ROOT_CNODE),
        tcb_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create IPC buffer frame
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Frame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        ipc_buf_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create driver's service endpoint
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Endpoint as u64,
        0,
        cptr(slots::ROOT_CNODE),
        driver_ep_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create fault endpoint for death detection
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Endpoint as u64,
        0,
        cptr(slots::ROOT_CNODE),
        fault_ep_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create DeviceFrame for MMIO region
    // Note: For VirtIO devices, this reuses the probe frame created during enumeration.
    // For other devices, this retypes from the device untyped.
    create_device_frame(device_frame_slot, &config.device_info, registry, &cptr)?;

    // Claim IRQ handler if needed
    if let Some(irq_slot) = irq_handler_slot {
        claim_irq(irq_slot, config.device_info.irq, &cptr)?;
    }

    // Create notification for IRQ delivery if needed
    if let Some(notif_slot) = irq_notif_slot {
        retype(
            cptr(slots::RAM_UNTYPED),
            ObjectType::Notification as u64,
            0,
            cptr(slots::ROOT_CNODE),
            notif_slot,
            1,
        ).map_err(SpawnError::RetypeFailed)?;
    }

    // Create IOSpace if needed (track whether it was actually created)
    let iospace_created = if let Some(io_slot) = iospace_slot {
        let smmu_slot = if has_smmu_control {
            Some(slots::SMMU_CONTROL)
        } else {
            None
        };
        create_iospace(io_slot, smmu_slot, config.device_info.stream_id, &cptr)?
    } else {
        false
    };
    // Only pass iospace_slot to install_driver_caps if it was actually created
    let effective_iospace_slot = if iospace_created { iospace_slot } else { None };

    // Create DMA buffer frames for DMA-capable drivers
    if let Some(ref dma_slots) = dma_buffer_slots {
        for &slot in dma_slots {
            retype(
                cptr(slots::RAM_UNTYPED),
                ObjectType::Frame as u64,
                12, // 4KB
                cptr(slots::ROOT_CNODE),
                slot,
                1,
            ).map_err(SpawnError::RetypeFailed)?;
        }
    }

    // Create DmaPool and map DMA buffers into IOSpace if IOSpace was created
    let dma_pool_slot = if let (true, Some(iospace), Some(dma_slots)) =
        (iospace_created, iospace_slot, dma_buffer_slots.as_ref())
    {
        let pool_slot = registry.alloc_slot();

        // Create DmaPool with IOVA range starting at 256MB
        const IOVA_BASE: u64 = 0x1000_0000;  // 256MB
        const IOVA_SIZE: u64 = 0x0100_0000;  // 16MB pool

        dma_pool_create(
            cptr(iospace),
            IOVA_BASE,
            IOVA_SIZE,
            cptr(slots::ROOT_CNODE),
            pool_slot,
            0,  // depth = 0 (auto)
        ).map_err(SpawnError::RetypeFailed)?;

        // Map DMA buffer frames into IOSpace at sequential IOVAs
        let mut iova = IOVA_BASE;
        for &slot in dma_slots {
            iospace_map_frame(
                cptr(iospace),
                cptr(slot),
                iova,
                3,  // RW access
            ).map_err(SpawnError::CapCopyFailed)?;
            iova += PAGE_SIZE as u64;
        }

        Some(pool_slot)
    } else {
        None
    };

    // Load ELF and create stack
    let entry = elf.entry();
    let stack_top = load_elf_and_stack(vspace_slot, &elf, config.elf_data, registry, &cptr)?;

    // Map IPC buffer - ensure page tables exist first
    const IPC_BUFFER_ADDR: u64 = m6_syscall::IPC_BUFFER_ADDR;
    ensure_page_tables(vspace_slot, IPC_BUFFER_ADDR, IPC_BUFFER_ADDR + PAGE_SIZE as u64, registry, &cptr)?;
    map_frame(cptr(vspace_slot), cptr(ipc_buf_slot), IPC_BUFFER_ADDR, MapRights::RW.to_bits(), 0)
        .map_err(SpawnError::FrameMapFailed)?;

    // Ensure page tables exist for the MMIO region so driver can map its DeviceFrame
    // Drivers use a standard MMIO address range starting at 0x8000_0000 (2GB)
    const MMIO_VADDR: u64 = 0x0000_8000_0000;
    ensure_page_tables(vspace_slot, MMIO_VADDR, MMIO_VADDR + PAGE_SIZE as u64, registry, &cptr)?;

    // Ensure page tables exist for DMA buffer region (0x8001_0000 onwards)
    // and map DMA buffer frames for DMA-capable drivers
    if let Some(ref dma_slots) = dma_buffer_slots {
        const DMA_BUFFER_VADDR: u64 = 0x0000_8001_0000;
        let dma_region_size = (slots::driver::DMA_BUFFER_COUNT * PAGE_SIZE) as u64;
        ensure_page_tables(vspace_slot, DMA_BUFFER_VADDR, DMA_BUFFER_VADDR + dma_region_size, registry, &cptr)?;

        // Map each DMA buffer frame into driver's VSpace
        for (i, &slot) in dma_slots.iter().enumerate() {
            let vaddr = DMA_BUFFER_VADDR + (i * PAGE_SIZE) as u64;
            map_frame(cptr(vspace_slot), cptr(slot), vaddr, MapRights::RW.to_bits(), 0)
                .map_err(SpawnError::FrameMapFailed)?;
        }
    }

    // Install initial capabilities in driver's CSpace
    let smmu_to_copy = if has_smmu_control {
        Some(slots::SMMU_CONTROL)
    } else {
        None
    };

    install_driver_caps(
        cptr(cspace_slot),           // dest cspace CPtr
        cptr(slots::ROOT_CNODE),     // src cnode CPtr
        cspace_slot,                  // cspace slot number
        vspace_slot,                  // vspace slot number
        tcb_slot,                     // tcb slot number
        driver_ep_slot,               // endpoint slot number
        device_frame_slot,            // device frame slot number
        irq_handler_slot,             // optional irq handler slot
        irq_notif_slot,               // optional notification for IRQ delivery
        effective_iospace_slot,       // optional iospace slot (only if actually created)
        smmu_to_copy,                 // optional smmu control slot
        dma_pool_slot,                // optional DMA pool slot
        config.console_ep_slot,       // optional console endpoint slot
        dma_buffer_slots.as_ref(),    // optional DMA buffer frame slots
    )?;

    // Calculate fault badge for this driver
    let driver_idx = registry.driver_count;
    let fault_badge = crate::ipc::badge::fault_badge_for_driver(driver_idx as u32);

    // Configure TCB with fault endpoint
    tcb_configure(
        cptr(tcb_slot),
        cptr(fault_ep_slot),
        cptr(cspace_slot),
        cptr(vspace_slot),
        IPC_BUFFER_ADDR,
        cptr(ipc_buf_slot),
    ).map_err(SpawnError::TcbConfigureFailed)?;

    // Set initial registers
    // Pass device offset within page as arg0 (x0 register)
    // This allows drivers to find their MMIO registers when devices aren't page-aligned
    let device_offset = config.device_info.phys_base & 0xFFF;
    tcb_write_registers(cptr(tcb_slot), entry, stack_top, device_offset)
        .map_err(SpawnError::TcbWriteRegistersFailed)?;

    // Resume the driver
    tcb_resume(cptr(tcb_slot)).map_err(SpawnError::TcbResumeFailed)?;

    // Add driver to registry
    let driver_entry = DriverEntry {
        tcb_slot,
        vspace_slot,
        cspace_slot,
        endpoint_slot: driver_ep_slot,
        device_indices: {
            let mut indices = [usize::MAX; 4];
            indices[0] = config.device_idx;
            indices
        },
        device_count: 1,
        alive: true,
        fault_badge,
    };

    registry.add_driver(driver_entry)
        .ok_or(SpawnError::TooManyDrivers)?;

    Ok(DriverSpawnResult {
        tcb_slot,
        vspace_slot,
        cspace_slot,
        endpoint_slot: driver_ep_slot,
        driver_idx,
    })
}

/// Create a DeviceFrame for the device's MMIO region.
///
/// First checks if we have an existing probe frame for this physical address
/// (from VirtIO probing). If so, uses cap_copy to reuse it. Otherwise falls
/// back to retyping from the device untyped.
fn create_device_frame(
    slot: u64,
    device_info: &DeviceInfo,
    registry: &Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<(), SpawnError> {
    // Check if we have an existing probe frame for this physical address.
    // This is the case for VirtIO devices that were probed during enumeration.
    if let Some(probe_slot) = registry.find_virtio_probe_frame(device_info.phys_base) {
        // Reuse the probe frame via cap_copy
        let cnode_cptr = cptr(slots::ROOT_CNODE);
        cap_copy(cnode_cptr, slot, 0, cnode_cptr, probe_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
        return Ok(());
    }

    // No existing probe frame - retype from device untyped
    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };

    // Find the device untyped that covers this physical address
    let (device_untyped_slot, _size) = boot_info
        .find_device_untyped(device_info.phys_base)
        .ok_or(SpawnError::DeviceUntypedNotFound)?;

    // Retype the device untyped to DeviceFrame
    // DeviceFrame size is always 4KB (size_bits = 12)
    retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    Ok(())
}

/// Claim an IRQ handler from IRQControl.
///
/// Creates an IRQHandler capability for the specified hardware IRQ and
/// places it in the given slot.
fn claim_irq(slot: u64, irq: u32, cptr: &impl Fn(u64) -> u64) -> Result<(), SpawnError> {
    irq_control_get(
        cptr(slots::IRQ_CONTROL),
        irq,
        cptr(slots::ROOT_CNODE),
        slot,
        0,
    ).map_err(SpawnError::IrqClaimFailed)?;
    Ok(())
}

/// Create an IOSpace for DMA.
///
/// Creates an IOSpace object using SmmuControl and untyped memory.
/// The IOSpace provides IOMMU translation for device DMA.
/// Optionally binds a stream ID if the device has one.
///
/// Returns `Ok(true)` if IOSpace was created successfully.
fn create_iospace(
    slot: u64,
    smmu_control_slot: Option<u64>,
    stream_id: Option<u32>,
    cptr: &impl Fn(u64) -> u64,
) -> Result<bool, SpawnError> {
    // Check if we have SmmuControl capability
    let smmu_slot = match smmu_control_slot {
        Some(s) => s,
        None => return Ok(false),  // No SMMU support
    };

    // Create IOSpace from SmmuControl + untyped memory
    iospace_create(
        cptr(smmu_slot),
        cptr(slots::RAM_UNTYPED),
        cptr(slots::ROOT_CNODE),
        slot,
        0,  // depth = 0 (auto)
    ).map_err(SpawnError::RetypeFailed)?;

    // Bind stream ID if device has one
    // VirtIO MMIO devices typically don't have stream IDs and operate in bypass mode
    // PCIe devices with stream IDs will have IOMMU translation enabled
    if let Some(sid) = stream_id {
        iospace_bind_stream(
            cptr(slot),
            cptr(smmu_slot),
            sid,
        ).map_err(SpawnError::CapCopyFailed)?;
    }

    Ok(true)
}

/// Ensure page tables exist for an address range in a VSpace.
fn ensure_page_tables(
    vspace_slot: u64,
    vaddr_start: u64,
    vaddr_end: u64,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<(), SpawnError> {
    const L1_SIZE: u64 = 512 * 1024 * 1024 * 1024; // 512GB
    const L2_SIZE: u64 = 1024 * 1024 * 1024;       // 1GB
    const L3_SIZE: u64 = 2 * 1024 * 1024;          // 2MB

    let l1_base = vaddr_start & !(L1_SIZE - 1);
    let l2_base = vaddr_start & !(L2_SIZE - 1);
    let l3_base = vaddr_start & !(L3_SIZE - 1);

    // Create L1 table (level 1)
    let l1_slot = registry.alloc_slot();
    retype(cptr(slots::RAM_UNTYPED), 5, 0, cptr(slots::ROOT_CNODE), l1_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l1_slot), l1_base, 1);

    // Create L2 table (level 2)
    let l2_slot = registry.alloc_slot();
    retype(cptr(slots::RAM_UNTYPED), 6, 0, cptr(slots::ROOT_CNODE), l2_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l2_slot), l2_base, 2);

    // Create L3 table (level 3)
    let l3_slot = registry.alloc_slot();
    retype(cptr(slots::RAM_UNTYPED), 7, 0, cptr(slots::ROOT_CNODE), l3_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l3_slot), l3_base, 3);

    // Handle case where end address is in a different L3 region
    let l3_end_base = (vaddr_end - 1) & !(L3_SIZE - 1);
    if l3_end_base != l3_base {
        let l3_slot2 = registry.alloc_slot();
        retype(cptr(slots::RAM_UNTYPED), 7, 0, cptr(slots::ROOT_CNODE), l3_slot2, 1)
            .map_err(SpawnError::RetypeFailed)?;
        let _ = map_page_table(cptr(vspace_slot), cptr(l3_slot2), l3_end_base, 3);
    }

    Ok(())
}

/// Load ELF segments and create stack.
fn load_elf_and_stack(
    vspace: u64,
    elf: &Elf64,
    _elf_data: &[u8],
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<u64, SpawnError> {
    // Ensure page tables exist for ELF segments
    for segment in elf.segments() {
        if segment.mem_size > 0 {
            let vaddr_start = segment.vaddr;
            let vaddr_end = segment.vaddr + segment.mem_size;
            ensure_page_tables(vspace, vaddr_start, vaddr_end, registry, &cptr)?;
        }
    }

    // Ensure page tables exist for stack region
    let stack_pages = 16;
    let stack_top = 0x0000_7FFF_F000u64;
    let stack_base = stack_top - (stack_pages * PAGE_SIZE) as u64;
    ensure_page_tables(vspace, stack_base, stack_top, registry, &cptr)?;

    // Map ELF segments
    for segment in elf.segments() {
        let rights = if segment.executable {
            MapRights::RX
        } else if segment.writable {
            MapRights::RW
        } else {
            MapRights::R
        };

        if let Some(data) = elf.segment_data(&segment) {
            map_segment(vspace, segment.vaddr, segment.mem_size, data, rights, registry, &cptr)?;
        }
    }

    // Create stack frames
    for i in 0..stack_pages {
        let page_vaddr = stack_base + (i * PAGE_SIZE) as u64;
        let frame_slot = alloc_frame(registry, &cptr)?;
        map_frame(cptr(vspace), cptr(frame_slot), page_vaddr, MapRights::RW.to_bits(), 0)
            .map_err(SpawnError::FrameMapFailed)?;
    }

    Ok(stack_top)
}

/// Map a memory segment using frame_write syscall (no temporary mapping needed).
fn map_segment(
    vspace_slot: u64,
    vaddr: u64,
    size: u64,
    data: &[u8],
    rights: MapRights,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<(), SpawnError> {
    let vaddr_start = vaddr & !(PAGE_SIZE as u64 - 1);
    let vaddr_end = (vaddr + size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let num_pages = ((vaddr_end - vaddr_start) / PAGE_SIZE as u64) as usize;

    let data_offset = (vaddr - vaddr_start) as usize;

    // Static zero buffer for zeroing pages
    static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];

    for i in 0..num_pages {
        let page_vaddr = vaddr_start + (i * PAGE_SIZE) as u64;
        let frame_slot = alloc_frame(registry, &cptr)?;

        // Calculate data range for this page
        let page_data_start = if i == 0 { 0 } else { i * PAGE_SIZE - data_offset };
        let page_data_end = core::cmp::min(page_data_start + PAGE_SIZE, data.len());

        // Use frame_write syscall to write data directly to the frame
        if page_data_start < data.len() {
            if i == 0 {
                // First page: may need leading zeros and data starting at offset
                let copy_len = core::cmp::min(PAGE_SIZE - data_offset, data.len());

                // Zero the page first (before the data)
                if data_offset > 0 {
                    frame_write(cptr(frame_slot), 0, ZEROS.as_ptr(), data_offset)
                        .map_err(SpawnError::FrameMapFailed)?;
                }

                // Write the actual data
                frame_write(cptr(frame_slot), data_offset as u64, data.as_ptr(), copy_len)
                    .map_err(SpawnError::FrameMapFailed)?;

                // Zero remainder if needed
                let remainder_start = data_offset + copy_len;
                if remainder_start < PAGE_SIZE {
                    frame_write(cptr(frame_slot), remainder_start as u64, ZEROS.as_ptr(), PAGE_SIZE - remainder_start)
                        .map_err(SpawnError::FrameMapFailed)?;
                }
            } else if page_data_start < page_data_end {
                // Subsequent pages with data
                let copy_len = page_data_end - page_data_start;
                frame_write(cptr(frame_slot), 0, data[page_data_start..].as_ptr(), copy_len)
                    .map_err(SpawnError::FrameMapFailed)?;

                // Zero remainder if partial page
                if copy_len < PAGE_SIZE {
                    frame_write(cptr(frame_slot), copy_len as u64, ZEROS.as_ptr(), PAGE_SIZE - copy_len)
                        .map_err(SpawnError::FrameMapFailed)?;
                }
            }
        } else {
            // No data for this page - just zero it
            frame_write(cptr(frame_slot), 0, ZEROS.as_ptr(), PAGE_SIZE)
                .map_err(SpawnError::FrameMapFailed)?;
        }

        // Map frame into driver's VSpace
        map_frame(cptr(vspace_slot), cptr(frame_slot), page_vaddr, rights.to_bits(), 0)
            .map_err(SpawnError::FrameMapFailed)?;
    }

    Ok(())
}

/// Allocate a frame.
fn alloc_frame(registry: &mut Registry, cptr: &impl Fn(u64) -> u64) -> Result<u64, SpawnError> {
    let slot = registry.alloc_slot();
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Frame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;
    Ok(slot)
}

/// Install initial capabilities into driver's CSpace.
///
/// Parameters:
/// - child_cspace_cptr: CPtr of the child's CSpace (destination)
/// - src_cnode_cptr: CPtr of device-mgr's root CNode (source)
/// - vspace_slot, tcb_slot, etc.: raw slot numbers in source CNode
#[allow(clippy::too_many_arguments)]
fn install_driver_caps(
    child_cspace_cptr: u64,
    src_cnode_cptr: u64,
    cspace_slot: u64,
    vspace_slot: u64,
    tcb_slot: u64,
    endpoint_slot: u64,
    device_frame_slot: u64,
    irq_handler_slot: Option<u64>,
    irq_notif_slot: Option<u64>,
    iospace_slot: Option<u64>,
    smmu_control_slot: Option<u64>,
    dma_pool_slot: Option<u64>,
    console_ep_slot: Option<u64>,
    dma_buffer_slots: Option<&[u64; slots::driver::DMA_BUFFER_COUNT]>,
) -> Result<(), SpawnError> {
    // Slot 0: CSpace self-reference
    cap_copy(child_cspace_cptr, slots::driver::ROOT_CNODE, 0, src_cnode_cptr, cspace_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 1: TCB
    cap_copy(child_cspace_cptr, slots::driver::ROOT_TCB, 0, src_cnode_cptr, tcb_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 2: VSpace
    cap_copy(child_cspace_cptr, slots::driver::ROOT_VSPACE, 0, src_cnode_cptr, vspace_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 10: DeviceFrame
    cap_copy(child_cspace_cptr, slots::driver::DEVICE_FRAME, 0, src_cnode_cptr, device_frame_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 11: IRQHandler (if present)
    if let Some(irq_slot) = irq_handler_slot {
        cap_copy(child_cspace_cptr, slots::driver::IRQ_HANDLER, 0, src_cnode_cptr, irq_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 14: Notification for IRQ delivery (if present)
    if let Some(notif_slot) = irq_notif_slot {
        cap_copy(child_cspace_cptr, slots::driver::NOTIF, 0, src_cnode_cptr, notif_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 12: Service endpoint
    cap_copy(child_cspace_cptr, slots::driver::SERVICE_EP, 0, src_cnode_cptr, endpoint_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 13: IOSpace (if present)
    if let Some(io_slot) = iospace_slot {
        cap_copy(child_cspace_cptr, slots::driver::IOSPACE, 0, src_cnode_cptr, io_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 15: SmmuControl (if present, for DMA-capable drivers)
    if let Some(_smmu_slot) = smmu_control_slot {
        cap_copy(child_cspace_cptr, slots::driver::SMMU_CONTROL, 0, src_cnode_cptr, slots::SMMU_CONTROL, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 16: DmaPool (if present, for IOVA allocation)
    if let Some(pool_slot) = dma_pool_slot {
        cap_copy(child_cspace_cptr, slots::driver::DMA_POOL, 0, src_cnode_cptr, pool_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 20: Console endpoint (if present, for IPC-based output)
    if let Some(console_slot) = console_ep_slot {
        cap_copy(child_cspace_cptr, slots::driver::CONSOLE_EP, 0, src_cnode_cptr, console_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slots 21-28: DMA buffer frames (if present, for DMA-capable drivers)
    if let Some(dma_slots) = dma_buffer_slots {
        for (i, &slot) in dma_slots.iter().enumerate() {
            let dest_slot = slots::driver::DMA_BUFFER_START + i as u64;
            cap_copy(child_cspace_cptr, dest_slot, 0, src_cnode_cptr, slot, 0)
                .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    Ok(())
}
