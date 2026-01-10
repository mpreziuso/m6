//! Driver process spawning with capability construction.
//!
//! This module handles creating driver processes with the appropriate
//! capabilities for their device (MMIO access, IRQ, IOSpace for DMA).

use m6_cap::ObjectType;
use m6_syscall::{error::SyscallError, invoke::*};

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
}

impl DeviceInfo {
    /// Create from a DeviceEntry
    pub fn from_entry(entry: &DeviceEntry) -> Self {
        Self {
            phys_base: entry.phys_base,
            size: entry.size,
            irq: entry.irq,
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
    let iospace_slot = if config.manifest.needs_iommu {
        Some(registry.alloc_slot())
    } else {
        None
    };

    // Create VSpace (page table root)
    retype(
        slots::RAM_UNTYPED,
        ObjectType::VSpace as u64,
        0,
        slots::ROOT_CNODE,
        vspace_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Assign ASID to VSpace
    asid_pool_assign(slots::ASID_POOL, vspace_slot)
        .map_err(SpawnError::AsidAssignFailed)?;

    // Create CSpace (radix 10 = 1024 slots for drivers)
    retype(
        slots::RAM_UNTYPED,
        ObjectType::CNode as u64,
        10, // radix
        slots::ROOT_CNODE,
        cspace_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create TCB
    retype(
        slots::RAM_UNTYPED,
        ObjectType::TCB as u64,
        0,
        slots::ROOT_CNODE,
        tcb_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create IPC buffer frame
    retype(
        slots::RAM_UNTYPED,
        ObjectType::Frame as u64,
        12, // 4KB
        slots::ROOT_CNODE,
        ipc_buf_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create driver's service endpoint
    retype(
        slots::RAM_UNTYPED,
        ObjectType::Endpoint as u64,
        0,
        slots::ROOT_CNODE,
        driver_ep_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create fault endpoint for death detection
    retype(
        slots::RAM_UNTYPED,
        ObjectType::Endpoint as u64,
        0,
        slots::ROOT_CNODE,
        fault_ep_slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;

    // Create DeviceFrame for MMIO region
    // Note: In a full implementation, this would retype from device untyped
    // or use a kernel-provided device frame capability
    // For now, we create a placeholder
    create_device_frame(device_frame_slot, &config.device_info)?;

    // Claim IRQ handler if needed
    if let Some(irq_slot) = irq_handler_slot {
        claim_irq(irq_slot, config.device_info.irq)?;
    }

    // Create IOSpace if needed
    if let Some(io_slot) = iospace_slot {
        create_iospace(io_slot)?;
    }

    // Load ELF and create stack
    let entry = elf.entry();
    let stack_top = load_elf_and_stack(vspace_slot, &elf, config.elf_data, registry)?;

    // Map IPC buffer
    const IPC_BUFFER_ADDR: u64 = 0x0000_7FFF_F000_0000;
    map_frame(vspace_slot, ipc_buf_slot, IPC_BUFFER_ADDR, MapRights::RW.to_bits(), 0)
        .map_err(SpawnError::FrameMapFailed)?;

    // Install initial capabilities in driver's CSpace
    install_driver_caps(
        cspace_slot,
        vspace_slot,
        tcb_slot,
        driver_ep_slot,
        device_frame_slot,
        irq_handler_slot,
        iospace_slot,
    )?;

    // Calculate fault badge for this driver
    let driver_idx = registry.driver_count;
    let fault_badge = crate::ipc::badge::fault_badge_for_driver(driver_idx as u32);

    // Configure TCB with fault endpoint
    tcb_configure(
        tcb_slot,
        fault_ep_slot,
        cspace_slot,
        vspace_slot,
        IPC_BUFFER_ADDR,
        ipc_buf_slot,
    ).map_err(SpawnError::TcbConfigureFailed)?;

    // Set initial registers
    tcb_write_registers(tcb_slot, entry, stack_top, 0)
        .map_err(SpawnError::TcbWriteRegistersFailed)?;

    // Resume the driver
    tcb_resume(tcb_slot).map_err(SpawnError::TcbResumeFailed)?;

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
fn create_device_frame(slot: u64, device_info: &DeviceInfo) -> Result<(), SpawnError> {
    // In a full implementation:
    // 1. Find the untyped capability covering this physical region
    // 2. Retype to DeviceFrame
    // For now, this is a placeholder that assumes the capability exists
    // or would be provided by init

    // The device-mgr would need to have been given untyped caps
    // covering device MMIO regions, or init would provide pre-made
    // DeviceFrame caps for known devices

    // Placeholder: just succeed for now
    let _ = (slot, device_info);
    Ok(())
}

/// Claim an IRQ handler.
fn claim_irq(slot: u64, irq: u32) -> Result<(), SpawnError> {
    // Use IRQ_CONTROL to create an IRQHandler for this IRQ
    // irq_control_get(slots::IRQ_CONTROL, irq, slot)
    //     .map_err(SpawnError::IrqClaimFailed)?;

    // Placeholder
    let _ = (slot, irq);
    Ok(())
}

/// Create an IOSpace for DMA.
fn create_iospace(slot: u64) -> Result<(), SpawnError> {
    // Create IOSpace from SMMU control capability
    // This would involve:
    // 1. Allocating an IOASID
    // 2. Creating IOSpace object
    // 3. Binding stream IDs

    // Placeholder
    let _ = slot;
    Ok(())
}

/// Load ELF segments and create stack.
fn load_elf_and_stack(
    vspace: u64,
    elf: &Elf64,
    elf_data: &[u8],
    registry: &mut Registry,
) -> Result<u64, SpawnError> {
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
            map_segment(vspace, segment.vaddr, segment.mem_size, data, rights, registry)?;
        }
    }

    // Create stack (16 pages = 64KB)
    let stack_pages = 16;
    let stack_top = 0x0000_7FFF_F000u64;
    let stack_base = stack_top - (stack_pages * PAGE_SIZE) as u64;

    for i in 0..stack_pages {
        let page_vaddr = stack_base + (i * PAGE_SIZE) as u64;
        let frame_slot = alloc_frame(registry)?;
        map_frame(vspace, frame_slot, page_vaddr, MapRights::RW.to_bits(), 0)
            .map_err(SpawnError::FrameMapFailed)?;
    }

    Ok(stack_top)
}

/// Map a memory segment.
fn map_segment(
    vspace: u64,
    vaddr: u64,
    size: u64,
    data: &[u8],
    rights: MapRights,
    registry: &mut Registry,
) -> Result<(), SpawnError> {
    let vaddr_start = vaddr & !(PAGE_SIZE as u64 - 1);
    let vaddr_end = (vaddr + size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let num_pages = ((vaddr_end - vaddr_start) / PAGE_SIZE as u64) as usize;

    let data_offset = (vaddr - vaddr_start) as usize;

    for i in 0..num_pages {
        let page_vaddr = vaddr_start + (i * PAGE_SIZE) as u64;
        let frame_slot = alloc_frame(registry)?;

        // Map temporarily to copy data
        const TEMP_MAP: u64 = 0x1_0000_0000;
        map_frame(slots::ROOT_VSPACE, frame_slot, TEMP_MAP, MapRights::RW.to_bits(), 0)
            .map_err(SpawnError::FrameMapFailed)?;

        // Copy data
        unsafe {
            let dest = core::slice::from_raw_parts_mut(TEMP_MAP as *mut u8, PAGE_SIZE);
            dest.fill(0);

            let page_data_start = if i == 0 { 0 } else { i * PAGE_SIZE - data_offset };
            let page_data_end = core::cmp::min(page_data_start + PAGE_SIZE, data.len());

            if page_data_start < data.len() {
                if i == 0 {
                    let copy_len = core::cmp::min(PAGE_SIZE - data_offset, data.len());
                    dest[data_offset..data_offset + copy_len].copy_from_slice(&data[..copy_len]);
                } else if page_data_start < page_data_end {
                    let copy_len = page_data_end - page_data_start;
                    dest[..copy_len].copy_from_slice(&data[page_data_start..page_data_end]);
                }
            }
        }

        // Unmap from our space
        unmap_frame(frame_slot).map_err(SpawnError::FrameMapFailed)?;

        // Map to driver's space
        map_frame(vspace, frame_slot, page_vaddr, rights.to_bits(), 0)
            .map_err(SpawnError::FrameMapFailed)?;
    }

    Ok(())
}

/// Allocate a frame.
fn alloc_frame(registry: &mut Registry) -> Result<u64, SpawnError> {
    let slot = registry.alloc_slot();
    retype(
        slots::RAM_UNTYPED,
        ObjectType::Frame as u64,
        12, // 4KB
        slots::ROOT_CNODE,
        slot,
        1,
    ).map_err(SpawnError::RetypeFailed)?;
    Ok(slot)
}

/// Install initial capabilities into driver's CSpace.
fn install_driver_caps(
    child_cspace: u64,
    vspace_slot: u64,
    tcb_slot: u64,
    endpoint_slot: u64,
    device_frame_slot: u64,
    irq_handler_slot: Option<u64>,
    iospace_slot: Option<u64>,
) -> Result<(), SpawnError> {
    // Slot 0: CSpace self-reference
    cap_copy(child_cspace, slots::driver::ROOT_CNODE, 0, slots::ROOT_CNODE, child_cspace, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 1: TCB
    cap_copy(child_cspace, slots::driver::ROOT_TCB, 0, slots::ROOT_CNODE, tcb_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 2: VSpace
    cap_copy(child_cspace, slots::driver::ROOT_VSPACE, 0, slots::ROOT_CNODE, vspace_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 10: DeviceFrame
    cap_copy(child_cspace, slots::driver::DEVICE_FRAME, 0, slots::ROOT_CNODE, device_frame_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 11: IRQHandler (if present)
    if let Some(irq_slot) = irq_handler_slot {
        cap_copy(child_cspace, slots::driver::IRQ_HANDLER, 0, slots::ROOT_CNODE, irq_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 12: Service endpoint
    cap_copy(child_cspace, slots::driver::SERVICE_EP, 0, slots::ROOT_CNODE, endpoint_slot, 0)
        .map_err(SpawnError::CapCopyFailed)?;

    // Slot 13: IOSpace (if present)
    if let Some(io_slot) = iospace_slot {
        cap_copy(child_cspace, slots::driver::IOSPACE, 0, slots::ROOT_CNODE, io_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    Ok(())
}
