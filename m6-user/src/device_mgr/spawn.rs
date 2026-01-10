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
    // Note: In a full implementation, this would retype from device untyped
    // or use a kernel-provided device frame capability
    // For now, we create a placeholder
    create_device_frame(device_frame_slot, &config.device_info, &cptr)?;

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

    // Create IOSpace if needed
    if let Some(io_slot) = iospace_slot {
        create_iospace(io_slot)?;
    }

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

    // Install initial capabilities in driver's CSpace
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
        iospace_slot,                 // optional iospace slot
        config.console_ep_slot,       // optional console endpoint slot
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
    tcb_write_registers(cptr(tcb_slot), entry, stack_top, 0)
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
fn create_device_frame(slot: u64, device_info: &DeviceInfo, cptr: &impl Fn(u64) -> u64) -> Result<(), SpawnError> {
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
    console_ep_slot: Option<u64>,
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

    // Slot 20: Console endpoint (if present, for IPC-based output)
    if let Some(console_slot) = console_ep_slot {
        cap_copy(child_cspace_cptr, slots::driver::CONSOLE_EP, 0, src_cnode_cptr, console_slot, 0)
            .map_err(SpawnError::CapCopyFailed)?;
    }

    Ok(())
}
