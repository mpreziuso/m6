//! Driver process spawning with capability construction.
//!
//! This module handles creating driver processes with the appropriate
//! capabilities for their device (MMIO access, IRQ, IOSpace for DMA).

use m6_cap::ObjectType;
use m6_syscall::{error::SyscallError, invoke::*, slot_to_cptr};

use crate::manifest::DriverManifest;
use crate::registry::{DeviceEntry, DriverEntry, Registry};
use crate::slots;

// Re-use ELF parser from parent
#[path = "../elf.rs"]
mod elf;

use elf::{Elf64, ElfError};

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Resolve SMMU DTB phandle to SmmuControl slot index.
///
/// Maps device tree SMMU phandles to the corresponding SmmuControl capability
/// slot in the device manager's CSpace.
///
/// # RK3588 Mapping
/// - 0x190 (mmu600_pcie @ 0xfc900000) → SMMU #0 (slot 18)
/// - 0x191 (mmu600_php @ 0xfcb00000) → SMMU #1 (slot 19)
///
/// Returns None if the phandle doesn't map to a known SMMU.
fn resolve_smmu_phandle_to_slot(phandle: u32) -> Option<u64> {
    match phandle {
        0x190 => Some(slots::SMMU_CONTROL_0), // PCIe SMMU
        0x191 => Some(slots::SMMU_CONTROL_1), // PHP SMMU (USB, etc.)
        0 => None, // No SMMU
        _ => {
            // Unknown phandle - log warning and default to SMMU #0
            crate::io::puts("[device-mgr] WARN: Unknown SMMU phandle ");
            crate::io::put_hex(phandle as u64);
            crate::io::puts(", defaulting to SMMU #0\n");
            Some(slots::SMMU_CONTROL_0)
        }
    }
}

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
    /// IOMMU required but not available (security violation)
    IommuRequired,
    /// Failed to allocate MSI vectors
    MsiAllocateFailed(SyscallError),
    /// Failed to setup MSI-X interrupts
    MsixSetupFailed,
    /// Invalid device configuration (e.g., zero MMIO address for wrapper node)
    InvalidDeviceConfig,
    /// IOSpace operation failed (e.g., map frame, bind stream)
    IOSpaceOpFailed(SyscallError),
}

impl From<ElfError> for SpawnError {
    fn from(e: ElfError) -> Self {
        Self::InvalidElf(e)
    }
}

/// MSI-X capability information (copied from registry)
#[derive(Clone, Copy, Default)]
pub struct MsixInfo {
    /// Whether MSI-X capability is present
    pub present: bool,
    /// Number of MSI-X vectors available
    pub table_size: u16,
    /// BAR index containing MSI-X table
    pub table_bir: u8,
    /// Offset of MSI-X table within the BAR
    pub table_offset: u32,
    /// Config space offset of MSI-X capability
    pub cap_offset: u8,
}

/// Device information needed for spawning (copied to avoid borrow issues)
#[derive(Clone)]
pub struct DeviceInfo {
    /// Physical base address
    pub phys_base: u64,
    /// Size of MMIO region
    pub size: u64,
    /// IRQ number (for legacy interrupts)
    pub irq: u32,
    /// Stream ID for IOMMU/SMMU (None if device doesn't have one, e.g. VirtIO MMIO)
    pub stream_id: Option<u32>,
    /// SMMU phandle from device tree (0 = none or unknown)
    pub smmu_phandle: u32,
    /// SMMU instance index (0-3) for SMMU driver devices only
    pub smmu_instance: u8,
    /// PCIe BDF address (None for platform devices)
    pub pcie_bdf: Option<(u8, u8, u8)>,
    /// MSI-X capability info (None for non-MSI-X devices)
    pub msix: Option<MsixInfo>,
}

impl DeviceInfo {
    /// Create from a DeviceEntry
    pub fn from_entry(entry: &DeviceEntry) -> Self {
        Self {
            phys_base: entry.phys_base,
            size: entry.size,
            irq: entry.irq,
            // Use stream_id from registry if non-zero (PCIe devices have stream IDs)
            stream_id: if entry.stream_id != 0 {
                Some(entry.stream_id)
            } else {
                None
            },
            smmu_phandle: entry.smmu_phandle,
            smmu_instance: entry.smmu_instance,
            pcie_bdf: entry.pcie_bdf,
            msix: if entry.msix.present {
                Some(MsixInfo {
                    present: true,
                    table_size: entry.msix.table_size,
                    table_bir: entry.msix.table_bir,
                    table_offset: entry.msix.table_offset,
                    cap_offset: entry.msix.cap_offset,
                })
            } else {
                None
            },
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
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    pub fn to_bits(self) -> u64 {
        let mut bits = 0u64;
        if self.read {
            bits |= 1;
        }
        if self.write {
            bits |= 2;
        }
        if self.execute {
            bits |= 4;
        }
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

    // -- Early validation: fail fast before allocating any slots
    // This prevents slot leakage when spawning fails for wrapper nodes
    // (e.g., rockchip,rk3588-dwc3) that have no MMIO address.

    // Check device has a valid MMIO address
    if config.device_info.phys_base == 0 {
        return Err(SpawnError::InvalidDeviceConfig);
    }

    // Check device untyped exists before allocating slots
    // (Skip for VirtIO devices which reuse probe frames instead of device untyped)
    if registry.find_virtio_probe_frame(config.device_info.phys_base).is_none()
        && boot_info
            .find_device_untyped(config.device_info.phys_base)
            .is_none()
    {
        return Err(SpawnError::DeviceUntypedNotFound);
    }

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
    let dma_buffer_slots: Option<[u64; slots::driver::DMA_BUFFER_COUNT]> =
        if config.manifest.needs_iommu {
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
    )
    .map_err(SpawnError::RetypeFailed)?;

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
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create TCB
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::TCB as u64,
        0,
        cptr(slots::ROOT_CNODE),
        tcb_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create IPC buffer frame
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Frame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        ipc_buf_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create driver's service endpoint
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Endpoint as u64,
        0,
        cptr(slots::ROOT_CNODE),
        driver_ep_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create fault endpoint for death detection
    retype(
        cptr(slots::RAM_UNTYPED),
        ObjectType::Endpoint as u64,
        0,
        cptr(slots::ROOT_CNODE),
        fault_ep_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create DeviceFrame for MMIO region
    // Note: For VirtIO devices, this reuses the probe frame created during enumeration.
    // For other devices, this retypes from the device untyped.
    create_device_frame(device_frame_slot, &config.device_info, registry, &cptr)?;

    // Create extended MMIO frames for devices with large MMIO regions (e.g., DWC3)
    let extended_mmio_slots =
        create_extended_mmio_frames(&config.device_info, config.manifest.mmio_pages, registry, &cptr)?;

    // Create additional device frames (GRF, CRU, PHY, etc.) if the driver needs them
    // Large MMIO regions (>4KB) are split: first page goes in additional_frame_slots,
    // subsequent pages go in large_frame_slots.
    let additional_result = create_additional_frames(config.manifest, registry, &cptr)?;
    let additional_frame_slots = additional_result.frame_slots;
    let large_frame_slots = additional_result.large_frame_slots;

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
        )
        .map_err(SpawnError::RetypeFailed)?;
    }

    // Create IOSpace if needed (track whether it was actually created)
    let iospace_created = if let Some(io_slot) = iospace_slot {
        let smmu_slot = if has_smmu_control {
            // Resolve device's SMMU phandle to the correct SmmuControl slot
            resolve_smmu_phandle_to_slot(config.device_info.smmu_phandle)
        } else {
            None
        };
        create_iospace(io_slot, smmu_slot, config.device_info.stream_id, &cptr)?
    } else {
        false
    };

    // SECURITY: Check if drivers that need IOMMU got IOSpace
    // In production, this should fail. For debugging, we allow degraded operation.
    if config.manifest.needs_iommu && !iospace_created {
        // TODO: Make this configurable or fail in production builds
        crate::io::puts("[device-mgr] SECURITY WARNING: ");
        crate::io::puts(config.manifest.binary_name);
        crate::io::puts(" running WITHOUT IOMMU protection!\n");
        // Continue in degraded mode for debugging - remove this for production!
    } else if iospace_created {
        crate::io::puts("[device-mgr] IOSpace created for ");
        crate::io::puts(config.manifest.binary_name);
        if let Some(sid) = config.device_info.stream_id {
            crate::io::puts(" with stream ID ");
            crate::io::put_hex(sid as u64);
        }
        crate::io::newline();
    }

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
            )
            .map_err(SpawnError::RetypeFailed)?;
        }
    }

    // Create DmaPool and map DMA buffers into IOSpace if IOSpace was created
    let dma_pool_slot = if let (true, Some(iospace), Some(dma_slots)) =
        (iospace_created, iospace_slot, dma_buffer_slots.as_ref())
    {
        let pool_slot = registry.alloc_slot();

        // Create DmaPool with IOVA range starting at 256MB
        const IOVA_BASE: u64 = 0x1000_0000; // 256MB
        const IOVA_SIZE: u64 = 0x0100_0000; // 16MB pool

        let pool_created = match dma_pool_create(
            cptr(iospace),
            IOVA_BASE,
            IOVA_SIZE,
            cptr(slots::ROOT_CNODE),
            pool_slot,
            0, // depth = 0 (auto)
        ) {
            Ok(_) => true,
            Err(SyscallError::WouldBlock) => {
                crate::io::puts("[device-mgr] WARN: DMA pool creation timed out\n");
                crate::io::puts("[device-mgr] WARN: Driver will run WITHOUT DMA buffers!\n");
                false
            }
            Err(e) => return Err(SpawnError::RetypeFailed(e)),
        };

        if !pool_created {
            None
        } else {
            // Map DMA buffer frames into IOSpace at sequential IOVAs
            // Retry with backoff for timing issues with SMMU
            let mut iova = IOVA_BASE;
            let mut mapping_failed = false;
            for &slot in dma_slots {
                let mut map_result = Err(SyscallError::WouldBlock);
                let mut delay_iterations = 100_000u32;

                for attempt in 0..5 {
                    map_result = iospace_map_frame(
                        cptr(iospace),
                        cptr(slot),
                        iova,
                        3, // RW access
                    );
                    match map_result {
                        Ok(_) => break,
                        Err(SyscallError::WouldBlock) if attempt < 4 => {
                            for _ in 0..delay_iterations {
                                core::hint::spin_loop();
                            }
                            delay_iterations = (delay_iterations * 3) / 2;
                            continue;
                        }
                        Err(_) => break,
                    }
                }

                match map_result {
                    Ok(_) => {}
                    Err(SyscallError::AlreadyMapped) => {
                        // IOVA already mapped by firmware (UEFI) - this is OK
                        // The mapping already exists, continue with next frame
                    }
                    Err(SyscallError::WouldBlock) => {
                        crate::io::puts("[device-mgr] WARN: IOMMU frame mapping timed out\n");
                        crate::io::puts("[device-mgr] WARN: Driver will run WITHOUT DMA buffers!\n");
                        mapping_failed = true;
                        break;
                    }
                    Err(e) => return Err(SpawnError::IOSpaceOpFailed(e)),
                }
                iova += PAGE_SIZE as u64;
            }

            if mapping_failed { None } else { Some(pool_slot) }
        }
    } else {
        None
    };

    // Load ELF and create stack
    let entry = elf.entry();
    let stack_top = load_elf_and_stack(vspace_slot, &elf, config.elf_data, registry, &cptr)?;

    // Map IPC buffer - ensure page tables exist first
    const IPC_BUFFER_ADDR: u64 = m6_syscall::IPC_BUFFER_ADDR;
    ensure_page_tables(
        vspace_slot,
        IPC_BUFFER_ADDR,
        IPC_BUFFER_ADDR + PAGE_SIZE as u64,
        registry,
        &cptr,
    )?;
    map_frame(
        cptr(vspace_slot),
        cptr(ipc_buf_slot),
        IPC_BUFFER_ADDR,
        MapRights::RW.to_bits(),
        0,
    )
    .map_err(SpawnError::FrameMapFailed)?;

    // Ensure page tables exist for the MMIO region so driver can map its DeviceFrame
    // Most drivers use a standard MMIO address range starting at 0x8000_0000 (2GB)
    // DWC3 USB drivers use per-controller addresses: 0x8000_0000, 0x8010_0000, 0x8020_0000
    let mmio_vaddr = if config.manifest.binary_name == "drv-usb-dwc3" {
        // Calculate controller-specific MMIO base address (same logic as driver)
        let controller_idx = match config.device_info.phys_base {
            0xFC00_0000 => 0, // USB3OTG_0
            0xFC40_0000 => 1, // USB3OTG_1
            0xFCD0_0000 => 2, // USB3OTG_2
            _ => 0,           // fallback
        };
        0x0000_8000_0000 + (controller_idx as u64) * 0x0010_0000
    } else {
        0x0000_8000_0000
    };
    let mmio_region_size = (config.manifest.mmio_pages * PAGE_SIZE) as u64;
    ensure_page_tables(
        vspace_slot,
        mmio_vaddr,
        mmio_vaddr + mmio_region_size,
        registry,
        &cptr,
    )?;

    // Ensure page tables exist for DMA buffer region and map DMA buffer frames
    // DWC3 USB drivers use per-controller DMA addresses: 0x8X01_0000
    if let Some(ref dma_slots) = dma_buffer_slots {
        let dma_buffer_vaddr = if config.manifest.binary_name == "drv-usb-dwc3" {
            // Per-controller DMA region: controller 0 = 0x80010000, 1 = 0x80110000, etc.
            let controller_idx = match config.device_info.phys_base {
                0xFC00_0000 => 0,
                0xFC40_0000 => 1,
                0xFCD0_0000 => 2,
                _ => 0,
            };
            0x0000_8000_0000 + (controller_idx as u64) * 0x0010_0000 + 0x0001_0000
        } else {
            0x0000_8001_0000
        };
        let dma_region_size = (slots::driver::DMA_BUFFER_COUNT * PAGE_SIZE) as u64;
        ensure_page_tables(
            vspace_slot,
            dma_buffer_vaddr,
            dma_buffer_vaddr + dma_region_size,
            registry,
            &cptr,
        )?;

        // Map each DMA buffer frame into driver's VSpace
        for (i, &slot) in dma_slots.iter().enumerate() {
            let vaddr = dma_buffer_vaddr + (i * PAGE_SIZE) as u64;
            map_frame(
                cptr(vspace_slot),
                cptr(slot),
                vaddr,
                MapRights::RW.to_bits(),
                0,
            )
            .map_err(SpawnError::FrameMapFailed)?;
        }
    }

    // Ensure page tables exist for heap region (drivers use 0x4000_0000 for heap)
    // This is needed for drivers that use the allocator (crab-usb, etc.)
    const HEAP_BASE: u64 = 0x4000_0000;
    const HEAP_SIZE: u64 = 128 * 1024 * 1024; // 128MB heap
    ensure_page_tables(vspace_slot, HEAP_BASE, HEAP_BASE + HEAP_SIZE, registry, &cptr)?;

    // Ensure page tables exist for INSTANCE_INFO region (used by SMMU drivers)
    // SMMU drivers map instance info frame at 0x70000000 to read their instance index
    if config.manifest.binary_name == "drv-smmu" {
        const INSTANCE_INFO_VADDR: u64 = 0x0000_7000_0000;
        ensure_page_tables(
            vspace_slot,
            INSTANCE_INFO_VADDR,
            INSTANCE_INFO_VADDR + PAGE_SIZE as u64,
            registry,
            &cptr,
        )?;
    }

    // Create instance info frame for SMMU drivers
    // SMMU drivers need to know their instance index (0, 1, 2, 3) to calculate
    // unique virtual addresses for MMIO mapping (0x80000000, 0x80100000, etc.)
    let instance_info_slot = if config.manifest.binary_name == "drv-smmu" {
        let info_slot = registry.alloc_slot();

        // Create Frame for instance info
        retype(
            cptr(slots::RAM_UNTYPED),
            ObjectType::Frame as u64,
            12, // 4KB
            cptr(slots::ROOT_CNODE),
            info_slot,
            1,
        )
        .map_err(SpawnError::RetypeFailed)?;

        // Temporary address for writing instance info (unmapped after use)
        const TEMP_VADDR: u64 = 0x0000_7000_0000;
        let instance_idx = config.device_info.smmu_instance as u64;

        // Ensure page tables exist for temporary mapping
        ensure_page_tables(
            slots::ROOT_VSPACE,
            TEMP_VADDR,
            TEMP_VADDR + PAGE_SIZE as u64,
            registry,
            &cptr,
        )?;

        // Map frame temporarily to write instance index
        map_frame(
            cptr(slots::ROOT_VSPACE),
            cptr(info_slot),
            TEMP_VADDR,
            MapRights::RW.to_bits(),
            0,
        )
        .map_err(SpawnError::FrameMapFailed)?;

        // Write SMMU instance index at offset 0
        // SAFETY: Writing to mapped frame at valid address
        unsafe {
            core::ptr::write_volatile(TEMP_VADDR as *mut u64, instance_idx);
        }

        // Unmap the frame so the address can be reused
        let _ = unmap_frame(cptr(info_slot));

        Some(info_slot)
    } else {
        None
    };

    // Install initial capabilities in driver's CSpace
    let smmu_to_copy = if has_smmu_control {
        // Resolve device's SMMU phandle to the correct SmmuControl slot
        resolve_smmu_phandle_to_slot(config.device_info.smmu_phandle)
    } else {
        None
    };

    install_driver_caps(
        cptr(cspace_slot),         // dest cspace CPtr
        cptr(slots::ROOT_CNODE),   // src cnode CPtr
        cspace_slot,               // cspace slot number
        vspace_slot,               // vspace slot number
        tcb_slot,                  // tcb slot number
        driver_ep_slot,            // endpoint slot number
        device_frame_slot,         // device frame slot number
        irq_handler_slot,          // optional irq handler slot
        irq_notif_slot,            // optional notification for IRQ delivery
        effective_iospace_slot,    // optional iospace slot (only if actually created)
        smmu_to_copy,              // optional smmu control slot
        dma_pool_slot,             // optional DMA pool slot
        instance_info_slot,        // optional instance info frame (for SMMU drivers)
        config.console_ep_slot,    // optional console endpoint slot
        dma_buffer_slots.as_ref(), // optional DMA buffer frame slots
        &additional_frame_slots,   // additional MMIO frames (GRF, CRU, etc.)
        &large_frame_slots,        // large MMIO frames for multi-page additional regions
        &extended_mmio_slots,      // extended MMIO frames for large MMIO regions
    )?;

    // Setup MSI-X for PCIe devices that support it
    if let (Some(msix), Some(bdf)) = (&config.device_info.msix, config.device_info.pcie_bdf)
        && msix.present
        && config.device_info.phys_base != 0
    {
        // Request 2 vectors for NVMe (admin + 1 IO queue), can be expanded later
        let requested_vectors = 2u32.min(msix.table_size as u32);

        let msix_result = setup_msix(
            msix,
            requested_vectors,
            bdf,
            config.device_info.phys_base,
            registry,
            &cptr,
        )?;

        // Install MSI-X handler capabilities into driver's CSpace
        install_msix_caps(cptr(cspace_slot), cptr(slots::ROOT_CNODE), &msix_result)?;
    }

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
    )
    .map_err(SpawnError::TcbConfigureFailed)?;

    // Set initial registers
    // Pass the full device physical address as arg0 (x0 register)
    // This allows drivers to identify which controller they're driving (e.g., USB3OTG_0 vs _1)
    // and also handle non-page-aligned devices by computing the offset within the mapped page.
    let device_phys_addr = config.device_info.phys_base;
    tcb_write_registers(cptr(tcb_slot), entry, stack_top, device_phys_addr)
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

    registry
        .add_driver(driver_entry)
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
    let (device_untyped_slot, _size, untyped_base) = boot_info
        .find_device_untyped(device_info.phys_base)
        .ok_or(SpawnError::DeviceUntypedNotFound)?;

    // Calculate offset within the device untyped
    // For PCIe devices, the BAR address may be offset from the untyped base
    let offset = device_info.phys_base.saturating_sub(untyped_base);

    // Retype the device untyped to DeviceFrame
    // DeviceFrame size is always 4KB (size_bits = 12)
    // For DeviceFrame, arg5 is the offset within the device untyped
    retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        slot,
        offset,
    )
    .map_err(SpawnError::RetypeFailed)?;

    Ok(())
}

/// Create extended MMIO frames for devices with large MMIO regions.
///
/// When a device's MMIO region spans more than 4KB, this function creates
/// additional DeviceFrame capabilities for pages 1 through (mmio_pages-1).
/// Page 0 is handled by create_device_frame.
///
/// Returns an array of slots containing the extended DeviceFrame capabilities.
/// Slots for unused pages are set to 0.
fn create_extended_mmio_frames(
    device_info: &DeviceInfo,
    mmio_pages: usize,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<[u64; slots::driver::EXTENDED_MMIO_MAX], SpawnError> {
    let mut frame_slots = [0u64; slots::driver::EXTENDED_MMIO_MAX];

    // Nothing to do if only 1 page needed
    if mmio_pages <= 1 {
        return Ok(frame_slots);
    }

    // Cap at maximum extended pages
    let pages_to_create = (mmio_pages - 1).min(slots::driver::EXTENDED_MMIO_MAX);

    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };

    // Find the device untyped covering this physical address
    let (device_untyped_slot, _size, untyped_base) = boot_info
        .find_device_untyped(device_info.phys_base)
        .ok_or(SpawnError::DeviceUntypedNotFound)?;

    crate::io::puts("[device-mgr] Creating ");
    crate::io::put_u64(pages_to_create as u64);
    crate::io::puts(" extended MMIO frames\n");

    for (i, frame_slot) in frame_slots.iter_mut().enumerate().take(pages_to_create) {
        // Page 0 is at phys_base, page 1 is at phys_base + 0x1000, etc.
        let page_phys = device_info.phys_base + ((i + 1) as u64 * PAGE_SIZE as u64);
        let offset_in_untyped = page_phys.saturating_sub(untyped_base);

        // Allocate a slot for this frame
        let slot = registry.alloc_slot();

        // Retype to DeviceFrame
        if let Err(e) = retype(
            cptr(device_untyped_slot),
            ObjectType::DeviceFrame as u64,
            12, // 4KB
            cptr(slots::ROOT_CNODE),
            slot,
            offset_in_untyped,
        ) {
            crate::io::puts("[device-mgr] WARN: Failed to create extended MMIO frame ");
            crate::io::put_u64(i as u64);
            crate::io::puts(" at offset ");
            crate::io::put_hex(offset_in_untyped);
            crate::io::puts(": ");
            crate::io::puts(e.name());
            crate::io::newline();
            // Continue trying remaining frames
            continue;
        }

        *frame_slot = slot;
    }

    Ok(frame_slots)
}

/// Create device frames for additional MMIO regions (GRF, CRU, etc.).
///
/// Returns an array of slots containing DeviceFrame capabilities.
/// Empty slots are set to 0.
///
/// GRF/CRU frames are shared resources - once created, they are cached
/// and subsequent drivers receive a cap_copy of the original.
/// Additional frames result including large frame slots
struct AdditionalFramesResult {
    frame_slots: [u64; slots::driver::ADDITIONAL_FRAME_MAX],
    large_frame_slots: [u64; slots::driver::LARGE_FRAME_MAX],
    large_frame_count: usize,
}

fn create_additional_frames(
    manifest: &DriverManifest,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<AdditionalFramesResult, SpawnError> {
    const PAGE_SIZE: u64 = 4096;
    let mut frame_slots = [0u64; slots::driver::ADDITIONAL_FRAME_MAX];
    let mut large_frame_slots = [0u64; slots::driver::LARGE_FRAME_MAX];
    let mut large_frame_idx = 0usize;

    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };

    for (i, frame) in manifest.additional_frames.iter().enumerate() {
        if i >= slots::driver::ADDITIONAL_FRAME_MAX {
            crate::io::puts("[device-mgr] WARN: too many additional frames\n");
            break;
        }

        // Calculate number of pages needed for this frame
        let num_pages = (frame.size.div_ceil(PAGE_SIZE)) as usize;
        let is_large = num_pages > 1;

        // Debug: show what we're looking for
        crate::io::puts("[device-mgr] Looking for ");
        crate::io::puts(frame.name);
        crate::io::puts(" at phys ");
        crate::io::put_hex(frame.phys_addr);
        crate::io::puts(" (");
        crate::io::put_u64(num_pages as u64);
        crate::io::puts(" pages)\n");

        // Check if we already have this frame cached from a previous driver
        if let Some(cached_slot) = registry.find_additional_frame(frame.phys_addr) {
            // Frame already exists - use cap_copy to share it
            let new_slot = registry.alloc_slot();
            let cnode_cptr = cptr(slots::ROOT_CNODE);

            if let Err(e) = cap_copy(cnode_cptr, new_slot, 0, cnode_cptr, cached_slot, 0) {
                crate::io::puts("[device-mgr] WARN: failed to copy ");
                crate::io::puts(frame.name);
                crate::io::puts(": ");
                crate::io::puts(e.name());
                crate::io::newline();
                continue;
            }

            // crate::io::puts("[device-mgr] Reusing cached frame: ");
            // crate::io::puts(frame.name);
            // crate::io::puts(" at ");
            // crate::io::put_hex(frame.phys_addr);
            // crate::io::newline();

            frame_slots[i] = new_slot;
            continue;
        }

        // Find device untyped covering this physical address
        let (device_untyped_slot, _untyped_size, untyped_base) = match boot_info
            .find_device_untyped(frame.phys_addr)
        {
            Some(v) => {
                crate::io::puts("[device-mgr] Found device untyped at ");
                crate::io::put_hex(v.2);
                crate::io::puts(" size ");
                crate::io::put_hex(v.1);
                crate::io::puts(" for ");
                crate::io::puts(frame.name);
                crate::io::newline();
                v
            }
            None => {
                // GRF/CRU regions might not have device untypeds on non-RK3588 platforms
                // This is not an error - just skip this frame
                crate::io::puts("[device-mgr] WARN: no device untyped for ");
                crate::io::puts(frame.name);
                crate::io::puts(" at ");
                crate::io::put_hex(frame.phys_addr);
                crate::io::newline();
                continue;
            }
        };

        // Create the first page (goes in regular additional frame slot)
        let slot = registry.alloc_slot();
        let offset = frame.phys_addr.saturating_sub(untyped_base);

        // crate::io::puts("[device-mgr] Retyping ");
        // crate::io::puts(frame.name);
        // crate::io::puts(": slot=");
        // crate::io::put_u64(slot);
        // crate::io::puts(" offset=");
        // crate::io::put_hex(offset);
        // crate::io::newline();

        if let Err(e) = retype(
            cptr(device_untyped_slot),
            ObjectType::DeviceFrame as u64,
            12, // 4KB
            cptr(slots::ROOT_CNODE),
            slot,
            offset,
        ) {
            crate::io::puts("[device-mgr] WARN: failed to create DeviceFrame for ");
            crate::io::puts(frame.name);
            crate::io::puts(": ");
            crate::io::puts(e.name());
            crate::io::newline();
            continue;
        }

        // Cache this frame for reuse by subsequent drivers
        registry.add_additional_frame(frame.phys_addr, slot);
        frame_slots[i] = slot;

        // crate::io::puts("[device-mgr] Created additional frame: ");
        // crate::io::puts(frame.name);
        // crate::io::puts(" at ");
        // crate::io::put_hex(frame.phys_addr);
        // if is_large {
        //     crate::io::puts(" (");
        //     crate::io::put_u64(num_pages as u64);
        //     crate::io::puts(" pages)");
        // }
        // crate::io::newline();

        // For large frames, create additional pages in LARGE_FRAME slots
        if is_large && large_frame_idx < slots::driver::LARGE_FRAME_MAX {
            for page in 1..num_pages {
                if large_frame_idx >= slots::driver::LARGE_FRAME_MAX {
                    crate::io::puts("[device-mgr] WARN: out of large frame slots\n");
                    break;
                }

                let page_slot = registry.alloc_slot();
                let page_offset = offset + (page as u64 * PAGE_SIZE);

                if let Err(e) = retype(
                    cptr(device_untyped_slot),
                    ObjectType::DeviceFrame as u64,
                    12, // 4KB
                    cptr(slots::ROOT_CNODE),
                    page_slot,
                    page_offset,
                ) {
                    crate::io::puts("[device-mgr] WARN: failed to create large frame page ");
                    crate::io::put_u64(page as u64);
                    crate::io::puts(": ");
                    crate::io::puts(e.name());
                    crate::io::newline();
                    break;
                }

                large_frame_slots[large_frame_idx] = page_slot;
                large_frame_idx += 1;
            }
        }
    }

    Ok(AdditionalFramesResult {
        frame_slots,
        large_frame_slots,
        large_frame_count: large_frame_idx,
    })
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
    )
    .map_err(SpawnError::IrqClaimFailed)?;
    Ok(())
}

/// Create an IOSpace for DMA.
///
/// Creates an IOSpace object using SmmuControl and untyped memory.
/// The IOSpace provides IOMMU translation for device DMA.
/// Optionally binds a stream ID if the device has one.
///
/// # Security
///
/// Returns `Err(IommuRequired)` if SMMU capability is not available.
/// Returns `Ok(false)` if IOSpace creation fails due to SMMU hardware issues
/// (WouldBlock/Timeout) - this allows degraded operation without IOMMU.
/// Returns `Ok(true)` if IOSpace was created successfully.
fn create_iospace(
    slot: u64,
    smmu_control_slot: Option<u64>,
    stream_id: Option<u32>,
    cptr: &impl Fn(u64) -> u64,
) -> Result<bool, SpawnError> {
    // SECURITY: Require SMMU capability - drivers with DMA must use IOMMU
    let smmu_slot = match smmu_control_slot {
        Some(s) => s,
        None => return Err(SpawnError::IommuRequired),
    };

    // Create IOSpace from SmmuControl + untyped memory
    // Retry with exponential backoff for WouldBlock (timing issues with SMMU init)
    // Total wait time: ~500ms (10ms + 15ms + 22ms + 33ms + 50ms + 75ms + 112ms + 168ms + 252ms)
    const MAX_RETRIES: u32 = 10;
    let mut create_result = Err(SyscallError::WouldBlock);
    let mut delay_iterations = 100_000u32; // ~10ms initial delay

    for attempt in 0..MAX_RETRIES {
        create_result = iospace_create(
            cptr(smmu_slot),
            cptr(slots::RAM_UNTYPED),
            cptr(slots::ROOT_CNODE),
            slot,
            0, // depth = 0 (auto)
        );
        match create_result {
            Ok(_) => break,
            Err(SyscallError::WouldBlock) if attempt < MAX_RETRIES - 1 => {
                // Exponential backoff: multiply delay by 1.5 each iteration
                for _ in 0..delay_iterations {
                    core::hint::spin_loop();
                }
                delay_iterations = (delay_iterations * 3) / 2;
                continue;
            }
            Err(_) => break,
        }
    }

    if let Err(e) = create_result {
        if e == SyscallError::WouldBlock {
            crate::io::puts("[device-mgr] WARN: IOSpace creation timed out (SMMU not ready?)\n");
            crate::io::puts("[device-mgr] WARN: Driver will run WITHOUT IOMMU protection!\n");
            return Ok(false);
        }
        if e == SyscallError::AlreadyMapped {
            // IOSpace already configured by firmware - we can't get the capability
            // Fall back to physical address mode (no IOMMU translation)
            crate::io::puts("[device-mgr] IOSpace already configured by firmware\n");
            crate::io::puts("[device-mgr] WARN: Cannot reuse firmware IOSpace, using physical addresses\n");
            return Ok(false);
        } else {
            return Err(SpawnError::RetypeFailed(e));
        }
    }

    // Bind stream ID if device has one
    // VirtIO MMIO devices typically don't have stream IDs and operate in bypass mode
    // PCIe devices with stream IDs will have IOMMU translation enabled
    if let Some(sid) = stream_id {
        // Retry stream binding with backoff
        let mut bind_result = Err(SyscallError::WouldBlock);
        let mut delay_iterations = 100_000u32;

        for attempt in 0..5 {
            bind_result = iospace_bind_stream(cptr(slot), cptr(smmu_slot), sid);
            match bind_result {
                Ok(_) => break,
                Err(SyscallError::WouldBlock) if attempt < 4 => {
                    for _ in 0..delay_iterations {
                        core::hint::spin_loop();
                    }
                    delay_iterations = (delay_iterations * 3) / 2;
                    continue;
                }
                Err(_) => break,
            }
        }

        match bind_result {
            Ok(_) => {
                crate::io::puts("[device-mgr] Bound stream ID ");
                crate::io::put_hex(sid as u64);
                crate::io::puts(" to IOSpace\n");
            }
            Err(SyscallError::AlreadyMapped) => {
                // Stream ID already bound by firmware (UEFI) - this is OK
                // The stream is already configured in the SMMU, use it as-is
                crate::io::puts("[device-mgr] Stream ");
                crate::io::put_hex(sid as u64);
                crate::io::puts(" already bound by firmware\n");
            }
            Err(SyscallError::WouldBlock) => {
                crate::io::puts("[device-mgr] WARN: Stream bind timed out for stream ");
                crate::io::put_hex(sid as u64);
                crate::io::newline();
                crate::io::puts("[device-mgr] WARN: Driver will run WITHOUT IOMMU protection!\n");
                return Ok(false);
            }
            Err(e) => return Err(SpawnError::IOSpaceOpFailed(e)),
        }
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
    const L2_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
    const L3_SIZE: u64 = 2 * 1024 * 1024; // 2MB

    let l1_base = vaddr_start & !(L1_SIZE - 1);
    let l2_base = vaddr_start & !(L2_SIZE - 1);
    let l3_base = vaddr_start & !(L3_SIZE - 1);

    // Create L1 table (level 1)
    let l1_slot = registry.alloc_slot();
    retype(
        cptr(slots::RAM_UNTYPED),
        5,
        0,
        cptr(slots::ROOT_CNODE),
        l1_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l1_slot), l1_base, 1);

    // Create L2 table (level 2)
    let l2_slot = registry.alloc_slot();
    retype(
        cptr(slots::RAM_UNTYPED),
        6,
        0,
        cptr(slots::ROOT_CNODE),
        l2_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l2_slot), l2_base, 2);

    // Create L3 table (level 3)
    let l3_slot = registry.alloc_slot();
    retype(
        cptr(slots::RAM_UNTYPED),
        7,
        0,
        cptr(slots::ROOT_CNODE),
        l3_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l3_slot), l3_base, 3);

    // Handle case where end address is in a different L3 region
    let l3_end_base = (vaddr_end - 1) & !(L3_SIZE - 1);
    if l3_end_base != l3_base {
        let l3_slot2 = registry.alloc_slot();
        retype(
            cptr(slots::RAM_UNTYPED),
            7,
            0,
            cptr(slots::ROOT_CNODE),
            l3_slot2,
            1,
        )
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
            map_segment(
                vspace,
                segment.vaddr,
                segment.mem_size,
                data,
                rights,
                registry,
                &cptr,
            )?;
        }
    }

    // Create stack frames
    for i in 0..stack_pages {
        let page_vaddr = stack_base + (i * PAGE_SIZE) as u64;
        let frame_slot = alloc_frame(registry, &cptr)?;
        map_frame(
            cptr(vspace),
            cptr(frame_slot),
            page_vaddr,
            MapRights::RW.to_bits(),
            0,
        )
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
        let page_data_start = if i == 0 {
            0
        } else {
            i * PAGE_SIZE - data_offset
        };
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
                frame_write(
                    cptr(frame_slot),
                    data_offset as u64,
                    data.as_ptr(),
                    copy_len,
                )
                .map_err(SpawnError::FrameMapFailed)?;

                // Zero remainder if needed
                let remainder_start = data_offset + copy_len;
                if remainder_start < PAGE_SIZE {
                    frame_write(
                        cptr(frame_slot),
                        remainder_start as u64,
                        ZEROS.as_ptr(),
                        PAGE_SIZE - remainder_start,
                    )
                    .map_err(SpawnError::FrameMapFailed)?;
                }
            } else if page_data_start < page_data_end {
                // Subsequent pages with data
                let copy_len = page_data_end - page_data_start;
                frame_write(
                    cptr(frame_slot),
                    0,
                    data[page_data_start..].as_ptr(),
                    copy_len,
                )
                .map_err(SpawnError::FrameMapFailed)?;

                // Zero remainder if partial page
                if copy_len < PAGE_SIZE {
                    frame_write(
                        cptr(frame_slot),
                        copy_len as u64,
                        ZEROS.as_ptr(),
                        PAGE_SIZE - copy_len,
                    )
                    .map_err(SpawnError::FrameMapFailed)?;
                }
            }
        } else {
            // No data for this page - just zero it
            frame_write(cptr(frame_slot), 0, ZEROS.as_ptr(), PAGE_SIZE)
                .map_err(SpawnError::FrameMapFailed)?;
        }

        // Map frame into driver's VSpace
        map_frame(
            cptr(vspace_slot),
            cptr(frame_slot),
            page_vaddr,
            rights.to_bits(),
            0,
        )
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
    )
    .map_err(SpawnError::RetypeFailed)?;
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
    instance_info_slot: Option<u64>,
    console_ep_slot: Option<u64>,
    dma_buffer_slots: Option<&[u64; slots::driver::DMA_BUFFER_COUNT]>,
    additional_frame_slots: &[u64; slots::driver::ADDITIONAL_FRAME_MAX],
    large_frame_slots: &[u64; slots::driver::LARGE_FRAME_MAX],
    extended_mmio_slots: &[u64; slots::driver::EXTENDED_MMIO_MAX],
) -> Result<(), SpawnError> {
    // Slot 0: CSpace self-reference
    cap_copy(
        child_cspace_cptr,
        slots::driver::ROOT_CNODE,
        0,
        src_cnode_cptr,
        cspace_slot,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 1: TCB
    cap_copy(
        child_cspace_cptr,
        slots::driver::ROOT_TCB,
        0,
        src_cnode_cptr,
        tcb_slot,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 2: VSpace
    cap_copy(
        child_cspace_cptr,
        slots::driver::ROOT_VSPACE,
        0,
        src_cnode_cptr,
        vspace_slot,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 10: DeviceFrame
    cap_copy(
        child_cspace_cptr,
        slots::driver::DEVICE_FRAME,
        0,
        src_cnode_cptr,
        device_frame_slot,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 11: IRQHandler (if present)
    if let Some(irq_slot) = irq_handler_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::IRQ_HANDLER,
            0,
            src_cnode_cptr,
            irq_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 14: Notification for IRQ delivery (if present)
    if let Some(notif_slot) = irq_notif_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::NOTIF,
            0,
            src_cnode_cptr,
            notif_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 29: Instance info frame (for SMMU drivers that need unique virtual addresses)
    if let Some(info_slot) = instance_info_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::INSTANCE_INFO,
            0,
            src_cnode_cptr,
            info_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 12: Service endpoint
    cap_copy(
        child_cspace_cptr,
        slots::driver::SERVICE_EP,
        0,
        src_cnode_cptr,
        endpoint_slot,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 13: IOSpace (if present)
    if let Some(io_slot) = iospace_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::IOSPACE,
            0,
            src_cnode_cptr,
            io_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 15: SmmuControl (if present, for DMA-capable drivers)
    if let Some(src_smmu_slot) = smmu_control_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::SMMU_CONTROL,
            0,
            src_cnode_cptr,
            src_smmu_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 16: DmaPool (if present, for IOVA allocation)
    if let Some(pool_slot) = dma_pool_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::DMA_POOL,
            0,
            src_cnode_cptr,
            pool_slot,
            0,
        )
        .map_err(SpawnError::CapCopyFailed)?;
    }

    // Slot 17: RAM untyped for heap allocation
    // All drivers get access to device-mgr's RAM untyped for heap allocation
    cap_copy(
        child_cspace_cptr,
        slots::driver::RAM_UNTYPED,
        0,
        src_cnode_cptr,
        slots::RAM_UNTYPED,
        0,
    )
    .map_err(SpawnError::CapCopyFailed)?;

    // Slot 20: Console endpoint (if present, for IPC-based output)
    if let Some(console_slot) = console_ep_slot {
        cap_copy(
            child_cspace_cptr,
            slots::driver::CONSOLE_EP,
            0,
            src_cnode_cptr,
            console_slot,
            0,
        )
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

    // Slots 30-39: Additional MMIO frames (GRF, CRU, etc.)
    for (i, &slot) in additional_frame_slots.iter().enumerate() {
        if slot != 0 {
            let dest_slot = slots::driver::ADDITIONAL_FRAME_START + i as u64;
            cap_copy(child_cspace_cptr, dest_slot, 0, src_cnode_cptr, slot, 0)
                .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    // Slots 64-127: Large MMIO frames (for multi-page additional regions like PHY)
    for (i, &slot) in large_frame_slots.iter().enumerate() {
        if slot != 0 {
            let dest_slot = slots::driver::LARGE_FRAME_START + i as u64;
            cap_copy(child_cspace_cptr, dest_slot, 0, src_cnode_cptr, slot, 0)
                .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    // Slots 48-63: Extended MMIO frames (for devices with large MMIO regions)
    for (i, &slot) in extended_mmio_slots.iter().enumerate() {
        if slot != 0 {
            let dest_slot = slots::driver::EXTENDED_MMIO_START + i as u64;
            cap_copy(child_cspace_cptr, dest_slot, 0, src_cnode_cptr, slot, 0)
                .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    Ok(())
}

/// Result of MSI-X setup
pub struct MsixSetupResult {
    /// Number of vectors actually allocated
    pub vector_count: u32,
    /// Base SPI number for the allocated vectors
    pub base_spi: u32,
    /// Slots containing IRQHandler caps (in device-mgr's CSpace)
    pub handler_slots: [u64; slots::driver::MSIX_MAX_VECTORS],
    /// Slots containing notification caps for each vector
    pub notif_slots: [u64; slots::driver::MSIX_MAX_VECTORS],
}

/// Setup MSI-X interrupts for a PCIe device.
///
/// This function:
/// 1. Allocates MSI vectors from the GIC
/// 2. Creates IRQHandler capabilities for each allocated SPI
/// 3. Maps the BAR containing the MSI-X table
/// 4. Programmes each MSI-X table entry with target address and SPI data
/// 5. Enables MSI-X in the device's config space
///
/// # Arguments
/// * `msix` - MSI-X capability info from the device
/// * `requested_vectors` - Number of vectors to allocate (clamped to device max)
/// * `pcie_bdf` - PCIe Bus/Device/Function address for config space access
/// * `bar_phys_base` - Physical base address of the BAR containing MSI-X table
/// * `registry` - Registry for slot allocation
/// * `cptr` - CPtr conversion function
pub fn setup_msix(
    msix: &MsixInfo,
    requested_vectors: u32,
    pcie_bdf: (u8, u8, u8),
    bar_phys_base: u64,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<MsixSetupResult, SpawnError> {
    use crate::io;

    // Clamp requested vectors to device capability and our maximum
    let max_vectors = (msix.table_size as u32)
        .min(requested_vectors)
        .min(slots::driver::MSIX_MAX_VECTORS as u32);

    if max_vectors == 0 {
        return Err(SpawnError::MsixSetupFailed);
    }

    io::puts("[device-mgr] MSI-X: allocating ");
    io::put_u64(max_vectors as u64);
    io::puts(" vectors\n");

    // Allocate MSI vectors from the kernel
    let msi_result = msi_allocate(cptr(slots::IRQ_CONTROL), max_vectors)
        .map_err(SpawnError::MsiAllocateFailed)?;

    io::puts("[device-mgr] MSI-X: allocated ");
    io::put_u64(msi_result.vector_count as u64);
    io::puts(" vectors, base SPI=");
    io::put_u64(msi_result.base_spi as u64);
    io::puts(", target=");
    io::put_hex(msi_result.target_addr);
    io::newline();

    let mut result = MsixSetupResult {
        vector_count: msi_result.vector_count,
        base_spi: msi_result.base_spi,
        handler_slots: [0; slots::driver::MSIX_MAX_VECTORS],
        notif_slots: [0; slots::driver::MSIX_MAX_VECTORS],
    };

    // Create IRQHandler and Notification caps for each vector
    for i in 0..msi_result.vector_count {
        let spi = msi_result.base_spi + i;
        let handler_slot = registry.alloc_slot();
        let notif_slot = registry.alloc_slot();

        // Claim IRQ handler for this SPI
        irq_control_get(
            cptr(slots::IRQ_CONTROL),
            spi,
            cptr(slots::ROOT_CNODE),
            handler_slot,
            0,
        )
        .map_err(SpawnError::IrqClaimFailed)?;

        // Create notification for this vector
        retype(
            cptr(slots::RAM_UNTYPED),
            ObjectType::Notification as u64,
            0,
            cptr(slots::ROOT_CNODE),
            notif_slot,
            1,
        )
        .map_err(SpawnError::RetypeFailed)?;

        // Bind the IRQ handler to the notification with badge = vector index
        irq_set_handler(cptr(handler_slot), cptr(notif_slot), i as u64)
            .map_err(SpawnError::IrqClaimFailed)?;

        result.handler_slots[i as usize] = handler_slot;
        result.notif_slots[i as usize] = notif_slot;
    }

    // Programme the MSI-X table
    // The table is in the BAR at offset msix.table_offset
    // We need to map the BAR temporarily to write to the table
    programme_msix_table(
        bar_phys_base,
        msix,
        msi_result.target_addr,
        msi_result.base_spi,
        msi_result.vector_count,
        pcie_bdf,
        registry,
        cptr,
    )?;

    Ok(result)
}

/// Programme the MSI-X table entries.
///
/// This maps the BAR containing the MSI-X table, writes the target address
/// and data to each entry, and unmasks the vectors.
#[allow(clippy::too_many_arguments)]
fn programme_msix_table(
    bar_phys_base: u64,
    msix: &MsixInfo,
    target_addr: u64,
    base_spi: u32,
    vector_count: u32,
    pcie_bdf: (u8, u8, u8),
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<(), SpawnError> {
    use crate::io;

    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };

    // Find the device untyped that covers the BAR
    let (device_untyped_slot, _size, untyped_base) = boot_info
        .find_device_untyped(bar_phys_base)
        .ok_or(SpawnError::DeviceUntypedNotFound)?;

    // Calculate the page-aligned base and offset
    let table_phys = bar_phys_base + msix.table_offset as u64;
    let page_base = table_phys & !0xFFF;
    let page_offset = (table_phys & 0xFFF) as usize;

    // Retype to DeviceFrame for temporary mapping
    let bar_frame_slot = registry.alloc_slot();
    let offset_in_untyped = page_base.saturating_sub(untyped_base);

    retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12, // 4KB
        cptr(slots::ROOT_CNODE),
        bar_frame_slot,
        offset_in_untyped,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Map into device-mgr's VSpace at a temporary address
    const MSIX_TABLE_VADDR: u64 = 0x0000_9000_0000; // Temporary mapping address

    // Ensure page tables exist for this address
    ensure_page_tables(
        slots::ROOT_VSPACE,
        MSIX_TABLE_VADDR,
        MSIX_TABLE_VADDR + PAGE_SIZE as u64,
        registry,
        cptr,
    )?;

    // Map the frame (device memory = uncached)
    map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(bar_frame_slot),
        MSIX_TABLE_VADDR,
        MapRights::RW.to_bits() | (1 << 3), // RW + device memory attribute
        0,
    )
    .map_err(SpawnError::FrameMapFailed)?;

    // Programme each MSI-X table entry
    // Each entry is 16 bytes: [msg_addr_lo (4), msg_addr_hi (4), msg_data (4), vector_ctrl (4)]
    let table_vaddr = MSIX_TABLE_VADDR as usize + page_offset;

    io::puts("[device-mgr] MSI-X: programming table at vaddr ");
    io::put_hex(table_vaddr as u64);
    io::newline();

    for i in 0..vector_count {
        let entry_offset = (i as usize) * 16;
        let entry_addr = table_vaddr + entry_offset;

        // SAFETY: We just mapped this memory and the address is valid
        unsafe {
            // Message Address Low (lower 32 bits of target address)
            core::ptr::write_volatile(entry_addr as *mut u32, target_addr as u32);
            // Message Address High (upper 32 bits)
            core::ptr::write_volatile((entry_addr + 4) as *mut u32, (target_addr >> 32) as u32);
            // Message Data (SPI number)
            core::ptr::write_volatile((entry_addr + 8) as *mut u32, base_spi + i);
            // Vector Control: bit 0 = mask bit, 0 = unmasked
            core::ptr::write_volatile((entry_addr + 12) as *mut u32, 0);
        }

        io::puts("[device-mgr] MSI-X: vector ");
        io::put_u64(i as u64);
        io::puts(" -> SPI ");
        io::put_u64((base_spi + i) as u64);
        io::newline();
    }

    // Unmap the temporary mapping
    let _ = unmap_frame(cptr(bar_frame_slot));

    // Enable MSI-X in config space
    enable_msix_in_config(pcie_bdf, msix.cap_offset, registry, cptr)?;

    Ok(())
}

/// Enable MSI-X in PCIe config space.
///
/// This maps the config space temporarily and sets the MSI-X Enable bit.
fn enable_msix_in_config(
    pcie_bdf: (u8, u8, u8),
    cap_offset: u8,
    registry: &mut Registry,
    cptr: &impl Fn(u64) -> u64,
) -> Result<(), SpawnError> {
    use crate::io;
    use crate::pcie;

    // SAFETY: Called after _start has initialised BOOT_INFO
    let boot_info = unsafe { crate::get_boot_info() };
    let dtb_data =
        unsafe { core::slice::from_raw_parts(boot_info.dtb_vaddr as *const u8, 0x10000) };

    // Parse PCIe hosts to find config space base
    let hosts = pcie::parse_pcie_hosts(dtb_data);

    let Some(host) = hosts.iter().flatten().next() else {
        io::puts("[device-mgr] MSI-X: no PCIe host found for config access\n");
        return Err(SpawnError::MsixSetupFailed);
    };

    // Calculate config space address for this BDF
    let (bus, dev, func) = pcie_bdf;
    let rel_bus = bus - host.bus_range.0;
    let config_offset = ((rel_bus as u64) << 20)
        | ((dev as u64) << 15)
        | ((func as u64) << 12)
        | (cap_offset as u64);

    let config_phys = host.config_base + (config_offset & !0xFFF);
    let config_page_offset = (config_offset & 0xFFF) as usize;

    // Find device untyped for config space
    let (device_untyped_slot, _size, untyped_base) = boot_info
        .find_device_untyped(config_phys)
        .ok_or(SpawnError::DeviceUntypedNotFound)?;

    // Retype to DeviceFrame
    let config_frame_slot = registry.alloc_slot();
    let offset_in_untyped = config_phys.saturating_sub(untyped_base);

    retype(
        cptr(device_untyped_slot),
        ObjectType::DeviceFrame as u64,
        12,
        cptr(slots::ROOT_CNODE),
        config_frame_slot,
        offset_in_untyped,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Map into device-mgr's VSpace
    const CONFIG_VADDR: u64 = 0x0000_9001_0000;

    ensure_page_tables(
        slots::ROOT_VSPACE,
        CONFIG_VADDR,
        CONFIG_VADDR + PAGE_SIZE as u64,
        registry,
        cptr,
    )?;

    map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(config_frame_slot),
        CONFIG_VADDR,
        MapRights::RW.to_bits() | (1 << 3),
        0,
    )
    .map_err(SpawnError::FrameMapFailed)?;

    // Read and modify MSI-X Message Control register (cap_offset + 2)
    let msg_ctrl_addr = CONFIG_VADDR as usize + config_page_offset + 2;

    // SAFETY: We just mapped this memory
    unsafe {
        let msg_ctrl = core::ptr::read_volatile(msg_ctrl_addr as *const u16);
        // Set MSI-X Enable (bit 15), clear Function Mask (bit 14)
        let new_msg_ctrl = (msg_ctrl | (1 << 15)) & !(1 << 14);
        core::ptr::write_volatile(msg_ctrl_addr as *mut u16, new_msg_ctrl);
    }

    io::puts("[device-mgr] MSI-X: enabled in config space\n");

    // Unmap
    let _ = unmap_frame(cptr(config_frame_slot));

    Ok(())
}

/// Copy MSI-X handler capabilities to driver's CSpace.
pub fn install_msix_caps(
    child_cspace_cptr: u64,
    src_cnode_cptr: u64,
    msix_result: &MsixSetupResult,
) -> Result<(), SpawnError> {
    // Copy IRQHandler caps to slots 40+
    for i in 0..msix_result.vector_count as usize {
        if msix_result.handler_slots[i] != 0 {
            let dest_slot = slots::driver::MSIX_IRQ_START + i as u64;
            cap_copy(
                child_cspace_cptr,
                dest_slot,
                0,
                src_cnode_cptr,
                msix_result.handler_slots[i],
                0,
            )
            .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    // Also copy notifications - they go after the IRQ handlers (slots 48+)
    for i in 0..msix_result.vector_count as usize {
        if msix_result.notif_slots[i] != 0 {
            let dest_slot =
                slots::driver::MSIX_IRQ_START + slots::driver::MSIX_MAX_VECTORS as u64 + i as u64;
            cap_copy(
                child_cspace_cptr,
                dest_slot,
                0,
                src_cnode_cptr,
                msix_result.notif_slots[i],
                0,
            )
            .map_err(SpawnError::CapCopyFailed)?;
        }
    }

    Ok(())
}
