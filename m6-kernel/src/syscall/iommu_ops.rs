//! IOMMU syscall handlers
//!
//! This module implements syscalls for IOMMU (SMMUv3) management:
//!
//! - [`handle_iospace_create`] - Create IOSpace from untyped memory
//! - [`handle_iospace_map_frame`] - Map frame into IOSpace for DMA
//! - [`handle_iospace_unmap_frame`] - Unmap frame from IOSpace
//! - [`handle_iospace_bind_stream`] - Bind PCIe stream ID to IOSpace
//! - [`handle_iospace_unbind_stream`] - Unbind stream ID from IOSpace
//! - [`handle_dma_pool_create`] - Create DMA pool from IOSpace
//! - [`handle_dma_pool_alloc`] - Allocate IOVA range from pool
//! - [`handle_dma_pool_free`] - Free IOVA range back to pool
//!
//! # Security Model
//!
//! The SMMU provides DMA isolation for userspace drivers. Without proper
//! IOMMU configuration, DMA-capable devices could access arbitrary physical
//! memory, bypassing capability isolation.
//!
//! All operations require appropriate capabilities:
//! - SmmuControl: singleton capability for stream binding
//! - IOSpace: represents an IOMMU translation domain
//! - DmaPool: provides IOVA allocation for a driver

use m6_cap::{CapRights, ObjectType};

use crate::cap::cspace::{self, SlotLocation};
use crate::cap::object_table;
use crate::smmu::{self, SmmuError};
use crate::syscall::error::{SyscallError, SyscallResult};
use crate::syscall::SyscallArgs;

/// Convert SMMU errors to syscall errors.
fn smmu_error_to_syscall(err: SmmuError) -> SyscallError {
    match err {
        SmmuError::NotAvailable => SyscallError::NotSupported,
        SmmuError::InvalidStreamId => SyscallError::InvalidArg,
        SmmuError::QueueFull => SyscallError::WouldBlock,
        SmmuError::Timeout => SyscallError::WouldBlock,
        SmmuError::InvalidConfig => SyscallError::InvalidArg,
        SmmuError::AllocFailed => SyscallError::NoMemory,
    }
}

/// Verify a slot is empty.
fn verify_slot_empty(loc: &SlotLocation) -> Result<(), SyscallError> {
    cspace::with_slot(loc, |slot| {
        if !slot.is_empty() {
            return Err(SyscallError::SlotOccupied);
        }
        Ok(())
    })
}

/// Handle IOSpaceCreate syscall.
///
/// Creates an IOSpace (IOMMU translation domain) from untyped memory.
///
/// # Arguments (registers)
///
/// - x0: smmu_control_cptr - Capability to SmmuControl object
/// - x1: untyped_cptr - Capability to untyped memory for page tables
/// - x2: dest_cnode_cptr - CNode to place new IOSpace capability
/// - x3: dest_index - Slot index for new capability
/// - x4: dest_depth - Bits to consume resolving dest CNode (0=auto)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_create(args: &SyscallArgs) -> SyscallResult {
    let smmu_cptr = args.arg0;
    let _untyped_cptr = args.arg1;
    let dest_cnode_cptr = args.arg2;
    let dest_index = args.arg3 as usize;
    let dest_depth = args.arg4 as u8;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify SmmuControl capability
    let smmu_loc = cspace::resolve_cptr(smmu_cptr, 0)?;
    cspace::with_slot(&smmu_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::SmmuControl {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(())
    })?;

    // Resolve destination slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Verify destination slot is empty
    verify_slot_empty(&dest_loc)?;

    // TODO: Retype untyped memory into IOSpace object
    // For now, return NotSupported until retype infrastructure is complete
    log::warn!("IOSpaceCreate: retype infrastructure not yet implemented");
    Err(SyscallError::NotSupported)
}

/// Handle IOSpaceMapFrame syscall.
///
/// Maps a frame into an IOSpace at the specified IOVA.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to IOSpace
/// - x1: frame_cptr - Capability to frame to map
/// - x2: iova - I/O virtual address to map at
/// - x3: rights - Access rights (read/write)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_map_frame(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let frame_cptr = args.arg1;
    let iova = args.arg2;
    let rights_bits = args.arg3 as u8;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    let iospace_ref = cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Verify frame capability
    let frame_loc = cspace::resolve_cptr(frame_cptr, 0)?;
    let frame_ref = cspace::with_slot(&frame_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::Frame {
            return Err(SyscallError::TypeMismatch);
        }
        let required_rights = CapRights::from_bits(rights_bits);
        if !slot.rights().contains(required_rights) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Get physical address from frame object
    let frame_phys = object_table::with_frame_mut(frame_ref, |frame| frame.phys_addr.as_u64())
        .ok_or(SyscallError::Revoked)?;

    // Get IOSpace and perform mapping
    object_table::with_iospace_mut(iospace_ref, |iospace| {
        // TODO: Add frame to IOSpace page tables
        // This requires:
        // 1. Walking/creating I/O page tables
        // 2. Installing PTE with frame_phys at iova
        // 3. Invalidating IOTLB for the ASID

        let _ = (iova, frame_phys); // Suppress unused warnings
        let _ = iospace;

        log::warn!("IOSpaceMapFrame: page table manipulation not yet implemented");
        Err(SyscallError::NotSupported)
    })
    .ok_or(SyscallError::Revoked)?
}

/// Handle IOSpaceUnmapFrame syscall.
///
/// Unmaps a frame from an IOSpace.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to IOSpace
/// - x1: iova - I/O virtual address to unmap
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_unmap_frame(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let iova = args.arg1;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    let iospace_ref = cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Get IOSpace and perform unmapping
    object_table::with_iospace_mut(iospace_ref, |iospace| {
        // TODO: Remove mapping from IOSpace page tables
        // This requires:
        // 1. Walking I/O page tables to find PTE
        // 2. Clearing the PTE
        // 3. Invalidating IOTLB for the ASID

        let _ = iova; // Suppress unused warning
        let _ = iospace;

        log::warn!("IOSpaceUnmapFrame: page table manipulation not yet implemented");
        Err(SyscallError::NotSupported)
    })
    .ok_or(SyscallError::Revoked)?
}

/// Handle IOSpaceBindStream syscall.
///
/// Binds a PCIe stream ID to an IOSpace. After binding, DMA from the
/// device with that stream ID will be translated through this IOSpace.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to IOSpace
/// - x1: smmu_control_cptr - Capability to SmmuControl
/// - x2: stream_id - PCIe stream ID to bind
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_bind_stream(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let smmu_cptr = args.arg1;
    let stream_id = args.arg2 as u32;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify SmmuControl capability
    let smmu_loc = cspace::resolve_cptr(smmu_cptr, 0)?;
    let smmu_ref = cspace::with_slot(&smmu_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::SmmuControl {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    let iospace_ref = cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Check stream ID is available (not already claimed)
    let stream_available = object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| {
        smmu_ctrl.is_stream_available(stream_id)
    })
    .ok_or(SyscallError::Revoked)?;

    if !stream_available {
        return Err(SyscallError::SlotOccupied);
    }

    // Get IOSpace details for STE configuration
    let (root_table, ioasid, smmu_index) = object_table::with_iospace_mut(iospace_ref, |iospace| {
        (
            iospace.root_table.as_u64(),
            iospace.ioasid.value(),
            iospace.smmu_index,
        )
    })
    .ok_or(SyscallError::Revoked)?;

    // Configure STE in SMMU
    smmu::with_smmu(smmu_index, |smmu| {
        use crate::smmu::registers::{ContextDescriptor, StreamTableEntry};

        // Create context descriptor for this IOSpace
        // T0SZ=16 for 48-bit address space with 4KB pages
        let cd = ContextDescriptor::new_stage1(root_table, ioasid, 16);

        // TODO: Allocate CD table and install CD
        // For now, configure STE with S1CDMax=0 (single CD)
        let ste = StreamTableEntry::new_s1_only(root_table, 0);

        smmu.configure_ste(stream_id, ste)?;

        let _ = cd; // CD will be used when CD table allocation is implemented

        Ok::<(), SmmuError>(())
    })
    .map_err(smmu_error_to_syscall)?;

    // Mark stream as claimed
    object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| {
        smmu_ctrl.claim_stream(stream_id);
    });

    // Update IOSpace stream count
    object_table::with_iospace_mut(iospace_ref, |iospace| {
        iospace.stream_count = iospace.stream_count.saturating_add(1);
        iospace.is_active = true;
    });

    log::debug!("Bound stream {} to IOSpace (IOASID {})", stream_id, ioasid);
    Ok(0)
}

/// Handle IOSpaceUnbindStream syscall.
///
/// Unbinds a PCIe stream ID from an IOSpace.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to IOSpace
/// - x1: smmu_control_cptr - Capability to SmmuControl
/// - x2: stream_id - PCIe stream ID to unbind
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_unbind_stream(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let smmu_cptr = args.arg1;
    let stream_id = args.arg2 as u32;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify SmmuControl capability
    let smmu_loc = cspace::resolve_cptr(smmu_cptr, 0)?;
    let smmu_ref = cspace::with_slot(&smmu_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::SmmuControl {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    let iospace_ref = cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Check stream ID is currently claimed
    let stream_available = object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| {
        smmu_ctrl.is_stream_available(stream_id)
    })
    .ok_or(SyscallError::Revoked)?;

    if stream_available {
        // Stream not bound, nothing to unbind
        return Err(SyscallError::InvalidArg);
    }

    // Get SMMU index from IOSpace
    let smmu_index = object_table::with_iospace_mut(iospace_ref, |iospace| iospace.smmu_index)
        .ok_or(SyscallError::Revoked)?;

    // Configure bypass STE in SMMU (invalidates the stream)
    smmu::with_smmu(smmu_index, |smmu| {
        use crate::smmu::registers::StreamTableEntry;

        let ste = StreamTableEntry::bypass();
        smmu.configure_ste(stream_id, ste)?;
        Ok::<(), SmmuError>(())
    })
    .map_err(smmu_error_to_syscall)?;

    // Release stream
    object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| {
        smmu_ctrl.release_stream(stream_id);
    });

    // Update IOSpace stream count
    object_table::with_iospace_mut(iospace_ref, |iospace| {
        iospace.stream_count = iospace.stream_count.saturating_sub(1);
        if iospace.stream_count == 0 {
            iospace.is_active = false;
        }
    });

    log::debug!("Unbound stream {} from IOSpace", stream_id);
    Ok(0)
}

/// Handle DmaPoolCreate syscall.
///
/// Creates a DMA pool for IOVA allocation within an IOSpace.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to parent IOSpace
/// - x1: iova_base - Start of IOVA range for this pool
/// - x2: iova_size - Size of IOVA range
/// - x3: dest_cnode_cptr - CNode for new DmaPool capability
/// - x4: dest_index - Slot index for new capability
/// - x5: dest_depth - Bits to consume resolving dest CNode
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_dma_pool_create(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let _iova_base = args.arg1;
    let _iova_size = args.arg2;
    let dest_cnode_cptr = args.arg3;
    let dest_index = args.arg4 as usize;
    let dest_depth = args.arg5 as u8;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(())
    })?;

    // Resolve destination slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Verify destination slot is empty
    verify_slot_empty(&dest_loc)?;

    // TODO: Create DmaPool object and install capability
    log::warn!("DmaPoolCreate: object creation not yet implemented");
    Err(SyscallError::NotSupported)
}

/// Handle DmaPoolAlloc syscall.
///
/// Allocates an IOVA range from a DMA pool.
///
/// # Arguments (registers)
///
/// - x0: dma_pool_cptr - Capability to DmaPool
/// - x1: size - Size of allocation in bytes
/// - x2: alignment - Required alignment (power of 2)
///
/// # Returns
///
/// IOVA on success (in x0), negative error code on failure.
pub fn handle_dma_pool_alloc(args: &SyscallArgs) -> SyscallResult {
    let pool_cptr = args.arg0;
    let size = args.arg1;
    let alignment = args.arg2;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify DmaPool capability
    let pool_loc = cspace::resolve_cptr(pool_cptr, 0)?;
    let pool_ref = cspace::with_slot(&pool_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::DmaPool {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Validate alignment (must be power of 2)
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(SyscallError::InvalidArg);
    }

    // Allocate from pool (bump allocator)
    object_table::with_dma_pool_mut(pool_ref, |pool| {
        // Round up watermark to alignment
        let aligned_watermark = (pool.alloc_watermark + alignment - 1) & !(alignment - 1);

        // Check if allocation fits
        if aligned_watermark + size > pool.iova_base + pool.iova_size {
            return Err(SyscallError::NoMemory);
        }

        // Check allocation count limit
        if pool.alloc_count >= pool.max_allocs {
            return Err(SyscallError::NoMemory);
        }

        let iova = aligned_watermark;
        pool.alloc_watermark = aligned_watermark + size;
        pool.alloc_count += 1;

        Ok(iova as i64)
    })
    .ok_or(SyscallError::Revoked)?
}

/// Handle DmaPoolFree syscall.
///
/// Frees an IOVA range back to a DMA pool.
///
/// Note: Current implementation uses a bump allocator, so individual
/// frees are not supported. The entire pool is freed when destroyed.
///
/// # Arguments (registers)
///
/// - x0: dma_pool_cptr - Capability to DmaPool
/// - x1: iova - IOVA to free
/// - x2: size - Size of allocation
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_dma_pool_free(args: &SyscallArgs) -> SyscallResult {
    let pool_cptr = args.arg0;
    let _iova = args.arg1;
    let _size = args.arg2;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify DmaPool capability
    let pool_loc = cspace::resolve_cptr(pool_cptr, 0)?;
    let pool_ref = cspace::with_slot(&pool_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::DmaPool {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Decrement allocation count
    // Note: With bump allocator, we don't actually free space
    object_table::with_dma_pool_mut(pool_ref, |pool| {
        pool.alloc_count = pool.alloc_count.saturating_sub(1);
    });

    log::trace!("DmaPoolFree: bump allocator does not support individual frees");
    Ok(0)
}
