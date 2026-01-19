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

use core::mem::ManuallyDrop;
use core::sync::atomic::Ordering;

use m6_cap::objects::{DmaPoolObject, IOSpaceObject, Ioasid};
use m6_cap::{Badge, CapRights, CapSlot, ObjectType, SlotFlags};

use crate::cap::cspace::{self, SlotLocation};
use crate::cap::object_table::{self, KernelObjectType};
use crate::memory::frame::{alloc_frame_zeroed, free_frame};
use crate::memory::translate::phys_to_virt;
use crate::smmu::{self, SmmuError};
use crate::syscall::SyscallArgs;
use crate::syscall::error::{SyscallError, SyscallResult};

// -- I/O page table constants (same as CPU page tables)

/// Page size (4KB).
const PAGE_SIZE: u64 = 4096;
/// Index mask (9 bits).
const INDEX_MASK: u64 = 0x1FF;

/// Shifts for extracting table indices from IOVA.
const L0_SHIFT: u32 = 39;
const L1_SHIFT: u32 = 30;
const L2_SHIFT: u32 = 21;
const L3_SHIFT: u32 = 12;

/// Table descriptor: valid=1, type=1 (0b11).
const TABLE_DESCRIPTOR: u64 = 0b11;
/// Page descriptor: valid=1, type=1 (0b11 for L3).
const PAGE_DESCRIPTOR: u64 = 0b11;

// -- I/O page table helpers

/// Extract L0 index from IOVA.
#[inline]
fn l0_index(iova: u64) -> usize {
    ((iova >> L0_SHIFT) & INDEX_MASK) as usize
}

/// Extract L1 index from IOVA.
#[inline]
fn l1_index(iova: u64) -> usize {
    ((iova >> L1_SHIFT) & INDEX_MASK) as usize
}

/// Extract L2 index from IOVA.
#[inline]
fn l2_index(iova: u64) -> usize {
    ((iova >> L2_SHIFT) & INDEX_MASK) as usize
}

/// Extract L3 index from IOVA.
#[inline]
fn l3_index(iova: u64) -> usize {
    ((iova >> L3_SHIFT) & INDEX_MASK) as usize
}

/// Check if a descriptor is valid.
#[inline]
fn is_valid(desc: u64) -> bool {
    desc & 0b1 != 0
}

/// Check if a descriptor is a table pointer (not a block).
#[inline]
fn is_table(desc: u64) -> bool {
    desc & 0b11 == TABLE_DESCRIPTOR
}

/// Extract next-level table physical address from a table descriptor.
#[inline]
fn table_address(desc: u64) -> u64 {
    desc & 0x0000_FFFF_FFFF_F000
}

/// Create a table descriptor pointing to a page table.
#[inline]
fn make_table_descriptor(table_phys: u64) -> u64 {
    (table_phys & 0x0000_FFFF_FFFF_F000) | TABLE_DESCRIPTOR
}

/// Create an L3 page descriptor for a 4KB page.
///
/// Creates a descriptor with:
/// - Valid bit set
/// - AF (Access Flag) set
/// - Normal memory attributes
/// - Inner Shareable
/// - Read/write permissions based on `writable`
#[inline]
fn make_page_descriptor(frame_phys: u64, writable: bool) -> u64 {
    let mut desc = (frame_phys & 0x0000_FFFF_FFFF_F000) | PAGE_DESCRIPTOR;

    // Set Access Flag (bit 10)
    desc |= 1 << 10;

    // Set shareability to Inner Shareable (bits [9:8] = 0b11)
    desc |= 0b11 << 8;

    // Set permissions
    if !writable {
        // AP = 0b10 (read-only at EL1)
        desc |= 0b10 << 6;
    }
    // else AP = 0b00 (read/write at EL1) which is the default

    // Disable execution (UXN=1, PXN=1) - DMA buffers shouldn't be executable
    desc |= 1 << 54; // UXN
    desc |= 1 << 53; // PXN

    desc
}

/// Walk I/O page tables and map a frame at the given IOVA.
///
/// Allocates intermediate page tables as needed.
///
/// # Arguments
/// - `root_table_phys`: Physical address of the root (L0) page table
/// - `iova`: I/O virtual address to map at (must be page-aligned)
/// - `frame_phys`: Physical address of the frame to map (must be page-aligned)
/// - `writable`: Whether the mapping should be writable
///
/// # Returns
/// - `Ok(())` on success
/// - `Err(SyscallError::NoMemory)` if intermediate table allocation fails
/// - `Err(SyscallError::AlreadyMapped)` if IOVA is already mapped
fn iospace_map_page(
    root_table_phys: u64,
    iova: u64,
    frame_phys: u64,
    writable: bool,
) -> Result<(), SyscallError> {
    // Get indices for each level
    let l0_idx = l0_index(iova);
    let l1_idx = l1_index(iova);
    let l2_idx = l2_index(iova);
    let l3_idx = l3_index(iova);

    // Walk L0 -> L1
    let l0_table = phys_to_virt(root_table_phys) as *mut u64;
    // SAFETY: root_table_phys is a valid page table allocated by IOSpaceCreate
    let l0_entry = unsafe { l0_table.add(l0_idx).read_volatile() };

    let l1_table_phys = if is_valid(l0_entry) {
        if !is_table(l0_entry) {
            // L0 cannot have block entries
            return Err(SyscallError::InvalidArg);
        }
        table_address(l0_entry)
    } else {
        // Allocate L1 table
        let new_table = alloc_frame_zeroed().ok_or(SyscallError::NoMemory)?;
        let desc = make_table_descriptor(new_table);
        // SAFETY: Writing to a valid page table entry
        unsafe { l0_table.add(l0_idx).write_volatile(desc) };
        new_table
    };

    // Walk L1 -> L2
    let l1_table = phys_to_virt(l1_table_phys) as *mut u64;
    // SAFETY: l1_table_phys points to a valid page table
    let l1_entry = unsafe { l1_table.add(l1_idx).read_volatile() };

    let l2_table_phys = if is_valid(l1_entry) {
        if !is_table(l1_entry) {
            // Block entry at L1 would conflict with our 4KB mapping
            return Err(SyscallError::AlreadyMapped);
        }
        table_address(l1_entry)
    } else {
        // Allocate L2 table
        let new_table = alloc_frame_zeroed().ok_or(SyscallError::NoMemory)?;
        let desc = make_table_descriptor(new_table);
        // SAFETY: Writing to a valid page table entry
        unsafe { l1_table.add(l1_idx).write_volatile(desc) };
        new_table
    };

    // Walk L2 -> L3
    let l2_table = phys_to_virt(l2_table_phys) as *mut u64;
    // SAFETY: l2_table_phys points to a valid page table
    let l2_entry = unsafe { l2_table.add(l2_idx).read_volatile() };

    let l3_table_phys = if is_valid(l2_entry) {
        if !is_table(l2_entry) {
            // Block entry at L2 would conflict with our 4KB mapping
            return Err(SyscallError::AlreadyMapped);
        }
        table_address(l2_entry)
    } else {
        // Allocate L3 table
        let new_table = alloc_frame_zeroed().ok_or(SyscallError::NoMemory)?;
        let desc = make_table_descriptor(new_table);
        // SAFETY: Writing to a valid page table entry
        unsafe { l2_table.add(l2_idx).write_volatile(desc) };
        new_table
    };

    // Install L3 entry
    let l3_table = phys_to_virt(l3_table_phys) as *mut u64;
    // SAFETY: l3_table_phys points to a valid page table
    let l3_entry = unsafe { l3_table.add(l3_idx).read_volatile() };

    if is_valid(l3_entry) {
        return Err(SyscallError::AlreadyMapped);
    }

    let page_desc = make_page_descriptor(frame_phys, writable);
    // SAFETY: Writing to a valid page table entry
    unsafe { l3_table.add(l3_idx).write_volatile(page_desc) };

    // Memory barrier to ensure visibility
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    Ok(())
}

/// Walk I/O page tables and unmap a frame at the given IOVA.
///
/// # Arguments
/// - `root_table_phys`: Physical address of the root (L0) page table
/// - `iova`: I/O virtual address to unmap (must be page-aligned)
///
/// # Returns
/// - `Ok(frame_phys)` with the unmapped frame's physical address
/// - `Err(SyscallError::NotMapped)` if IOVA is not mapped
fn iospace_unmap_page(root_table_phys: u64, iova: u64) -> Result<u64, SyscallError> {
    // Get indices for each level
    let l0_idx = l0_index(iova);
    let l1_idx = l1_index(iova);
    let l2_idx = l2_index(iova);
    let l3_idx = l3_index(iova);

    // Walk L0 -> L1
    let l0_table = phys_to_virt(root_table_phys) as *mut u64;
    // SAFETY: root_table_phys is a valid page table
    let l0_entry = unsafe { l0_table.add(l0_idx).read_volatile() };

    if !is_valid(l0_entry) || !is_table(l0_entry) {
        return Err(SyscallError::NotMapped);
    }
    let l1_table_phys = table_address(l0_entry);

    // Walk L1 -> L2
    let l1_table = phys_to_virt(l1_table_phys) as *mut u64;
    // SAFETY: l1_table_phys points to a valid page table
    let l1_entry = unsafe { l1_table.add(l1_idx).read_volatile() };

    if !is_valid(l1_entry) || !is_table(l1_entry) {
        return Err(SyscallError::NotMapped);
    }
    let l2_table_phys = table_address(l1_entry);

    // Walk L2 -> L3
    let l2_table = phys_to_virt(l2_table_phys) as *mut u64;
    // SAFETY: l2_table_phys points to a valid page table
    let l2_entry = unsafe { l2_table.add(l2_idx).read_volatile() };

    if !is_valid(l2_entry) || !is_table(l2_entry) {
        return Err(SyscallError::NotMapped);
    }
    let l3_table_phys = table_address(l2_entry);

    // Read and clear L3 entry
    let l3_table = phys_to_virt(l3_table_phys) as *mut u64;
    // SAFETY: l3_table_phys points to a valid page table
    let l3_entry = unsafe { l3_table.add(l3_idx).read_volatile() };

    if !is_valid(l3_entry) {
        return Err(SyscallError::NotMapped);
    }

    let frame_phys = table_address(l3_entry); // Same mask works for page address

    // Clear the entry (0 = invalid descriptor)
    // SAFETY: Writing to a valid page table entry
    unsafe { l3_table.add(l3_idx).write_volatile(0) };

    // Memory barrier
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    Ok(frame_phys)
}

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
    let untyped_cptr = args.arg1;
    let dest_cnode_cptr = args.arg2;
    let dest_index = args.arg3 as usize;
    let dest_depth = args.arg4 as u8;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify SmmuControl capability and get object ref
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

    // Verify untyped capability and get object ref
    let untyped_loc = cspace::resolve_cptr(untyped_cptr, 0)?;
    let untyped_ref = cspace::with_slot(&untyped_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::Untyped {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Resolve destination slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Verify destination slot is empty
    verify_slot_empty(&dest_loc)?;

    // Allocate 4KB from untyped for root page table
    let root_table_phys =
        object_table::with_untyped_mut(untyped_ref, |ut| ut.try_allocate(4096, 4096))
            .ok_or(SyscallError::Revoked)?
            .map_err(|_| SyscallError::NoMemory)?;

    // Zero the page table memory (important for invalid PTEs)
    let root_table_virt = phys_to_virt(root_table_phys.as_u64());
    // SAFETY: We just allocated this memory and it's mapped via direct physical map
    unsafe {
        core::ptr::write_bytes(root_table_virt as *mut u8, 0, 4096);
    }

    // Get SMMU index from SmmuControl
    let smmu_index =
        object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| smmu_ctrl.smmu_index)
            .ok_or(SyscallError::Revoked)?;

    // Allocate IOASID from SmmuControl
    let ioasid =
        object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| smmu_ctrl.alloc_ioasid())
            .ok_or(SyscallError::Revoked)?
            .ok_or(SyscallError::NoMemory)?;

    // Allocate object table entry for IOSpace
    let iospace_ref =
        object_table::alloc(KernelObjectType::IOSpace).ok_or(SyscallError::NoMemory)?;

    // Create IOSpaceObject with allocated page table and IOASID
    object_table::with_object_mut(iospace_ref, |obj| {
        obj.data.iospace = ManuallyDrop::new(IOSpaceObject {
            root_table: root_table_phys,
            ioasid: Ioasid::new(ioasid),
            root_table_cap: untyped_ref, // Track source untyped for revocation
            mapped_frames: 0,
            stream_count: 0,
            is_active: false,
            smmu_index,
        });
    });

    // Install capability in destination slot
    cspace::with_slot_mut(&dest_loc, |slot| {
        *slot = CapSlot::new(
            iospace_ref,
            ObjectType::IOSpace,
            CapRights::ALL,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL,
        );
        Ok(())
    })?;

    // Increment SmmuControl IOSpace count
    object_table::with_smmu_control_mut(smmu_ref, |smmu_ctrl| {
        smmu_ctrl.increment_iospaces();
    });

    log::debug!(
        "Created IOSpace: ref={:?} root_table={:#x} ioasid={}",
        iospace_ref,
        root_table_phys.as_u64(),
        ioasid
    );

    Ok(0)
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

    // Validate IOVA alignment
    if (iova & (PAGE_SIZE - 1)) != 0 {
        return Err(SyscallError::InvalidArg);
    }

    // Get physical address from frame object
    let frame_phys = object_table::with_frame_mut(frame_ref, |frame| frame.phys_addr.as_u64())
        .ok_or(SyscallError::Revoked)?;

    // Get IOSpace details for mapping and IOTLB invalidation
    let (root_table, ioasid, smmu_index) = object_table::with_iospace_mut(iospace_ref, |iospace| {
        (
            iospace.root_table.as_u64(),
            iospace.ioasid.value(),
            iospace.smmu_index,
        )
    })
    .ok_or(SyscallError::Revoked)?;

    // Determine if mapping should be writable
    let writable = (rights_bits & CapRights::WRITE.bits()) != 0;

    // Map the frame in I/O page tables
    iospace_map_page(root_table, iova, frame_phys, writable)?;

    // Invalidate IOTLB for the mapping
    smmu::with_smmu(smmu_index, |smmu| smmu.invalidate_va(ioasid, iova))
        .map_err(smmu_error_to_syscall)?
        .map_err(smmu_error_to_syscall)?;

    // Update mapped frames count (already validated iospace_ref above)
    let _ = object_table::with_iospace_mut(iospace_ref, |iospace| {
        iospace.mapped_frames = iospace.mapped_frames.saturating_add(1);
    });

    log::debug!(
        "IOSpace map: iova={:#x} -> frame={:#x} writable={}",
        iova,
        frame_phys,
        writable
    );

    Ok(0)
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

    // Validate IOVA alignment
    if (iova & (PAGE_SIZE - 1)) != 0 {
        return Err(SyscallError::InvalidArg);
    }

    // Get IOSpace details for unmapping and IOTLB invalidation
    let (root_table, ioasid, smmu_index) = object_table::with_iospace_mut(iospace_ref, |iospace| {
        (
            iospace.root_table.as_u64(),
            iospace.ioasid.value(),
            iospace.smmu_index,
        )
    })
    .ok_or(SyscallError::Revoked)?;

    // Unmap the frame from I/O page tables
    let _frame_phys = iospace_unmap_page(root_table, iova)?;

    // Invalidate IOTLB for the unmapped page
    smmu::with_smmu(smmu_index, |smmu| smmu.invalidate_va(ioasid, iova))
        .map_err(smmu_error_to_syscall)?
        .map_err(smmu_error_to_syscall)?;

    // Update mapped frames count (already validated iospace_ref above)
    let _ = object_table::with_iospace_mut(iospace_ref, |iospace| {
        iospace.mapped_frames = iospace.mapped_frames.saturating_sub(1);
    });

    log::debug!("IOSpace unmap: iova={:#x}", iova);

    Ok(0)
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

    // Allocate Context Descriptor table (1 frame = 64 CDs)
    let cd_table_phys = alloc_frame_zeroed().ok_or(SyscallError::NoMemory)?;
    let cd_table_virt = phys_to_virt(cd_table_phys);

    // Configure STE in SMMU
    smmu::with_smmu(smmu_index, |smmu| {
        use crate::smmu::registers::{ContextDescriptor, StreamTableEntry};

        // Create context descriptor for this IOSpace
        // T0SZ=16 for 48-bit address space with 4KB pages
        let cd = ContextDescriptor::new_stage1(root_table, ioasid, 16);

        // Install CD at index 0 in CD table
        // SAFETY: We just allocated and zeroed this frame, and cd_table_virt is valid
        unsafe {
            let cd_ptr = cd_table_virt as *mut ContextDescriptor;
            core::ptr::write_volatile(cd_ptr, cd);
        }

        // Memory barrier to ensure CD is written before STE
        core::sync::atomic::fence(Ordering::Release);

        // Configure STE with CD table base address
        // S1CDMax=0 (single CD at index 0)
        let ste = StreamTableEntry::new_s1_only(cd_table_phys, 0);
        smmu.configure_ste(stream_id, ste)?;

        // Register stream binding with fault handler tracking
        // For now, no fault handler (fault_notification = NULL, badge = 0)
        smmu.bind_stream(
            stream_id,
            cd_table_phys,
            iospace_ref,
            m6_cap::ObjectRef::NULL,
            0,
        )?;

        Ok::<(), SmmuError>(())
    })
    .map_err(smmu_error_to_syscall)?
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
    // Also retrieve and unbind the stream, freeing the CD table
    let cd_table_phys = smmu::with_smmu(smmu_index, |smmu| {
        use crate::smmu::registers::StreamTableEntry;

        // Get CD table address before unbinding
        let cd_table_phys = smmu
            .get_stream_binding(stream_id)
            .map(|binding| binding.cd_table_phys)
            .unwrap_or(0);

        // Configure bypass STE
        let ste = StreamTableEntry::bypass();
        smmu.configure_ste(stream_id, ste)?;

        // Unbind stream (clears binding entry)
        smmu.unbind_stream(stream_id)?;

        Ok::<u64, SmmuError>(cd_table_phys)
    })
    .map_err(smmu_error_to_syscall)?
    .map_err(smmu_error_to_syscall)?;

    // Free CD table frame if it was allocated
    if cd_table_phys != 0 {
        free_frame(cd_table_phys);
        log::debug!("Freed CD table frame at {:#x}", cd_table_phys);
    }

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

/// Handle IOSpaceSetFaultHandler syscall.
///
/// Configures fault notification for a bound stream.
///
/// # Arguments (registers)
///
/// - x0: iospace_cptr - Capability to IOSpace
/// - x1: stream_id - Stream ID to configure
/// - x2: notification_cptr - Notification for fault delivery
/// - x3: badge - Badge to OR with fault info
///
/// # Returns
///
/// 0 on success, negative error code on failure.
pub fn handle_iospace_set_fault_handler(args: &SyscallArgs) -> SyscallResult {
    let iospace_cptr = args.arg0;
    let stream_id = args.arg1 as u32;
    let notification_cptr = args.arg2;
    let badge = args.arg3;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Verify IOSpace capability
    let iospace_loc = cspace::resolve_cptr(iospace_cptr, 0)?;
    let (iospace_ref, smmu_index) = cspace::with_slot(&iospace_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::IOSpace {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }

        // Get SMMU index from IOSpace
        let smmu_index =
            object_table::with_iospace_mut(slot.object_ref(), |iospace| iospace.smmu_index)
                .ok_or(SyscallError::Revoked)?;

        Ok((slot.object_ref(), smmu_index))
    })?;

    // Verify notification capability
    let notification_loc = cspace::resolve_cptr(notification_cptr, 0)?;
    let notification_ref = cspace::with_slot(&notification_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != ObjectType::Notification {
            return Err(SyscallError::TypeMismatch);
        }
        if !slot.rights().contains(CapRights::WRITE) {
            return Err(SyscallError::NoRights);
        }
        Ok(slot.object_ref())
    })?;

    // Update stream binding fault handler
    smmu::with_smmu(smmu_index, |smmu| {
        // Verify stream is bound to this IOSpace
        let binding = smmu
            .get_stream_binding(stream_id)
            .ok_or(SmmuError::InvalidStreamId)?;

        if binding.iospace_ref != iospace_ref {
            return Err(SmmuError::InvalidConfig);
        }

        // Set fault handler
        smmu.set_fault_handler(stream_id, notification_ref, badge)?;

        Ok(())
    })
    .map_err(smmu_error_to_syscall)?
    .map_err(smmu_error_to_syscall)?;

    log::debug!(
        "Configured fault handler for stream {}: notif={:?} badge={:#x}",
        stream_id,
        notification_ref,
        badge
    );

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
    let iova_base = args.arg1;
    let iova_size = args.arg2;
    let dest_cnode_cptr = args.arg3;
    let dest_index = args.arg4 as usize;
    let dest_depth = args.arg5 as u8;

    // Check SMMU availability
    if !smmu::is_available() {
        return Err(SyscallError::NotSupported);
    }

    // Validate IOVA parameters
    if iova_base == 0 || iova_size == 0 {
        return Err(SyscallError::InvalidArg);
    }
    // Require page alignment
    if (iova_base & 0xFFF) != 0 || (iova_size & 0xFFF) != 0 {
        return Err(SyscallError::InvalidArg);
    }
    // Check for overflow
    if iova_base.checked_add(iova_size).is_none() {
        return Err(SyscallError::InvalidArg);
    }

    // Verify IOSpace capability and get object ref
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

    // Resolve destination slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Verify destination slot is empty
    verify_slot_empty(&dest_loc)?;

    // Allocate object table entry for DmaPool
    let pool_ref = object_table::alloc(KernelObjectType::DmaPool).ok_or(SyscallError::NoMemory)?;

    // Create DmaPoolObject
    object_table::with_object_mut(pool_ref, |obj| {
        obj.data.dma_pool =
            ManuallyDrop::new(DmaPoolObject::new(iospace_ref, iova_base, iova_size));
    });

    // Install capability in destination slot
    cspace::with_slot_mut(&dest_loc, |slot| {
        *slot = CapSlot::new(
            pool_ref,
            ObjectType::DmaPool,
            CapRights::ALL,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL,
        );
        Ok(())
    })?;

    log::debug!(
        "Created DmaPool: ref={:?} iospace={:?} base={:#x} size={:#x}",
        pool_ref,
        iospace_ref,
        iova_base,
        iova_size
    );

    Ok(0)
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
        // alloc_watermark is an offset from iova_base
        let aligned_watermark = (pool.alloc_watermark + alignment - 1) & !(alignment - 1);

        // Check if allocation fits within pool size
        let end = aligned_watermark.saturating_add(size);
        if end > pool.iova_size {
            return Err(SyscallError::NoMemory);
        }

        // Check allocation count limit (0 means unlimited)
        if pool.max_allocs > 0 && pool.alloc_count >= pool.max_allocs {
            return Err(SyscallError::NoMemory);
        }

        // Convert offset to absolute IOVA
        let iova = pool.iova_base.saturating_add(aligned_watermark);
        pool.alloc_watermark = end;
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
