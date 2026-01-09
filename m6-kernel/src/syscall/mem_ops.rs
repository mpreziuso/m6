//! Memory syscall handlers
//!
//! This module implements syscalls for memory management:
//! - Retype: Create typed objects from untyped memory
//! - MapFrame: Map a frame into a VSpace
//! - UnmapFrame: Unmap a frame from a VSpace
//! - MapPageTable: Map a page table into a VSpace

use core::mem::ManuallyDrop;

use m6_cap::{Badge, CapRights, CapSlot, ObjectRef, ObjectType, SlotFlags};
use m6_cap::objects::{FrameObject, PageTableLevel, UntypedObject, VSpaceObject};
use m6_cap::objects::untyped::{object_alignment, object_size};
use m6_common::PhysAddr;
use m6_paging::{
    address::{PA, TPA, VA},
    arch::arm64::{
        descriptors::{
            BlockPageMapper, L0Descriptor, L1Descriptor, L2Descriptor, L3Descriptor,
            PageTableEntry, TableMapper,
        },
        tables::{L0Table, PgTable, TableLevel},
    },
    permissions::{MemoryType, PtePermissions},
};

use crate::cap::{cspace, object_table};
use crate::cap::object_table::KernelObjectType;
use crate::ipc;

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};

// -- User address space boundary
const USER_SPACE_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

// -- Helper functions for page table operations

/// Convert syscall rights bitmap to PTE permissions.
///
/// Rights bitmap: R=1 (always), W=2, X=4
fn rights_to_pte_perms(rights: u64) -> PtePermissions {
    PtePermissions {
        read: true,
        write: rights & 2 != 0,
        execute: rights & 4 != 0,
        user: true,          // Always user-accessible for syscall mappings
        cow: false,
        global: false,       // User mappings are per-ASID
    }
}

/// Select memory type based on device flag.
fn select_memory_type(is_device: bool) -> MemoryType {
    if is_device {
        MemoryType::Device
    } else {
        MemoryType::Normal
    }
}

/// Handle Retype syscall.
///
/// Creates typed kernel objects from untyped memory.
///
/// # ABI
///
/// - x0: Untyped capability pointer
/// - x1: Target object type (ObjectType enum value)
/// - x2: Size bits (for variable-size objects like CNode, Untyped)
/// - x3: Destination CNode capability pointer
/// - x4: Destination slot index
/// - x5: Number of objects to create
///
/// # Returns
///
/// - Number of objects created on success
/// - Negative error code on failure
pub fn handle_retype(args: &SyscallArgs) -> SyscallResult {
    let untyped_cptr = args.arg0;
    let target_type_raw = args.arg1;
    let size_bits = args.arg2 as u8;
    let dest_cnode_cptr = args.arg3;
    let dest_index = args.arg4 as usize;
    let count = args.arg5 as usize;

    // Validate count
    if count == 0 || count > 256 {
        return Err(SyscallError::Range);
    }

    // Parse target object type
    let target_type = object_type_from_raw(target_type_raw as u8)
        .ok_or(SyscallError::InvalidArg)?;

    // Can't retype to Empty
    if target_type == ObjectType::Empty {
        return Err(SyscallError::InvalidArg);
    }

    // Look up untyped capability with WRITE right
    let untyped_cap = ipc::lookup_cap(untyped_cptr, ObjectType::Untyped, CapRights::WRITE)?;

    // Look up destination CNode with WRITE right
    let _dest_cnode_cap = ipc::lookup_cap(dest_cnode_cptr, ObjectType::CNode, CapRights::WRITE)?;

    // Get object size and alignment
    let obj_size = object_size(target_type, size_bits)
        .map_err(|_| SyscallError::InvalidArg)?;
    let obj_align = object_alignment(target_type, size_bits);

    // Map target type to kernel object type
    let kernel_type = object_type_to_kernel_type(target_type)?;

    // Track how many objects we successfully created
    let mut created = 0usize;

    // For each object to create
    for i in 0..count {
        let slot_index = dest_index + i;

        // Check destination slot is empty
        let slot_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, 0, slot_index)?;

        let slot_empty = cspace::with_slot(&slot_loc, |slot| {
            Ok(slot.is_empty())
        })?;

        if !slot_empty {
            if created == 0 {
                return Err(SyscallError::SlotOccupied);
            }
            break; // Partial success
        }

        // Allocate from untyped
        let phys_addr = object_table::with_untyped_mut(untyped_cap.obj_ref, |untyped| {
            untyped.try_allocate(obj_size, obj_align)
                .map_err(|_| SyscallError::NoMemory)
        }).ok_or(SyscallError::InvalidCap)??;

        // Allocate object table entry
        let obj_ref = object_table::alloc(kernel_type)
            .ok_or(SyscallError::NoMemory)?;

        // Initialise object-specific data
        let init_result = init_kernel_object(obj_ref, kernel_type, phys_addr, size_bits, target_type);
        if let Err(e) = init_result {
            // Free the allocated object table entry
            // SAFETY: We just allocated this and haven't stored any pointers yet.
            unsafe { object_table::free(obj_ref) };
            if created == 0 {
                return Err(e);
            }
            break;
        }

        // Create capability in destination slot
        let cap_result = cspace::with_slot_mut(&slot_loc, |slot| {
            *slot = CapSlot::new(
                obj_ref,
                target_type,
                CapRights::ALL, // Full rights for original capability
                Badge::NONE,
                SlotFlags::IS_ORIGINAL,
            );
            Ok(())
        });

        if let Err(e) = cap_result {
            // Cleanup on failure
            // SAFETY: Object was just created and not yet referenced.
            unsafe { object_table::free(obj_ref) };
            if created == 0 {
                return Err(e);
            }
            break;
        }

        // Increment reference count
        object_table::with_table(|table| table.inc_ref(obj_ref));

        created += 1;
    }

    Ok(created as i64)
}

/// Handle MapFrame syscall.
///
/// Maps a frame capability into a VSpace at a specified virtual address.
///
/// # ABI
///
/// - x0: VSpace capability pointer
/// - x1: Frame capability pointer
/// - x2: Virtual address to map at
/// - x3: Access rights (bitmap: R=1, W=2, X=4)
/// - x4: Memory attributes (0=normal, 1=device)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_map_frame(args: &SyscallArgs) -> SyscallResult {
    let vspace_cptr = args.arg0;
    let frame_cptr = args.arg1;
    let vaddr = args.arg2;
    let rights_raw = args.arg3;
    let attr = args.arg4;

    // Look up VSpace capability with WRITE right
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::WRITE)?;

    // Determine required frame rights based on mapping rights
    let required_rights = if rights_raw & 2 != 0 {
        CapRights::RW
    } else {
        CapRights::READ
    };

    // Look up frame capability
    let frame_cap = ipc::lookup_cap(frame_cptr, ObjectType::Frame, required_rights)?;

    // Get frame info
    let (frame_phys, frame_size_bits, is_device) = object_table::with_frame_mut(
        frame_cap.obj_ref,
        |frame| (frame.phys_addr, frame.size_bits, frame.is_device),
    ).ok_or(SyscallError::InvalidCap)?;

    let frame_size = 1usize << frame_size_bits;

    // Validate virtual address
    if vaddr > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Must be aligned to frame size
    let alignment_mask = (frame_size - 1) as u64;
    if vaddr & alignment_mask != 0 {
        return Err(SyscallError::Alignment);
    }

    // Get VSpace root table address
    let root_table = object_table::with_vspace(vspace_cap.obj_ref, |vspace| {
        vspace.root_table
    }).ok_or(SyscallError::InvalidCap)?;

    // Walk page tables and install mapping
    // This is a simplified implementation - full implementation would need
    // to walk the page table hierarchy and potentially allocate intermediate tables
    let map_result = install_mapping(
        root_table,
        vaddr,
        frame_phys,
        frame_size_bits,
        rights_raw,
        attr,
        is_device,
    );

    map_result?;

    // Update frame map count
    object_table::with_frame_mut(frame_cap.obj_ref, |frame| {
        frame.increment_map_count();
    });

    // Update VSpace mapped frames count
    object_table::with_vspace_mut(vspace_cap.obj_ref, |vspace| {
        vspace.increment_frames();
    });

    Ok(0)
}

/// Handle UnmapFrame syscall.
///
/// Unmaps a frame from a VSpace.
///
/// # ABI
///
/// - x0: VSpace capability pointer
/// - x1: Virtual address to unmap
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_unmap_frame(args: &SyscallArgs) -> SyscallResult {
    let vspace_cptr = args.arg0;
    let vaddr = args.arg1;

    // Look up VSpace capability with WRITE right
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::WRITE)?;

    // Validate virtual address (must be page-aligned)
    if vaddr & 0xFFF != 0 {
        return Err(SyscallError::Alignment);
    }

    if vaddr > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Get VSpace info
    let (root_table, asid, is_active) = object_table::with_vspace(
        vspace_cap.obj_ref,
        |vspace| (vspace.root_table, vspace.asid, vspace.is_active),
    ).ok_or(SyscallError::InvalidCap)?;

    // Walk page tables and clear mapping
    clear_mapping(root_table, vaddr)?;

    // Issue TLB invalidation if VSpace is active
    if is_active {
        invalidate_tlb_entry(vaddr, asid.value());
    }

    // Update VSpace mapped frames count
    object_table::with_vspace_mut(vspace_cap.obj_ref, |vspace| {
        vspace.decrement_frames();
    });

    Ok(0)
}

/// Handle MapPageTable syscall.
///
/// Maps a page table capability into a VSpace at a given level.
///
/// # ABI
///
/// - x0: VSpace capability pointer
/// - x1: Page table capability pointer
/// - x2: Virtual address this page table will cover
/// - x3: Level (1-3, L0 is root and not mappable)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_map_page_table(args: &SyscallArgs) -> SyscallResult {
    let vspace_cptr = args.arg0;
    let pt_cptr = args.arg1;
    let vaddr = args.arg2;
    let level_raw = args.arg3;

    // Validate level (1-3, cannot map L0 which is root)
    if !(1..=3).contains(&level_raw) {
        return Err(SyscallError::InvalidArg);
    }

    let level = match level_raw {
        1 => PageTableLevel::L1,
        2 => PageTableLevel::L2,
        3 => PageTableLevel::L3,
        _ => return Err(SyscallError::InvalidArg),
    };

    // Look up VSpace capability with WRITE right
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::WRITE)?;

    // Look up page table capability - determine correct type based on level
    let pt_type = match level {
        PageTableLevel::L0 => ObjectType::PageTableL0,
        PageTableLevel::L1 => ObjectType::PageTableL1,
        PageTableLevel::L2 => ObjectType::PageTableL2,
        PageTableLevel::L3 => ObjectType::PageTableL3,
    };
    let pt_cap = ipc::lookup_cap(pt_cptr, pt_type, CapRights::WRITE)?;

    // Validate virtual address alignment for the level
    let alignment = level.entry_coverage() as u64;
    if vaddr & (alignment - 1) != 0 {
        return Err(SyscallError::Alignment);
    }

    if vaddr > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Get VSpace root table
    let root_table = object_table::with_vspace(vspace_cap.obj_ref, |vspace| {
        vspace.root_table
    }).ok_or(SyscallError::InvalidCap)?;

    // Get page table physical address
    let pt_phys = object_table::with_page_table(pt_cap.obj_ref, |pt| {
        pt.phys_addr
    }).ok_or(SyscallError::InvalidCap)?;

    // Install the page table in the parent level
    install_page_table(root_table, vaddr, pt_phys, level)?;

    // Update VSpace page table count
    object_table::with_vspace_mut(vspace_cap.obj_ref, |vspace| {
        vspace.increment_page_tables();
    });

    Ok(0)
}

// -- Helper functions

/// Convert ObjectType to KernelObjectType.
fn object_type_to_kernel_type(obj_type: ObjectType) -> Result<KernelObjectType, SyscallError> {
    match obj_type {
        ObjectType::Untyped => Ok(KernelObjectType::Untyped),
        ObjectType::Frame => Ok(KernelObjectType::Frame),
        ObjectType::DeviceFrame => Ok(KernelObjectType::DeviceFrame),
        ObjectType::PageTableL0 | ObjectType::PageTableL1 |
        ObjectType::PageTableL2 | ObjectType::PageTableL3 => Ok(KernelObjectType::PageTable),
        ObjectType::VSpace => Ok(KernelObjectType::VSpace),
        ObjectType::ASIDPool => Ok(KernelObjectType::AsidPool),
        ObjectType::Endpoint => Ok(KernelObjectType::Endpoint),
        ObjectType::Notification => Ok(KernelObjectType::Notification),
        ObjectType::Reply => Ok(KernelObjectType::Reply),
        ObjectType::CNode => Ok(KernelObjectType::CNode),
        ObjectType::TCB => Ok(KernelObjectType::Tcb),
        ObjectType::IRQHandler => Ok(KernelObjectType::IrqHandler),
        ObjectType::SchedContext => Ok(KernelObjectType::SchedContext),
        ObjectType::IOSpace => Ok(KernelObjectType::IOSpace),
        ObjectType::DmaPool => Ok(KernelObjectType::DmaPool),
        _ => Err(SyscallError::InvalidArg),
    }
}

/// Initialise a kernel object after allocation.
fn init_kernel_object(
    obj_ref: ObjectRef,
    kernel_type: KernelObjectType,
    phys_addr: PhysAddr,
    size_bits: u8,
    _obj_type: ObjectType,
) -> Result<(), SyscallError> {
    object_table::with_object_mut(obj_ref, |obj| {
        match kernel_type {
            KernelObjectType::Frame | KernelObjectType::DeviceFrame => {
                let is_device = kernel_type == KernelObjectType::DeviceFrame;
                let frame = FrameObject::new(phys_addr, size_bits, is_device);
                obj.data.frame = ManuallyDrop::new(frame);
            }
            KernelObjectType::Untyped => {
                let untyped = UntypedObject::new(phys_addr, size_bits, false);
                obj.data.untyped = ManuallyDrop::new(untyped);
            }
            KernelObjectType::VSpace => {
                let vspace = VSpaceObject::new(phys_addr, ObjectRef::NULL);
                obj.data.vspace = ManuallyDrop::new(vspace);
            }
            // For other types, zeroed memory is a valid initial state
            // or they need special handling (TCB, CNode need heap allocation)
            KernelObjectType::Tcb => {
                // TCB needs heap allocation
                let tcb_ptr = crate::cap::tcb_storage::create_tcb()
                    .map_err(|_| SyscallError::NoMemory)?;
                obj.data.tcb_ptr = tcb_ptr;
            }
            KernelObjectType::CNode => {
                // CNode needs heap allocation based on size_bits
                // For now, return error - needs more complex initialisation
                return Err(SyscallError::NotSupported);
            }
            _ => {
                // Other objects: zeroed is valid initial state
            }
        }
        Ok(())
    }).ok_or(SyscallError::InvalidCap)?
}

/// Install a memory mapping in the page tables.
///
/// Walks the page table hierarchy and installs the mapping at the appropriate level.
/// Intermediate page tables must already exist (seL4 model - userspace pre-installs them).
///
/// # Arguments
///
/// * `root_table` - Physical address of the L0 (root) page table
/// * `vaddr` - Virtual address to map at
/// * `phys_addr` - Physical address of the frame to map
/// * `size_bits` - Size of the frame (12 for 4KB, 21 for 2MB)
/// * `rights` - Access rights bitmap (R=1, W=2, X=4)
/// * `_attr` - Memory attributes (reserved for future use)
/// * `is_device` - Whether this is device memory
fn install_mapping(
    root_table: PhysAddr,
    vaddr: u64,
    phys_addr: PhysAddr,
    size_bits: u8,
    rights: u64,
    _attr: u64,
    is_device: bool,
) -> Result<(), SyscallError> {
    let va = VA::new(vaddr);
    let pa = PA::new(phys_addr.as_u64());
    let perms = rights_to_pte_perms(rights);
    let mem_type = select_memory_type(is_device);

    // Get L0 table from root physical address
    let l0 = unsafe { L0Table::from_pa(TPA::new(root_table.as_u64())) };

    // Walk L0 -> L1
    let Some(l1) = l0.get_next_table(va) else {
        log::debug!("install_mapping: L1 table missing for va={:#x}", vaddr);
        return Err(SyscallError::InvalidState);
    };

    // Check if L1 has a block mapping (1GB) - shouldn't happen for user mappings
    let l1_desc = l1.get_desc(va);
    if l1_desc.is_valid() && !l1_desc.is_table() {
        return Err(SyscallError::AlreadyMapped);
    }

    // Walk L1 -> L2
    let Some(mut l2) = l1.get_next_table(va) else {
        log::debug!("install_mapping: L2 table missing for va={:#x}", vaddr);
        return Err(SyscallError::InvalidState);
    };

    if size_bits == 21 {
        // 2MB block mapping at L2
        let l2_desc = l2.get_desc(va);
        if l2_desc.is_valid() {
            return Err(SyscallError::AlreadyMapped);
        }

        let new_desc = L2Descriptor::new_mapping(pa, mem_type, perms);
        // SAFETY: We verified the entry is not occupied
        unsafe { l2.set_desc(va, new_desc) };

        log::debug!(
            "MapFrame: installed 2MB block at va={:#x} -> pa={:#x}",
            vaddr,
            phys_addr.as_u64()
        );
    } else {
        // 4KB page mapping at L3
        let l2_desc = l2.get_desc(va);
        if l2_desc.is_valid() && !l2_desc.is_table() {
            // L2 entry is a block, cannot install L3 page here
            return Err(SyscallError::AlreadyMapped);
        }

        // Walk L2 -> L3
        let Some(mut l3) = l2.get_next_table(va) else {
            log::debug!("install_mapping: L3 table missing for va={:#x}", vaddr);
            return Err(SyscallError::InvalidState);
        };

        let l3_desc = l3.get_desc(va);
        if l3_desc.is_valid() {
            return Err(SyscallError::AlreadyMapped);
        }

        let new_desc = L3Descriptor::new_mapping(pa, mem_type, perms);
        // SAFETY: We verified the entry is not occupied
        unsafe { l3.set_desc(va, new_desc) };

        log::debug!(
            "MapFrame: installed 4KB page at va={:#x} -> pa={:#x}",
            vaddr,
            phys_addr.as_u64()
        );
    }

    // Memory barriers to ensure visibility
    m6_arch::cpu::dsb_sy();
    m6_arch::cpu::isb();

    Ok(())
}

/// Clear a memory mapping from the page tables.
///
/// Walks the page table hierarchy and clears the mapping.
///
/// # Arguments
///
/// * `root_table` - Physical address of the L0 (root) page table
/// * `vaddr` - Virtual address to unmap
fn clear_mapping(root_table: PhysAddr, vaddr: u64) -> Result<(), SyscallError> {
    let va = VA::new(vaddr);

    // Get L0 table from root physical address
    let l0 = unsafe { L0Table::from_pa(TPA::new(root_table.as_u64())) };

    // Walk L0 -> L1
    let Some(l1) = l0.get_next_table(va) else {
        return Err(SyscallError::NotMapped);
    };

    // Check L1 descriptor
    let l1_desc = l1.get_desc(va);
    if l1_desc.is_valid() && !l1_desc.is_table() {
        // 1GB block - we don't support unmapping these via syscall
        return Err(SyscallError::NotSupported);
    }

    // Walk L1 -> L2
    let Some(mut l2) = l1.get_next_table(va) else {
        return Err(SyscallError::NotMapped);
    };

    let l2_desc = l2.get_desc(va);
    if l2_desc.is_valid() && !l2_desc.is_table() {
        // 2MB block - clear it
        // SAFETY: We're clearing a valid mapping
        unsafe { l2.set_desc(va, L2Descriptor::invalid()) };

        log::debug!("UnmapFrame: cleared 2MB block at va={:#x}", vaddr);
    } else {
        // Walk L2 -> L3
        let Some(mut l3) = l2.get_next_table(va) else {
            return Err(SyscallError::NotMapped);
        };

        let l3_desc = l3.get_desc(va);
        if !l3_desc.is_valid() {
            return Err(SyscallError::NotMapped);
        }

        // Clear the 4KB page
        // SAFETY: We're clearing a valid mapping
        unsafe { l3.set_desc(va, L3Descriptor::invalid()) };

        log::debug!("UnmapFrame: cleared 4KB page at va={:#x}", vaddr);
    }

    // Memory barriers to ensure visibility
    m6_arch::cpu::dsb_sy();
    m6_arch::cpu::isb();

    Ok(())
}

/// Install a page table in its parent.
///
/// Walks to the parent level and installs a table descriptor pointing to
/// the new page table.
///
/// # Arguments
///
/// * `root_table` - Physical address of the L0 (root) page table
/// * `vaddr` - Virtual address this page table will cover
/// * `pt_phys` - Physical address of the page table to install
/// * `level` - The level of the page table being installed (L1, L2, or L3)
fn install_page_table(
    root_table: PhysAddr,
    vaddr: u64,
    pt_phys: PhysAddr,
    level: PageTableLevel,
) -> Result<(), SyscallError> {
    let va = VA::new(vaddr);
    let pa = PA::new(pt_phys.as_u64());

    // Get L0 table from root physical address
    let mut l0 = unsafe { L0Table::from_pa(TPA::new(root_table.as_u64())) };

    match level {
        PageTableLevel::L0 => {
            // Cannot map the root table via syscall
            return Err(SyscallError::InvalidArg);
        }
        PageTableLevel::L1 => {
            // Install L1 table in L0
            let l0_desc = l0.get_desc(va);
            if l0_desc.is_valid() {
                return Err(SyscallError::AlreadyMapped);
            }

            let new_desc = L0Descriptor::new_table(pa);
            // SAFETY: We verified the entry is not occupied
            unsafe { l0.set_desc(va, new_desc) };

            log::debug!(
                "MapPageTable: installed L1 table at va={:#x} -> pa={:#x}",
                vaddr,
                pt_phys.as_u64()
            );
        }
        PageTableLevel::L2 => {
            // Walk to L1 first
            let Some(mut l1) = l0.get_next_table(va) else {
                log::debug!("install_page_table: L1 table missing for va={:#x}", vaddr);
                return Err(SyscallError::InvalidState);
            };

            let l1_desc = l1.get_desc(va);
            if l1_desc.is_valid() {
                return Err(SyscallError::AlreadyMapped);
            }

            let new_desc = L1Descriptor::new_table(pa);
            // SAFETY: We verified the entry is not occupied
            unsafe { l1.set_desc(va, new_desc) };

            log::debug!(
                "MapPageTable: installed L2 table at va={:#x} -> pa={:#x}",
                vaddr,
                pt_phys.as_u64()
            );
        }
        PageTableLevel::L3 => {
            // Walk to L1
            let Some(l1) = l0.get_next_table(va) else {
                log::debug!("install_page_table: L1 table missing for va={:#x}", vaddr);
                return Err(SyscallError::InvalidState);
            };

            // Walk to L2
            let Some(mut l2) = l1.get_next_table(va) else {
                log::debug!("install_page_table: L2 table missing for va={:#x}", vaddr);
                return Err(SyscallError::InvalidState);
            };

            let l2_desc = l2.get_desc(va);
            if l2_desc.is_valid() {
                return Err(SyscallError::AlreadyMapped);
            }

            let new_desc = L2Descriptor::new_table(pa);
            // SAFETY: We verified the entry is not occupied
            unsafe { l2.set_desc(va, new_desc) };

            log::debug!(
                "MapPageTable: installed L3 table at va={:#x} -> pa={:#x}",
                vaddr,
                pt_phys.as_u64()
            );
        }
    }

    // Memory barriers to ensure visibility
    m6_arch::cpu::dsb_sy();
    m6_arch::cpu::isb();

    Ok(())
}

/// Invalidate a TLB entry.
fn invalidate_tlb_entry(_vaddr: u64, _asid: u16) {
    // Issue TLBI for this VA + ASID
    // TLBI VAE1IS, Xt - invalidate by VA, EL1, inner shareable
    //
    // For now, use a full TLB invalidation
    unsafe {
        core::arch::asm!(
            "dsb ishst",       // Ensure stores complete
            "tlbi vmalle1is",  // Invalidate all EL1 TLB entries (inner shareable)
            "dsb ish",         // Ensure TLB invalidation completes
            "isb",             // Synchronisation barrier
            options(nostack, preserves_flags)
        );
    }
}

/// Convert a raw u8 value to an ObjectType.
fn object_type_from_raw(value: u8) -> Option<ObjectType> {
    match value {
        0 => Some(ObjectType::Empty),
        1 => Some(ObjectType::Untyped),
        2 => Some(ObjectType::Frame),
        3 => Some(ObjectType::DeviceFrame),
        4 => Some(ObjectType::PageTableL0),
        5 => Some(ObjectType::PageTableL1),
        6 => Some(ObjectType::PageTableL2),
        7 => Some(ObjectType::PageTableL3),
        8 => Some(ObjectType::VSpace),
        9 => Some(ObjectType::ASIDPool),
        10 => Some(ObjectType::ASIDControl),
        11 => Some(ObjectType::Endpoint),
        12 => Some(ObjectType::Notification),
        13 => Some(ObjectType::Reply),
        14 => Some(ObjectType::CNode),
        15 => Some(ObjectType::TCB),
        16 => Some(ObjectType::IRQHandler),
        17 => Some(ObjectType::IRQControl),
        18 => Some(ObjectType::SchedContext),
        19 => Some(ObjectType::SchedControl),
        20 => Some(ObjectType::IOSpace),
        21 => Some(ObjectType::DmaPool),
        22 => Some(ObjectType::SmmuControl),
        _ => None,
    }
}
