//! Root task bootstrap
//!
//! This module creates the initial root task with all system capabilities.
//! The root task is the first userspace process, running in EL0, with
//! authority over all system resources.
//!
//! # Bootstrap Sequence
//!
//! 1. Initialise object table and CDT pool
//! 2. Create root CNode
//! 3. Create root VSpace
//! 4. Create root TCB
//! 5. Create control objects (IRQ, ASID, Sched)
//! 6. Populate CNode with initial capabilities
//! 7. Create Untyped capabilities for free memory
//! 8. Load init ELF from initrd
//! 9. Configure TCB for EL0 entry

extern crate alloc;

use core::mem::ManuallyDrop;

use m6_cap::{
    Badge, CNodeGuard, CNodeOps, CapRights, CapSlot, CdtOps, ObjectRef, ObjectType, SlotFlags,
    objects::{
        Asid, AsidPoolObject, IrqControlObject, TimerControlObject, UntypedObject, VSpaceObject,
    },
    root_slots::Slot as BootSlot,
};
use m6_common::PhysAddr;
use m6_common::boot::BootInfo;
use m6_syscall::boot_info::{USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION, UserBootInfo};

use super::cnode_storage::{CNodeStorage, create_cnode};
use super::object_table::{self, KernelObjectType};
use super::tcb_storage::create_tcb;

use crate::initrd;
use crate::memory::frame::alloc_frame_zeroed;
use crate::memory::translate::phys_to_virt;
use crate::user::layout::USER_BOOT_INFO_ADDR;
use crate::user::vspace_setup;

/// Bootstrap error type.
#[derive(Debug)]
pub enum BootstrapError {
    /// Out of object slots.
    NoObjectSlots,
    /// Out of memory.
    OutOfMemory,
    /// Invalid configuration.
    InvalidConfig,
    /// InitRD not found or invalid.
    NoInitrd,
    /// Init binary not found in initrd.
    InitNotFound,
    /// Failed to load ELF.
    ElfLoadFailed,
    /// Failed to set up VSpace.
    VSpaceSetupFailed,
}

/// Root task bootstrap result.
pub type BootstrapResult<T> = Result<T, BootstrapError>;

/// Root task state after bootstrap.
pub struct RootTask {
    /// Root CNode object reference.
    pub cnode_ref: ObjectRef,
    /// Root TCB object reference.
    pub tcb_ref: ObjectRef,
    /// Root VSpace object reference.
    pub vspace_ref: ObjectRef,
    /// Number of capabilities installed.
    pub cap_count: usize,
    /// Entry point address.
    pub entry_point: u64,
}

/// Bootstrap the root task.
///
/// This creates the initial task with all system capabilities.
/// Call this after memory management is initialised.
pub fn bootstrap_root_task() -> BootstrapResult<RootTask> {
    log::info!("Bootstrapping root task...");

    // 1. Create root CNode (radix 12 = 4096 slots)
    let cnode_ref = create_root_cnode(12)?;
    log::debug!("Created root CNode: {:?}", cnode_ref);

    // 2. Create root VSpace
    let vspace_ref = create_root_vspace()?;
    log::debug!("Created root VSpace: {:?}", vspace_ref);

    // 3. Create root TCB
    let tcb_ref = create_root_tcb(cnode_ref, vspace_ref)?;
    log::debug!("Created root TCB: {:?}", tcb_ref);

    // 4. Create control objects
    let irq_control_ref = create_irq_control()?;
    let asid_control_ref = create_asid_control()?;
    let sched_control_ref = create_sched_control()?;
    let timer_control_ref = create_timer_control()?;

    // 5. Populate root CNode with initial capabilities
    let mut cap_count = 0;
    object_table::with_table(|table| {
        let cnode_obj = table.get(cnode_ref).ok_or(BootstrapError::InvalidConfig)?;
        // SAFETY: We just created this CNode.
        let cnode = unsafe { &mut *cnode_obj.data.cnode_ptr };

        // Self-reference to root CNode
        install_cap(
            cnode,
            BootSlot::RootCNode as usize,
            cnode_ref,
            ObjectType::CNode,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        // Root TCB
        install_cap(
            cnode,
            BootSlot::RootTcb as usize,
            tcb_ref,
            ObjectType::TCB,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        // Root VSpace
        install_cap(
            cnode,
            BootSlot::RootVSpace as usize,
            vspace_ref,
            ObjectType::VSpace,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        // Control capabilities
        install_cap(
            cnode,
            BootSlot::IrqControl as usize,
            irq_control_ref,
            ObjectType::IRQControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::AsidControl as usize,
            asid_control_ref,
            ObjectType::ASIDControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::SchedControl as usize,
            sched_control_ref,
            ObjectType::SchedControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::TimerControl as usize,
            timer_control_ref,
            ObjectType::TimerControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        Ok(())
    })?;

    log::info!(
        "Root task bootstrap complete: {} initial capabilities",
        cap_count
    );

    Ok(RootTask {
        cnode_ref,
        tcb_ref,
        vspace_ref,
        cap_count,
        entry_point: 0, // Kernel-mode bootstrap, no userspace entry
    })
}

/// Create the root CNode.
fn create_root_cnode(radix: u8) -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::CNode).ok_or(BootstrapError::NoObjectSlots)?;

    // Create CNode storage
    let cnode_ptr =
        create_cnode(radix, CNodeGuard::NONE).map_err(|_| BootstrapError::OutOfMemory)?;

    // Store pointer in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.cnode_ptr = cnode_ptr;
    });

    Ok(obj_ref)
}

/// Create the root VSpace.
fn create_root_vspace() -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::VSpace).ok_or(BootstrapError::NoObjectSlots)?;

    // Create VSpace object
    // Note: The L0 page table will be allocated when the VSpace is first used
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.vspace = ManuallyDrop::new(VSpaceObject::new(
            PhysAddr::new(0), // Will be allocated later
            ObjectRef::NULL,
        ));
    });

    Ok(obj_ref)
}

/// Create the root TCB.
fn create_root_tcb(cspace_root: ObjectRef, vspace: ObjectRef) -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::Tcb).ok_or(BootstrapError::NoObjectSlots)?;

    // Create TCB storage
    let tcb_ptr = create_tcb().map_err(|_| BootstrapError::OutOfMemory)?;

    // Configure TCB
    // SAFETY: We just allocated this TCB.
    unsafe {
        (*tcb_ptr).tcb.cspace_root = cspace_root;
        (*tcb_ptr).tcb.vspace = vspace;
        (*tcb_ptr).tcb.set_name(b"root");
    }

    // Store pointer in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.tcb_ptr = tcb_ptr;
    });

    Ok(obj_ref)
}

/// Create the IRQ control object (singleton).
fn create_irq_control() -> BootstrapResult<ObjectRef> {
    use alloc::boxed::Box;

    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::IrqControl).ok_or(BootstrapError::NoObjectSlots)?;

    // Create IRQ control object (heap-allocated due to large bitmap)
    let ctrl = Box::new(IrqControlObject::new());
    let ctrl_ptr = Box::into_raw(ctrl);

    // Store pointer in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.irq_control_ptr = ctrl_ptr;
    });

    Ok(obj_ref)
}

/// Create the ASID control object (singleton).
fn create_asid_control() -> BootstrapResult<ObjectRef> {
    object_table::alloc(KernelObjectType::AsidControl).ok_or(BootstrapError::NoObjectSlots)
}

/// Create the scheduling control object (singleton).
fn create_sched_control() -> BootstrapResult<ObjectRef> {
    object_table::alloc(KernelObjectType::SchedControl).ok_or(BootstrapError::NoObjectSlots)
}

/// Create the timer control object (singleton).
fn create_timer_control() -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::TimerControl).ok_or(BootstrapError::NoObjectSlots)?;

    // Initialise TimerControlObject (stored inline)
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.timer_control = ManuallyDrop::new(TimerControlObject::new());
    });

    Ok(obj_ref)
}

/// Create an ASID pool for init to spawn child processes.
fn create_asid_pool() -> BootstrapResult<ObjectRef> {
    use alloc::boxed::Box;

    // Allocate object table entry
    let obj_ref =
        object_table::alloc(KernelObjectType::AsidPool).ok_or(BootstrapError::NoObjectSlots)?;

    // Create ASID pool object (base ASID 0, first pool)
    let pool = Box::new(AsidPoolObject::new(0));
    let pool_ptr = Box::into_raw(pool);

    // Store pointer in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.asid_pool_ptr = pool_ptr;
    });

    Ok(obj_ref)
}

/// Create SMMU control objects for all initialized SMMUs.
///
/// Returns a vector of ObjectRefs for each SMMU, or an empty vector if no SMMUs.
fn create_smmu_controls() -> BootstrapResult<alloc::vec::Vec<ObjectRef>> {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use m6_cap::objects::SmmuControlObject;

    // Check if any SMMUs are available
    if !crate::smmu::is_available() {
        return Ok(Vec::new()); // No SMMUs
    }

    let mut smmu_refs = Vec::new();
    let smmu_count = crate::smmu::get_smmu_count();

    // Create SmmuControl for each initialized SMMU
    for index in 0..smmu_count.min(4) {
        if let Some(smmu_info) = crate::smmu::get_smmu_info_by_index(index as u8) {
            // Allocate object table entry
            let obj_ref = object_table::alloc(KernelObjectType::SmmuControl)
                .ok_or(BootstrapError::NoObjectSlots)?;

            // Create SMMU control object
            let mut ctrl = Box::new(SmmuControlObject::new(
                smmu_info.base_phys,
                smmu_info.base_virt,
                smmu_info.index,
                smmu_info.max_streams,
            ));
            ctrl.set_ready(); // Mark as ready since init() already succeeded
            let ctrl_ptr = Box::into_raw(ctrl);

            // Store pointer in object table
            object_table::with_object_mut(obj_ref, |obj| {
                obj.data.smmu_control_ptr = ctrl_ptr;
            });

            log::debug!("Created SmmuControl for SMMU #{}: {:?}", index, obj_ref);
            smmu_refs.push(obj_ref);
        }
    }

    log::info!("Created {} SmmuControl capabilities", smmu_refs.len());
    Ok(smmu_refs)
}

/// Install a capability in a CNode slot with CDT registration.
fn install_cap(
    cnode: &mut CNodeStorage,
    slot: usize,
    obj_ref: ObjectRef,
    obj_type: ObjectType,
    rights: CapRights,
    cnode_ref: ObjectRef,
) {
    if let Some(cap_slot) = cnode.get_slot_mut(slot) {
        *cap_slot = CapSlot::new(
            obj_ref,
            obj_type,
            rights,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL.with(SlotFlags::IN_CDT),
        );
        cnode.meta_mut().increment_used();

        // Register CDT node for this capability
        super::cdt_storage::with_cdt(|cdt| {
            if let Some(node_id) = cdt.alloc_node() {
                if let Some(node) = cdt.get_node_mut(node_id) {
                    node.object_ref = obj_ref;
                    node.slot_cnode = cnode_ref;
                    node.slot_index = slot as u32;
                }
                super::cdt_storage::register_cdt_node(cnode_ref, slot as u32, node_id);
            }
        });
    }
}

/// Create an untyped capability for a memory region.
///
/// This is called during bootstrap to create capabilities for all
/// available physical memory.
///
/// This version takes a reference to the object table to avoid deadlocks
/// when called from within a `with_table` closure.
fn create_untyped_cap_with_table(
    table: &mut object_table::ObjectTable,
    cnode: &mut CNodeStorage,
    slot: usize,
    phys_base: PhysAddr,
    size_bits: u8,
    is_device: bool,
    cnode_ref: ObjectRef,
) -> BootstrapResult<ObjectRef> {
    // Allocate object table entry using the passed-in table
    let obj_ref = table
        .alloc(KernelObjectType::Untyped)
        .ok_or(BootstrapError::NoObjectSlots)?;

    // Create untyped object
    if let Some(obj) = table.get_mut(obj_ref) {
        obj.data.untyped = ManuallyDrop::new(UntypedObject::new(phys_base, size_bits, is_device));
    }

    // Install capability
    install_cap(
        cnode,
        slot,
        obj_ref,
        ObjectType::Untyped,
        CapRights::ALL,
        cnode_ref,
    );

    Ok(obj_ref)
}

/// Bootstrap the root task from initrd.
///
/// This is the main entry point for creating the root task. It:
/// 1. Finds and loads the init binary from initrd
/// 2. Creates capability objects (CNode, VSpace, TCB, etc.)
/// 3. Sets up the user address space with ELF mappings
/// 4. Configures the TCB for EL0 execution
///
/// # Arguments
///
/// * `boot_info` - Boot information from bootloader
///
/// # Returns
///
/// The root task state on success, or an error.
pub fn bootstrap_root_task_from_initrd(boot_info: &BootInfo) -> BootstrapResult<RootTask> {
    log::info!("Bootstrapping root task from initrd...");

    // 1. Verify initrd is present
    if !boot_info.has_initrd() {
        log::error!("No initrd present in boot info");
        return Err(BootstrapError::NoInitrd);
    }
    log::info!(
        "InitRD: phys={:#x}, size={} bytes",
        boot_info.initrd_phys_base.0,
        boot_info.initrd_size
    );

    // List initrd contents for debugging
    initrd::list_files(boot_info);

    // 2. Find init binary in initrd
    let init_data = initrd::find_file(boot_info, "init").ok_or_else(|| {
        log::error!("'init' binary not found in initrd");
        BootstrapError::InitNotFound
    })?;
    log::info!("Found init binary: {} bytes", init_data.len());

    // 3. Create UserBootInfo page
    let user_boot_info_phys = create_user_boot_info(boot_info)?;

    // 4. Create capability objects
    let cnode_ref = create_root_cnode(12)?; // 4096 slots
    log::debug!("Created root CNode: {:?}", cnode_ref);

    let vspace_ref = create_root_vspace()?;
    log::debug!("Created root VSpace: {:?}", vspace_ref);

    let tcb_ref = create_root_tcb(cnode_ref, vspace_ref)?;
    log::debug!("Created root TCB: {:?}", tcb_ref);

    let irq_control_ref = create_irq_control()?;
    let asid_control_ref = create_asid_control()?;
    let sched_control_ref = create_sched_control()?;
    let asid_pool_ref = create_asid_pool()?;
    log::debug!("Created ASID pool for init: {:?}", asid_pool_ref);

    // Create SMMU controls for all available SMMUs
    let smmu_control_refs = create_smmu_controls()?;

    // 5. Set up user VSpace with ELF, stack, DTB, and initrd
    let vspace_result = vspace_setup::setup_root_vspace(
        init_data,
        user_boot_info_phys,
        boot_info.dtb_address,
        get_dtb_size(boot_info),
        boot_info.initrd_phys_base,
        boot_info.initrd_size,
    )
    .map_err(|e| {
        log::error!("Failed to set up root VSpace: {:?}", e);
        BootstrapError::VSpaceSetupFailed
    })?;

    // 6. Update UserBootInfo with DTB/initrd virtual addresses
    update_user_boot_info(
        user_boot_info_phys,
        vspace_result.dtb_vaddr,
        vspace_result.dtb_size,
        vspace_result.initrd_vaddr,
        vspace_result.initrd_size,
    );

    // 7. Update VSpace object with L0 table and ASID (including generation)
    object_table::with_object_mut(vspace_ref, |obj| {
        // SAFETY: We just created this VSpace object.
        let vspace = unsafe { &mut *core::ptr::addr_of_mut!(obj.data.vspace) };
        vspace.root_table = vspace_result.l0_phys;
        vspace.assign_asid_with_generation(
            Asid::new(vspace_result.asid.asid),
            vspace_result.asid.generation,
        );
    });

    // 8. Drain all remaining free physical memory into Untyped capabilities.
    //
    // Now that every kernel allocation (heap, page tables, VSpace setup) is done,
    // we claim all remaining free frames and decompose them into maximally-aligned
    // power-of-2 chunks.  Each chunk becomes one RAM Untyped capability for the
    // root task — this is the seL4-style "give everything to userspace" handoff.
    let mut ram_chunks = crate::memory::frame::drain_free_aligned_chunks(
        m6_common::boot::MAX_RAM_UNTYPED_REGIONS,
    );
    if ram_chunks.is_empty() {
        log::error!("No free physical memory left to hand to init — boot failed");
        return Err(BootstrapError::OutOfMemory);
    }

    // Sort largest first: init always allocates from Slot::FirstUntyped (slot 12).
    // Without sorting the first chunk may be as small as 1 page (if the first free
    // frame has an odd absolute frame number), causing the initial VSpace retype to
    // fail with NoMemory immediately after the Endpoint has been allocated from it.
    ram_chunks.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    {
        let total_bytes: u64 = ram_chunks
            .iter()
            .map(|&(_, size_bits)| 1u64 << size_bits)
            .sum();
        log::info!(
            "Handing {} MiB free RAM to init as {} Untyped capability/capabilities",
            total_bytes / (1024 * 1024),
            ram_chunks.len(),
        );
    }

    // 9. Populate root CNode with initial capabilities
    log::debug!("Installing capabilities in root CNode...");
    let mut cap_count = 0;
    let mut untyped_count = 0u32;
    object_table::with_table(|table| {
        let cnode_obj = table.get(cnode_ref).ok_or(BootstrapError::InvalidConfig)?;
        // SAFETY: We just created this CNode.
        let cnode = unsafe { &mut *cnode_obj.data.cnode_ptr };

        install_cap(
            cnode,
            BootSlot::RootCNode as usize,
            cnode_ref,
            ObjectType::CNode,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::RootTcb as usize,
            tcb_ref,
            ObjectType::TCB,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::RootVSpace as usize,
            vspace_ref,
            ObjectType::VSpace,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::IrqControl as usize,
            irq_control_ref,
            ObjectType::IRQControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::AsidControl as usize,
            asid_control_ref,
            ObjectType::ASIDControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::SchedControl as usize,
            sched_control_ref,
            ObjectType::SchedControl,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        install_cap(
            cnode,
            BootSlot::AsidPool as usize,
            asid_pool_ref,
            ObjectType::ASIDPool,
            CapRights::ALL,
            cnode_ref,
        );
        cap_count += 1;

        // Install SMMU control capabilities (one per SMMU)
        for (index, smmu_ref) in smmu_control_refs.iter().enumerate() {
            install_cap(
                cnode,
                BootSlot::smmu_control(index),
                *smmu_ref,
                ObjectType::SmmuControl,
                CapRights::ALL,
                cnode_ref,
            );
            cap_count += 1;
            log::debug!(
                "Installed SMMU #{} control capability at slot {}",
                index,
                BootSlot::smmu_control(index)
            );
        }

        log::debug!("Installed {} control capabilities", cap_count);

        // Create RAM Untyped capabilities from the drained free-memory chunks.
        for &(phys_base, size_bits) in &ram_chunks {
            let slot = BootSlot::FirstUntyped as usize + untyped_count as usize;
            let _ram_ref = create_untyped_cap_with_table(
                table,
                cnode,
                slot,
                PhysAddr::new(phys_base),
                size_bits,
                false, // RAM, not device memory
                cnode_ref,
            )?;
            cap_count += 1;
            untyped_count += 1;
        }

        // Create device untyped capabilities for MMIO regions from DTB
        for i in 0..boot_info.device_region_count as usize {
            let region = &boot_info.device_regions[i];
            if !region.is_valid() {
                continue;
            }
            let slot = BootSlot::FirstUntyped as usize + untyped_count as usize;
            // log::debug!(
            //     "Creating device untyped at slot {} for {:#x} ({} bytes, type {:?})",
            //     slot,
            //     region.phys_base.as_u64(),
            //     1u64 << region.size_bits,
            //     region.device_type
            // );
            let _device_ref = create_untyped_cap_with_table(
                table,
                cnode,
                slot,
                region.phys_base,
                region.size_bits,
                true, // device memory
                cnode_ref,
            )?;
            cap_count += 1;
            untyped_count += 1;
            // log::debug!(
            //     "Created device untyped cap {} at {:#x}",
            //     i,
            //     region.phys_base.as_u64()
            // );
        }

        Ok(())
    })?;

    // 10. Update UserBootInfo with untyped region info (RAM chunks + device regions)
    update_user_boot_info_all_untyped(
        user_boot_info_phys,
        &ram_chunks,
        boot_info,
    );

    // 11. Configure TCB for EL0 entry
    configure_tcb_for_el0(
        tcb_ref,
        vspace_result.entry,
        vspace_result.stack_top,
        vspace_result.ipc_buffer_vaddr,
        vspace_result.ipc_buffer_phys,
    )?;

    log::info!(
        "Root task bootstrap complete: entry={:#x}, SP={:#x}, {} capabilities",
        vspace_result.entry,
        vspace_result.stack_top,
        cap_count
    );

    Ok(RootTask {
        cnode_ref,
        tcb_ref,
        vspace_ref,
        cap_count,
        entry_point: vspace_result.entry,
    })
}

/// Create the UserBootInfo page.
///
/// Allocates a frame and populates it with boot information for the init process.
fn create_user_boot_info(_boot_info: &BootInfo) -> BootstrapResult<PhysAddr> {
    let phys = alloc_frame_zeroed().ok_or(BootstrapError::OutOfMemory)?;
    let virt = phys_to_virt(phys);

    // SAFETY: We just allocated this frame and it's zeroed.
    let info = unsafe { &mut *(virt as *mut UserBootInfo) };

    info.magic = USER_BOOT_INFO_MAGIC;
    info.version = USER_BOOT_INFO_VERSION;
    info.cnode_radix = 12; // 4096 slots
    info.untyped_count = 0; // Updated later by update_user_boot_info_all_untyped

    let (free, total) = crate::memory::frame::memory_stats();
    info.total_memory = total as u64;
    info.free_memory = free as u64;

    // Platform ID - match common platform names
    let platform_name = m6_pal::platform::platform().name();
    info.platform_id = if platform_name.contains("virt") || platform_name.contains("QEMU") {
        1 // QEMU virt machine
    } else if platform_name.contains("Rock") || platform_name.contains("RK3588") {
        2 // Radxa Rock 5B+
    } else {
        0 // Unknown
    };
    info.cpu_count = 1; // Single CPU for now

    // SMMU availability
    info.has_smmu = if crate::smmu::is_available() { 1 } else { 0 };
    info.smmu_count = crate::smmu::get_smmu_count() as u8;

    // Untyped regions - zeroed by default, TODO: populate with actual regions

    log::debug!(
        "Created UserBootInfo: phys={:#x}, platform={}, mem={}/{}",
        phys,
        info.platform_id,
        info.free_memory / (1024 * 1024),
        info.total_memory / (1024 * 1024)
    );

    Ok(PhysAddr::new(phys))
}

/// Get the DTB size from boot info.
///
/// We parse the DTB header to determine the actual size rather than assuming
/// a maximum. Returns 0 if DTB is not available or invalid.
fn get_dtb_size(boot_info: &BootInfo) -> u64 {
    if boot_info.dtb_address.is_null() {
        return 0;
    }

    // DTB header: magic (4 bytes) + totalsize (4 bytes, big-endian)
    let dtb_virt = phys_to_virt(boot_info.dtb_address.0);
    // SAFETY: Bootloader guarantees DTB is valid and mapped in direct map
    let dtb_header = unsafe { core::slice::from_raw_parts(dtb_virt as *const u8, 8) };

    // Check FDT magic (0xd00dfeed in big-endian)
    if dtb_header[0..4] != [0xd0, 0x0d, 0xfe, 0xed] {
        log::warn!("Invalid DTB magic");
        return 0;
    }

    // Read totalsize from header (big-endian u32 at offset 4)
    let size = u32::from_be_bytes([dtb_header[4], dtb_header[5], dtb_header[6], dtb_header[7]]);

    size as u64
}

/// Update UserBootInfo with DTB/initrd virtual addresses.
///
/// Called after VSpace setup to populate the mapped addresses.
fn update_user_boot_info(
    boot_info_phys: PhysAddr,
    dtb_vaddr: u64,
    dtb_size: u64,
    initrd_vaddr: u64,
    initrd_size: u64,
) {
    let virt = phys_to_virt(boot_info_phys.0);
    // SAFETY: boot_info_phys points to a valid UserBootInfo we allocated
    let info = unsafe { &mut *(virt as *mut UserBootInfo) };

    info.dtb_vaddr = dtb_vaddr;
    info.dtb_size = dtb_size;
    info.initrd_vaddr = initrd_vaddr;
    info.initrd_size = initrd_size;

    log::debug!(
        "Updated UserBootInfo: DTB={:#x}({} bytes), initrd={:#x}({} bytes)",
        dtb_vaddr,
        dtb_size,
        initrd_vaddr,
        initrd_size
    );
}

/// Update UserBootInfo with untyped memory region info.
#[expect(dead_code)]
fn update_user_boot_info_untyped(
    boot_info_phys: PhysAddr,
    count: u32,
    phys_base: u64,
    size_bits: u8,
) {
    let virt = phys_to_virt(boot_info_phys.0);
    // SAFETY: boot_info_phys points to a valid UserBootInfo we allocated
    let info = unsafe { &mut *(virt as *mut UserBootInfo) };

    info.untyped_count = count;
    if count > 0 {
        info.untyped_size_bits[0] = size_bits;
        info.untyped_is_device[0] = 0; // not device memory
        info.untyped_phys_base[0] = phys_base;
    }

    log::debug!(
        "Updated UserBootInfo: {} untyped region(s), first at {:#x} ({} bytes)",
        count,
        phys_base,
        1u64 << size_bits
    );
}

/// Update UserBootInfo with all untyped regions (RAM chunks + device MMIO).
fn update_user_boot_info_all_untyped(
    user_boot_info_phys: PhysAddr,
    ram_chunks: &[(u64, u8)],
    boot_info: &BootInfo,
) {
    let virt = phys_to_virt(user_boot_info_phys.0);
    // SAFETY: user_boot_info_phys points to a valid UserBootInfo we allocated
    let info = unsafe { &mut *(virt as *mut UserBootInfo) };

    let max_regions = m6_syscall::boot_info::MAX_UNTYPED_REGIONS;
    let mut idx = 0usize;

    // RAM Untyped regions
    for &(phys_base, size_bits) in ram_chunks {
        if idx >= max_regions {
            log::warn!(
                "Untyped region limit ({}) reached, cannot record all RAM chunks",
                max_regions
            );
            break;
        }
        info.untyped_size_bits[idx] = size_bits;
        info.untyped_is_device[idx] = 0;
        info.untyped_phys_base[idx] = phys_base;
        idx += 1;
    }
    let ram_count = idx;

    // Device Untyped regions from BootInfo
    let device_count = boot_info.device_region_count as usize;
    for i in 0..device_count {
        if idx >= max_regions {
            log::warn!(
                "Untyped region limit ({}) reached, skipping remaining {} device regions",
                max_regions,
                device_count - i
            );
            break;
        }
        let region = &boot_info.device_regions[i];
        if !region.is_valid() {
            continue;
        }
        info.untyped_size_bits[idx] = region.size_bits;
        info.untyped_is_device[idx] = 1;
        info.untyped_phys_base[idx] = region.phys_base.as_u64();
        idx += 1;
    }

    info.untyped_count = idx as u32;

    log::debug!(
        "Updated UserBootInfo: {} untyped region(s) ({} RAM, {} device)",
        idx,
        ram_count,
        idx - ram_count,
    );
}

/// Configure a TCB for EL0 (userspace) execution.
///
/// Sets up the exception context so that when this thread is scheduled,
/// the CPU will return to user mode at the specified entry point.
fn configure_tcb_for_el0(
    tcb_ref: ObjectRef,
    entry: u64,
    stack_top: u64,
    ipc_buffer_vaddr: u64,
    ipc_buffer_phys: PhysAddr,
) -> BootstrapResult<()> {
    object_table::with_object_mut(tcb_ref, |obj| {
        // SAFETY: tcb_ref points to a valid TCB.
        let tcb = unsafe { &mut *obj.data.tcb_ptr };

        // Set exception context for eret to EL0
        tcb.context.elr = entry; // Entry point
        tcb.context.sp = stack_top; // Stack pointer (SP_EL0)

        // SPSR for EL0t (user mode with SP_EL0):
        // - Bits [3:0] = 0b0000 = EL0t
        // - Bit 4 = 0 (AArch64)
        // - DAIF [9:6] = 0 (interrupts enabled)
        tcb.context.spsr = 0x0;

        // Pass UserBootInfo address in x0
        tcb.context.gpr[0] = USER_BOOT_INFO_ADDR;

        // Set IPC buffer addresses for capability transfer
        tcb.tcb.ipc_buffer_addr = m6_common::VirtAddr::new(ipc_buffer_vaddr);
        tcb.tcb.ipc_buffer_phys = ipc_buffer_phys;

        // Set thread state to Running (ready to be scheduled)
        tcb.tcb.state = m6_cap::objects::ThreadState::Running;
    });

    Ok(())
}
