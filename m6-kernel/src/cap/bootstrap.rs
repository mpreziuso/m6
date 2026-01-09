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
    Badge, CapRights, CapSlot, CNodeGuard, CNodeOps, ObjectRef, ObjectType, SlotFlags,
    objects::{Asid, UntypedObject, VSpaceObject},
};
use m6_common::PhysAddr;
use m6_common::boot::BootInfo;
use m6_syscall::boot_info::{UserBootInfo, USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION};

use super::cnode_storage::{create_cnode, CNodeStorage};
use super::object_table::{self, KernelObjectType};
use super::tcb_storage::create_tcb;

use crate::initrd;
use crate::memory::frame::alloc_frame_zeroed;
use crate::memory::translate::phys_to_virt;
use crate::user::layout::USER_BOOT_INFO_ADDR;
use crate::user::vspace_setup;

/// Well-known slot indices in root task's CSpace.
pub mod slots {
    /// Root CNode (self-reference).
    pub const ROOT_CNODE: usize = 0;
    /// Root TCB.
    pub const ROOT_TCB: usize = 1;
    /// Root VSpace.
    pub const ROOT_VSPACE: usize = 2;
    /// IRQ control capability.
    pub const IRQ_CONTROL: usize = 3;
    /// ASID control capability.
    pub const ASID_CONTROL: usize = 4;
    /// Scheduling control capability.
    pub const SCHED_CONTROL: usize = 5;
    /// First untyped memory slot.
    pub const FIRST_UNTYPED: usize = 6;
}

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

    // 5. Populate root CNode with initial capabilities
    let mut cap_count = 0;
    object_table::with_table(|table| {
        let cnode_obj = table.get(cnode_ref).ok_or(BootstrapError::InvalidConfig)?;
        // SAFETY: We just created this CNode.
        let cnode = unsafe { &mut *cnode_obj.data.cnode_ptr };

        // Self-reference to root CNode
        install_cap(cnode, slots::ROOT_CNODE, cnode_ref, ObjectType::CNode, CapRights::ALL);
        cap_count += 1;

        // Root TCB
        install_cap(cnode, slots::ROOT_TCB, tcb_ref, ObjectType::TCB, CapRights::ALL);
        cap_count += 1;

        // Root VSpace
        install_cap(cnode, slots::ROOT_VSPACE, vspace_ref, ObjectType::VSpace, CapRights::ALL);
        cap_count += 1;

        // Control capabilities
        install_cap(cnode, slots::IRQ_CONTROL, irq_control_ref, ObjectType::IRQControl, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::ASID_CONTROL, asid_control_ref, ObjectType::ASIDControl, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::SCHED_CONTROL, sched_control_ref, ObjectType::SchedControl, CapRights::ALL);
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
    let obj_ref = object_table::alloc(KernelObjectType::CNode)
        .ok_or(BootstrapError::NoObjectSlots)?;

    // Create CNode storage
    let cnode_ptr = create_cnode(radix, CNodeGuard::NONE)
        .map_err(|_| BootstrapError::OutOfMemory)?;

    // Store pointer in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.cnode_ptr = cnode_ptr;
    });

    Ok(obj_ref)
}

/// Create the root VSpace.
fn create_root_vspace() -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref = object_table::alloc(KernelObjectType::VSpace)
        .ok_or(BootstrapError::NoObjectSlots)?;

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
    let obj_ref = object_table::alloc(KernelObjectType::Tcb)
        .ok_or(BootstrapError::NoObjectSlots)?;

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
    object_table::alloc(KernelObjectType::IrqControl)
        .ok_or(BootstrapError::NoObjectSlots)
}

/// Create the ASID control object (singleton).
fn create_asid_control() -> BootstrapResult<ObjectRef> {
    object_table::alloc(KernelObjectType::AsidControl)
        .ok_or(BootstrapError::NoObjectSlots)
}

/// Create the scheduling control object (singleton).
fn create_sched_control() -> BootstrapResult<ObjectRef> {
    object_table::alloc(KernelObjectType::SchedControl)
        .ok_or(BootstrapError::NoObjectSlots)
}

/// Install a capability in a CNode slot.
fn install_cap(
    cnode: &mut CNodeStorage,
    slot: usize,
    obj_ref: ObjectRef,
    obj_type: ObjectType,
    rights: CapRights,
) {
    if let Some(cap_slot) = cnode.get_slot_mut(slot) {
        *cap_slot = CapSlot::new(
            obj_ref,
            obj_type,
            rights,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL,
        );
        cnode.meta_mut().increment_used();
    }
}

/// Create an untyped capability for a memory region.
///
/// This is called during bootstrap to create capabilities for all
/// available physical memory.
pub fn create_untyped_cap(
    cnode: &mut CNodeStorage,
    slot: usize,
    phys_base: PhysAddr,
    size_bits: u8,
    is_device: bool,
) -> BootstrapResult<ObjectRef> {
    // Allocate object table entry
    let obj_ref = object_table::alloc(KernelObjectType::Untyped)
        .ok_or(BootstrapError::NoObjectSlots)?;

    // Create untyped object
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.untyped = ManuallyDrop::new(UntypedObject::new(phys_base, size_bits, is_device));
    });

    // Install capability
    install_cap(cnode, slot, obj_ref, ObjectType::Untyped, CapRights::ALL);

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
    let init_data = initrd::find_file(boot_info, "init")
        .ok_or_else(|| {
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

    // 5. Set up user VSpace with ELF and stack
    let (l0_phys, asid, entry, stack_top) = vspace_setup::setup_root_vspace(
        init_data,
        user_boot_info_phys,
    ).map_err(|e| {
        log::error!("Failed to set up root VSpace: {:?}", e);
        BootstrapError::VSpaceSetupFailed
    })?;

    // 6. Update VSpace object with L0 table and ASID
    object_table::with_object_mut(vspace_ref, |obj| {
        // SAFETY: We just created this VSpace object.
        let vspace = unsafe { &mut *core::ptr::addr_of_mut!(obj.data.vspace) };
        vspace.root_table = l0_phys;
        vspace.asid = Asid::new(asid);
    });

    // 7. Populate root CNode with initial capabilities
    let mut cap_count = 0;
    object_table::with_table(|table| {
        let cnode_obj = table.get(cnode_ref).ok_or(BootstrapError::InvalidConfig)?;
        // SAFETY: We just created this CNode.
        let cnode = unsafe { &mut *cnode_obj.data.cnode_ptr };

        install_cap(cnode, slots::ROOT_CNODE, cnode_ref, ObjectType::CNode, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::ROOT_TCB, tcb_ref, ObjectType::TCB, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::ROOT_VSPACE, vspace_ref, ObjectType::VSpace, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::IRQ_CONTROL, irq_control_ref, ObjectType::IRQControl, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::ASID_CONTROL, asid_control_ref, ObjectType::ASIDControl, CapRights::ALL);
        cap_count += 1;

        install_cap(cnode, slots::SCHED_CONTROL, sched_control_ref, ObjectType::SchedControl, CapRights::ALL);
        cap_count += 1;

        Ok(())
    })?;

    // 8. Configure TCB for EL0 entry
    configure_tcb_for_el0(tcb_ref, entry, stack_top)?;

    log::info!(
        "Root task bootstrap complete: entry={:#x}, SP={:#x}, {} capabilities",
        entry,
        stack_top,
        cap_count
    );

    Ok(RootTask {
        cnode_ref,
        tcb_ref,
        vspace_ref,
        cap_count,
        entry_point: entry,
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
    info.untyped_count = 0; // No untyped caps for now (TODO: add them)

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

/// Configure a TCB for EL0 (userspace) execution.
///
/// Sets up the exception context so that when this thread is scheduled,
/// the CPU will return to user mode at the specified entry point.
fn configure_tcb_for_el0(
    tcb_ref: ObjectRef,
    entry: u64,
    stack_top: u64,
) -> BootstrapResult<()> {
    object_table::with_object_mut(tcb_ref, |obj| {
        // SAFETY: tcb_ref points to a valid TCB.
        let tcb = unsafe { &mut *obj.data.tcb_ptr };

        // Set exception context for eret to EL0
        tcb.context.elr = entry;      // Entry point
        tcb.context.sp = stack_top;   // Stack pointer (SP_EL0)

        // SPSR for EL0t (user mode with SP_EL0):
        // - Bits [3:0] = 0b0000 = EL0t
        // - Bit 4 = 0 (AArch64)
        // - DAIF [9:6] = 0 (interrupts enabled)
        tcb.context.spsr = 0x0;

        // Pass UserBootInfo address in x0
        tcb.context.gpr[0] = USER_BOOT_INFO_ADDR;

        // Set thread state to Running (ready to be scheduled)
        tcb.tcb.state = m6_cap::objects::ThreadState::Running;
    });

    Ok(())
}
