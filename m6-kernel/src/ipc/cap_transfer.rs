//! Capability transfer during IPC operations
//!
//! Implements seL4-style capability transfer where capabilities can be sent
//! alongside messages through endpoints. The IPC buffer contains an array of
//! capability pointers (CPtrs) that are resolved in the sender's CSpace and
//! copied/moved to the receiver's CSpace.

use crate::cap::{cdt_storage, cspace, object_table};
use crate::memory::translate::phys_to_virt;
use crate::syscall::error::SyscallError;
use m6_cap::{CNodeOps, ObjectRef};
use m6_syscall::IpcBuffer;

// -- Helper Functions

/// Read IPC buffer for a TCB.
///
/// Uses the physical address of the IPC buffer and accesses it via the
/// kernel's direct map, since user virtual addresses aren't accessible
/// from kernel mode.
fn read_ipc_buffer(tcb_ref: ObjectRef) -> Result<&'static IpcBuffer, SyscallError> {
    let ipc_buf_phys =
        object_table::with_tcb(tcb_ref, |tcb| Some(tcb.tcb.ipc_buffer_phys.as_u64()))
            .ok_or(SyscallError::InvalidState)?;

    if ipc_buf_phys == 0 {
        return Err(SyscallError::InvalidState);
    }

    // Convert physical address to kernel virtual address via direct map
    let kernel_va = phys_to_virt(ipc_buf_phys);

    // SAFETY: Physical address comes from TCB configuration, validated at TCB setup time.
    // The IPC buffer frame is allocated and remains valid for the lifetime of the thread.
    // We access it via the kernel's direct map which maps all physical memory.
    Ok(unsafe { &*(kernel_va as *const IpcBuffer) })
}

/// Write to IPC buffer for a TCB.
///
/// Uses the physical address of the IPC buffer and accesses it via the
/// kernel's direct map, since user virtual addresses aren't accessible
/// from kernel mode.
fn write_ipc_buffer(tcb_ref: ObjectRef) -> Result<&'static mut IpcBuffer, SyscallError> {
    let ipc_buf_phys =
        object_table::with_tcb(tcb_ref, |tcb| Some(tcb.tcb.ipc_buffer_phys.as_u64()))
            .ok_or(SyscallError::InvalidState)?;

    if ipc_buf_phys == 0 {
        return Err(SyscallError::InvalidState);
    }

    // Convert physical address to kernel virtual address via direct map
    let kernel_va = phys_to_virt(ipc_buf_phys);

    // SAFETY: Physical address comes from TCB configuration, validated at TCB setup time.
    // We have exclusive access to this TCB during IPC, so mutable access is safe.
    Ok(unsafe { &mut *(kernel_va as *mut IpcBuffer) })
}

/// Find an empty slot in a CSpace starting from a hint.
fn find_empty_slot_in_cspace(
    cspace_root: ObjectRef,
    hint_slot: Option<usize>,
) -> Result<usize, SyscallError> {
    cspace::with_cnode(cspace_root, |cnode| {
        let radix = cnode.meta().radix();
        let num_slots = 1 << radix;
        let start = hint_slot.unwrap_or(0).min(num_slots - 1);

        // Search from hint to end
        for i in start..num_slots {
            if let Some(slot) = cnode.get_slot(i)
                && slot.is_empty()
            {
                return Ok(i);
            }
        }

        // Wrap around and search from beginning to hint
        for i in 0..start {
            if let Some(slot) = cnode.get_slot(i)
                && slot.is_empty()
            {
                return Ok(i);
            }
        }

        Err(SyscallError::NoMemory)
    })
}

// -- Main Transfer Functions

/// Transfer capabilities from sender to receiver during IPC.
///
/// Reads sender's IPC buffer `caps_or_badges[0..extra_caps]` as CPtrs,
/// resolves them in sender's CSpace, and copies them to receiver's CSpace.
///
/// # Arguments
/// * `sender_ref` - Sender TCB reference
/// * `receiver_ref` - Receiver TCB reference
/// * `has_grant` - Whether endpoint has Grant right
///
/// # Returns
/// Number of capabilities successfully transferred
///
/// # Errors
/// * `NoRights` - If trying to transfer capabilities without Grant right
/// * `InvalidCap` - If any CPtr is invalid
/// * `NoMemory` - If receiver's CSpace is full
#[allow(dead_code)]
pub fn transfer_capabilities(
    sender_ref: ObjectRef,
    receiver_ref: ObjectRef,
    has_grant: bool,
) -> Result<usize, SyscallError> {
    // Read sender's IPC buffer to see how many capabilities to transfer
    let sender_buf = read_ipc_buffer(sender_ref)?;
    let num_caps = sender_buf.extra_caps as usize;

    // Fast path: no capabilities to transfer
    if num_caps == 0 {
        return Ok(0);
    }

    // Validate Grant right
    if !has_grant {
        return Err(SyscallError::NoRights);
    }

    // Limit to maximum of 4 capabilities (size of caps_or_badges array)
    let num_caps = num_caps.min(4);

    // Get sender's and receiver's CSpace roots
    let sender_cspace = object_table::with_tcb(sender_ref, |tcb| Some(tcb.tcb.cspace_root))
        .ok_or(SyscallError::InvalidState)?;
    let receiver_cspace = object_table::with_tcb(receiver_ref, |tcb| Some(tcb.tcb.cspace_root))
        .ok_or(SyscallError::InvalidState)?;

    // Read receiver's IPC buffer for destination hints
    let receiver_buf = read_ipc_buffer(receiver_ref)?;
    let mut dest_hints = [0u64; 4];
    dest_hints.copy_from_slice(&receiver_buf.caps_or_badges[..4]);

    // Array to store where we placed the capabilities
    let mut placed_slots = [0u64; 4];
    let mut transferred = 0usize;

    // Transfer each capability
    for i in 0..num_caps {
        let src_cptr = sender_buf.caps_or_badges[i];

        // Resolve the CPtr in sender's CSpace (depth 0 = auto)
        let src_loc = cspace::resolve_cptr_from_root(sender_cspace, src_cptr, 0)?;

        // Validate source slot is not empty
        cspace::with_slot(&src_loc, |slot| {
            if slot.is_empty() {
                return Err(SyscallError::EmptySlot);
            }
            Ok(())
        })?;

        // Find empty slot in receiver's CSpace (use hint if provided)
        let hint = if dest_hints[i] != 0 {
            Some(dest_hints[i] as usize)
        } else {
            None
        };
        let dest_slot_index = find_empty_slot_in_cspace(receiver_cspace, hint)?;

        // Look up source CDT node (if capability is tracked in CDT)
        let src_cdt_node =
            cdt_storage::lookup_cdt_node(src_loc.cnode_ref, src_loc.slot_index as u32)
                .unwrap_or(m6_cap::CdtNodeId::NULL);

        // Copy capability with CDT tracking using with_two_cnodes
        let new_cdt_node = cspace::with_two_cnodes(
            src_loc.cnode_ref,
            receiver_cspace,
            |src_cnode, dst_cnode, _same_cnode| {
                // Access CDT pool
                cdt_storage::with_cdt(|cdt| {
                    // Use cap_copy_with_cdt from m6_cap::ops
                    let new_node = m6_cap::ops::cap_copy_with_cdt(
                        src_cnode,
                        src_loc.slot_index,
                        dst_cnode,
                        dest_slot_index,
                        cdt,
                        src_cdt_node,
                        receiver_cspace,
                    )
                    .map_err(|_| SyscallError::InvalidCap)?;

                    Ok(new_node)
                })
            },
        )?;

        // Register the new CDT node in the slot map
        cdt_storage::register_cdt_node(receiver_cspace, dest_slot_index as u32, new_cdt_node);

        placed_slots[i] = dest_slot_index as u64;
        transferred += 1;
    }

    // Write destination slots back to receiver's IPC buffer
    let receiver_buf_mut = write_ipc_buffer(receiver_ref)?;
    receiver_buf_mut.recv_extra_caps = transferred as u8;
    receiver_buf_mut.caps_or_badges[..transferred].copy_from_slice(&placed_slots[..transferred]);

    Ok(transferred)
}

/// Unwrap a capability: receive and atomically delete from sender.
///
/// This is used when the receiver wants to take ownership rather than
/// share the capability with the sender.
///
/// # Arguments
/// * `sender_ref` - Sender TCB reference
/// * `receiver_ref` - Receiver TCB reference
/// * `cap_index` - Which capability in the transfer array to unwrap
///
/// # Returns
/// Slot where capability was placed in receiver's CSpace
///
/// # Errors
/// * `InvalidCap` - If capability index is invalid
/// * `NoMemory` - If receiver's CSpace is full
#[allow(dead_code)]
pub fn unwrap_capability(
    sender_ref: ObjectRef,
    receiver_ref: ObjectRef,
    cap_index: usize,
) -> Result<usize, SyscallError> {
    if cap_index >= 4 {
        return Err(SyscallError::InvalidCap);
    }

    // Read sender's IPC buffer to get the CPtr
    let sender_buf = read_ipc_buffer(sender_ref)?;
    let src_cptr = sender_buf.caps_or_badges[cap_index];

    // Get sender's and receiver's CSpace roots
    let sender_cspace = object_table::with_tcb(sender_ref, |tcb| Some(tcb.tcb.cspace_root))
        .ok_or(SyscallError::InvalidState)?;
    let receiver_cspace = object_table::with_tcb(receiver_ref, |tcb| Some(tcb.tcb.cspace_root))
        .ok_or(SyscallError::InvalidState)?;

    // Resolve CPtr in sender's CSpace
    let src_loc = cspace::resolve_cptr_from_root(sender_cspace, src_cptr, 0)?;

    // Validate source slot is not empty
    cspace::with_slot(&src_loc, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        Ok(())
    })?;

    // Read receiver's IPC buffer for destination hint
    let receiver_buf = read_ipc_buffer(receiver_ref)?;
    let hint = if receiver_buf.caps_or_badges[cap_index] != 0 {
        Some(receiver_buf.caps_or_badges[cap_index] as usize)
    } else {
        None
    };

    // Find empty slot in receiver's CSpace
    let dest_slot_index = find_empty_slot_in_cspace(receiver_cspace, hint)?;

    // Look up source CDT node (if capability is tracked in CDT)
    let src_cdt_node = cdt_storage::lookup_cdt_node(src_loc.cnode_ref, src_loc.slot_index as u32)
        .unwrap_or(m6_cap::CdtNodeId::NULL);

    // Move capability (no new CDT node created, just transfer ownership)
    cspace::with_two_cnodes(
        src_loc.cnode_ref,
        receiver_cspace,
        |src_cnode, dst_cnode, _same_cnode| {
            // Use cap_move from m6_cap::ops
            m6_cap::ops::cap_move(src_cnode, src_loc.slot_index, dst_cnode, dest_slot_index)
                .map_err(|_| SyscallError::InvalidCap)?;
            Ok(())
        },
    )?;

    // Update CDT slot map: unregister from sender, register with receiver
    if src_cdt_node != m6_cap::CdtNodeId::NULL {
        cdt_storage::unregister_cdt_node(src_loc.cnode_ref, src_loc.slot_index as u32);
        cdt_storage::register_cdt_node(receiver_cspace, dest_slot_index as u32, src_cdt_node);
    }

    // Write destination slot to receiver's IPC buffer
    let receiver_buf_mut = write_ipc_buffer(receiver_ref)?;
    receiver_buf_mut.caps_or_badges[cap_index] = dest_slot_index as u64;
    receiver_buf_mut.recv_extra_caps = 1;

    Ok(dest_slot_index)
}
