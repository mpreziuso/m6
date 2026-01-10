//! Capability syscall handlers
//!
//! This module implements the 7 capability management syscalls:
//!
//! - [`handle_cap_copy`] - Copy a capability between slots
//! - [`handle_cap_move`] - Move a capability between slots
//! - [`handle_cap_mint`] - Create a derived capability with reduced rights
//! - [`handle_cap_delete`] - Delete a single capability
//! - [`handle_cap_revoke`] - Revoke a capability and all its derivatives
//! - [`handle_cap_mutate`] - Reduce capability rights in-place
//! - [`handle_cap_rotate`] - Rotate capabilities between three slots
//!
//! # CSpace Addressing
//!
//! All capability syscalls use seL4-style addressing: a CNode capability
//! pointer plus a slot index within that CNode. The CNode CPtr is resolved
//! through the hierarchical CSpace using guard-based addressing.
//!
//! # CDT Tracking
//!
//! Copy and mint operations track capability derivations in the CDT
//! (Capability Derivation Tree) to enable proper revocation semantics.

use m6_cap::{ops, Badge, CapRights, CdtNodeId, CNodeOps, RevocationCallback};
use m6_syscall::IpcBuffer;

use crate::cap::cdt_storage;
use crate::cap::cspace::{self, with_two_cnodes};
use crate::cap::object_table::{self, KernelObjectType};
use crate::syscall::error::{cap_error_to_syscall, SyscallError, SyscallResult};
use crate::syscall::SyscallArgs;

/// Handle CapCopy syscall.
///
/// Copies a capability from source slot to destination slot.
/// Creates a sibling relationship in the CDT (same parent as source).
///
/// # Arguments (registers)
///
/// - x0: dest_cnode_cptr - CPtr to destination CNode
/// - x1: dest_index - Slot index in destination CNode
/// - x2: dest_depth - Bits to consume resolving dest CNode (0=auto)
/// - x3: src_cnode_cptr - CPtr to source CNode
/// - x4: src_index - Slot index in source CNode
/// - x5: src_depth - Bits to consume resolving src CNode (0=auto)
pub fn handle_cap_copy(args: &SyscallArgs) -> SyscallResult {
    let dest_cnode_cptr = args.arg0;
    let dest_index = args.arg1 as usize;
    let dest_depth = args.arg2 as u8;
    let src_cnode_cptr = args.arg3;
    let src_index = args.arg4 as usize;
    let src_depth = args.arg5 as u8;

    log::trace!(
        "cap_copy: dest_cnode={:#x} dest_idx={} src_cnode={:#x} src_idx={}",
        dest_cnode_cptr, dest_index, src_cnode_cptr, src_index
    );

    // Resolve both CNode locations
    let src_loc = cspace::resolve_cnode_slot(src_cnode_cptr, src_depth, src_index)?;
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    log::trace!(
        "cap_copy: resolved src=({:?}, {}) dest=({:?}, {})",
        src_loc.cnode_ref, src_loc.slot_index, dest_loc.cnode_ref, dest_loc.slot_index
    );

    // Look up source CDT node (if tracked)
    let src_cdt_node = cdt_storage::lookup_cdt_node(src_loc.cnode_ref, src_loc.slot_index as u32)
        .unwrap_or(CdtNodeId::NULL);

    // Perform the copy with CDT tracking
    with_two_cnodes(src_loc.cnode_ref, dest_loc.cnode_ref, |src_cnode, dest_cnode, _| {
        cdt_storage::with_cdt(|cdt| {
            let new_cdt_node = ops::cap_copy_with_cdt(
                src_cnode,
                src_loc.slot_index,
                dest_cnode,
                dest_loc.slot_index,
                cdt,
                src_cdt_node,
                dest_loc.cnode_ref,
            )
            .map_err(cap_error_to_syscall)?;

            // Register the new CDT node in the slot map
            if new_cdt_node.is_valid() {
                cdt_storage::register_cdt_node(
                    dest_loc.cnode_ref,
                    dest_loc.slot_index as u32,
                    new_cdt_node,
                );
            }

            Ok(0)
        })
    })
}

/// Handle CapMove syscall.
///
/// Moves a capability from source slot to destination slot.
/// The source slot becomes empty. CDT membership transfers with the capability.
///
/// # Arguments (registers)
///
/// Same as CapCopy.
pub fn handle_cap_move(args: &SyscallArgs) -> SyscallResult {
    let dest_cnode_cptr = args.arg0;
    let dest_index = args.arg1 as usize;
    let dest_depth = args.arg2 as u8;
    let src_cnode_cptr = args.arg3;
    let src_index = args.arg4 as usize;
    let src_depth = args.arg5 as u8;

    // Resolve both CNode locations
    let src_loc = cspace::resolve_cnode_slot(src_cnode_cptr, src_depth, src_index)?;
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Perform the move
    with_two_cnodes(src_loc.cnode_ref, dest_loc.cnode_ref, |src_cnode, dest_cnode, _| {
        ops::cap_move(src_cnode, src_loc.slot_index, dest_cnode, dest_loc.slot_index)
            .map_err(cap_error_to_syscall)?;

        // Update CDT mapping
        cdt_storage::move_cdt_mapping(
            src_loc.cnode_ref,
            src_loc.slot_index as u32,
            dest_loc.cnode_ref,
            dest_loc.slot_index as u32,
        );

        Ok(0)
    })
}

/// Handle CapMint syscall.
///
/// Creates a derived capability with reduced rights and optional badge.
/// Creates a child relationship in the CDT (parent = source).
///
/// # Arguments (registers)
///
/// - x0: dest_cnode_cptr
/// - x1: dest_index
/// - x2: src_cnode_cptr
/// - x3: src_index
/// - x4: reserved (0)
/// - x5: reserved (0)
///
/// Extended arguments are read from the IPC buffer at IPC_BUFFER_ADDR.
pub fn handle_cap_mint(args: &SyscallArgs) -> SyscallResult {
    let dest_cnode_cptr = args.arg0;
    let dest_index = args.arg1 as usize;
    let src_cnode_cptr = args.arg2;
    let src_index = args.arg3 as usize;

    // Read extended arguments from IPC buffer
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;
    let ipc_buffer_addr = object_table::with_tcb(current, |tcb| tcb.tcb.ipc_buffer_addr.as_u64());

    // If no IPC buffer is set, use defaults
    let (dest_depth, src_depth, new_rights, badge) = if ipc_buffer_addr == 0 {
        (0u8, 0u8, CapRights::ALL, Badge::NONE)
    } else {
        // SAFETY: The IPC buffer address is validated by the kernel when set.
        // We're reading from a userspace page that's mapped into the task.
        let ipc_buffer = unsafe { &*(ipc_buffer_addr as *const IpcBuffer) };
        let mint_args = &ipc_buffer.mint_args;

        let badge = if mint_args.should_set_badge() {
            Badge::new(mint_args.badge_value)
        } else {
            Badge::NONE
        };

        (
            mint_args.dest_depth,
            mint_args.src_depth,
            CapRights::from_bits(mint_args.new_rights),
            badge,
        )
    };

    // Resolve both CNode locations
    let src_loc = cspace::resolve_cnode_slot(src_cnode_cptr, src_depth, src_index)?;
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Look up source CDT node
    let src_cdt_node = cdt_storage::lookup_cdt_node(src_loc.cnode_ref, src_loc.slot_index as u32)
        .unwrap_or(CdtNodeId::NULL);

    // Perform the mint with CDT tracking
    with_two_cnodes(src_loc.cnode_ref, dest_loc.cnode_ref, |src_cnode, dest_cnode, _| {
        cdt_storage::with_cdt(|cdt| {
            let new_cdt_node = ops::cap_mint_with_cdt(
                src_cnode,
                src_loc.slot_index,
                dest_cnode,
                dest_loc.slot_index,
                new_rights,
                badge,
                cdt,
                src_cdt_node,
                dest_loc.cnode_ref,
            )
            .map_err(cap_error_to_syscall)?;

            // Register the new CDT node
            if new_cdt_node.is_valid() {
                cdt_storage::register_cdt_node(
                    dest_loc.cnode_ref,
                    dest_loc.slot_index as u32,
                    new_cdt_node,
                );
            }

            Ok(0)
        })
    })
}

/// Handle CapDelete syscall.
///
/// Deletes a single capability from a slot.
/// If the capability has children in the CDT, they are reparented to the grandparent.
///
/// # Arguments (registers)
///
/// - x0: cnode_cptr - CPtr to the CNode
/// - x1: slot_index - Slot index to delete
/// - x2: depth - Bits to consume resolving CNode (0=auto)
pub fn handle_cap_delete(args: &SyscallArgs) -> SyscallResult {
    let cnode_cptr = args.arg0;
    let slot_index = args.arg1 as usize;
    let depth = args.arg2 as u8;

    // Resolve the CNode location
    let loc = cspace::resolve_cnode_slot(cnode_cptr, depth, slot_index)?;

    // Get CDT node before deletion
    let cdt_node = cdt_storage::lookup_cdt_node(loc.cnode_ref, loc.slot_index as u32);

    cspace::with_cnode_mut(loc.cnode_ref, |cnode| {
        if let Some(node_id) = cdt_node {
            // Delete with CDT cleanup
            cdt_storage::with_cdt(|cdt| {
                ops::cap_delete_with_cdt(cnode, loc.slot_index, cdt, node_id)
                    .map_err(cap_error_to_syscall)?;
                Ok(())
            })?;
            cdt_storage::unregister_cdt_node(loc.cnode_ref, loc.slot_index as u32);
        } else {
            // Simple delete without CDT
            ops::cap_delete(cnode, loc.slot_index).map_err(cap_error_to_syscall)?;
        }

        Ok(0)
    })
}

/// Revocation callback that clears slots and updates the slot map.
struct SlotClearCallback;

impl RevocationCallback for SlotClearCallback {
    fn on_revoke(&mut self, node: &m6_cap::CdtNode) {
        // Clear the capability slot
        object_table::with_object(node.slot_cnode, |obj| {
            if obj.obj_type != KernelObjectType::CNode {
                return;
            }
            let cnode_ptr = unsafe { obj.data.cnode_ptr };
            if cnode_ptr.is_null() {
                return;
            }

            let cnode = unsafe { &mut *cnode_ptr };
            if let Some(slot) = cnode.get_slot_mut(node.slot_index as usize)
                && !slot.is_empty()
            {
                slot.clear();
                cnode.meta_mut().decrement_used();
            }
        });

        // Unregister from slot map
        cdt_storage::unregister_cdt_node(node.slot_cnode, node.slot_index);
    }
}

/// Handle CapRevoke syscall.
///
/// Revokes a capability and all its derivatives in the CDT.
/// This is a recursive operation that removes the entire subtree.
///
/// # Arguments (registers)
///
/// - x0: cnode_cptr - CPtr to the CNode
/// - x1: slot_index - Slot index to revoke
/// - x2: depth - Bits to consume resolving CNode (0=auto)
///
/// # Returns
///
/// The number of capabilities revoked (including the target).
pub fn handle_cap_revoke(args: &SyscallArgs) -> SyscallResult {
    let cnode_cptr = args.arg0;
    let slot_index = args.arg1 as usize;
    let depth = args.arg2 as u8;

    // Resolve the CNode location
    let loc = cspace::resolve_cnode_slot(cnode_cptr, depth, slot_index)?;

    // Get the CDT node for this capability
    let cdt_node = cdt_storage::lookup_cdt_node(loc.cnode_ref, loc.slot_index as u32)
        .ok_or(SyscallError::InvalidCap)?;

    // Revoke all descendants
    let count = cdt_storage::with_cdt(|cdt| {
        let mut callback = SlotClearCallback;
        m6_cap::cdt::revoke_subtree(cdt, cdt_node, &mut callback)
    });

    // Unregister the root node from the slot map (revoke_subtree already freed it)
    cdt_storage::unregister_cdt_node(loc.cnode_ref, loc.slot_index as u32);

    Ok(count as i64)
}

/// Handle CapMutate syscall.
///
/// Reduces the rights of a capability in-place.
/// This does not create a new CDT node.
///
/// # Arguments (registers)
///
/// - x0: cnode_cptr - CPtr to the CNode
/// - x1: slot_index - Slot index to mutate
/// - x2: depth - Bits to consume resolving CNode (0=auto)
/// - x3: new_rights - New rights (must be subset of current)
pub fn handle_cap_mutate(args: &SyscallArgs) -> SyscallResult {
    let cnode_cptr = args.arg0;
    let slot_index = args.arg1 as usize;
    let depth = args.arg2 as u8;
    let new_rights = CapRights::from_bits(args.arg3 as u8);

    // Resolve the CNode location
    let loc = cspace::resolve_cnode_slot(cnode_cptr, depth, slot_index)?;

    cspace::with_cnode_mut(loc.cnode_ref, |cnode| {
        ops::cap_mutate(cnode, loc.slot_index, new_rights).map_err(cap_error_to_syscall)?;
        Ok(0)
    })
}

/// Handle CapRotate syscall.
///
/// Atomically rotates capabilities between three slots:
/// - slot1 -> slot2
/// - slot2 -> slot3
/// - slot3 -> slot1
///
/// # Arguments (registers)
///
/// - x0: cnode_cptr - CPtr to the CNode
/// - x1: slot1_index - First slot
/// - x2: slot2_index - Second slot
/// - x3: slot3_index - Third slot
/// - x4: depth - Bits to consume resolving CNode (0=auto)
pub fn handle_cap_rotate(args: &SyscallArgs) -> SyscallResult {
    let cnode_cptr = args.arg0;
    let slot1 = args.arg1 as usize;
    let slot2 = args.arg2 as usize;
    let slot3 = args.arg3 as usize;
    let depth = args.arg4 as u8;

    // Resolve the CNode
    let cnode_ref = cspace::resolve_cptr(cnode_cptr, depth)?;

    // Get the actual CNode reference from the resolved slot
    let cnode_obj_ref = cspace::with_slot(&cnode_ref, |slot| {
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }
        if slot.cap_type() != m6_cap::ObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }
        Ok(slot.object_ref())
    })?;

    cspace::with_cnode_mut(cnode_obj_ref, |cnode| {
        ops::cap_rotate(cnode, slot1, slot2, slot3).map_err(cap_error_to_syscall)?;

        // Update CDT mappings
        cdt_storage::rotate_cdt_mappings(cnode_obj_ref, slot1 as u32, slot2 as u32, slot3 as u32);

        Ok(0)
    })
}
