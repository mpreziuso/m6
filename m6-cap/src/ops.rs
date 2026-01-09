//! Capability operations
//!
//! Core operations for manipulating capabilities:
//!
//! - [`cap_copy`]: Duplicate a capability to another slot
//! - [`cap_move`]: Transfer a capability between slots
//! - [`cap_mint`]: Create a derived capability with reduced rights
//! - [`cap_delete`]: Remove a single capability
//! - [`cap_revoke`]: Remove all derived capabilities
//!
//! # Rights Attenuation
//!
//! The fundamental security property is that rights can only be
//! reduced (attenuated), never increased. When minting a capability,
//! the new rights must be a subset of the source rights.
//!
//! # CDT Integration
//!
//! Copy and mint operations create new nodes in the Capability
//! Derivation Tree (CDT). Revocation uses the CDT to find and
//! remove all derived capabilities.

use crate::cdt::{CdtNodeId, CdtOps};
use crate::cnode::CNodeOps;
use crate::error::{CapError, CapResult};
use crate::slot::{CapSlot, SlotFlags};
use crate::{Badge, CapRights};

/// Copy a capability from source slot to destination slot.
///
/// Creates a sibling in the CDT (shares the same parent as source).
/// The copy has the same rights and badge as the original.
///
/// # Parameters
///
/// - `src`: Source CNode
/// - `src_index`: Index of source slot
/// - `dst`: Destination CNode
/// - `dst_index`: Index of destination slot
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Index out of bounds
/// - [`CapError::EmptySlot`]: Source slot is empty
/// - [`CapError::SlotOccupied`]: Destination slot not empty
pub fn cap_copy<C: CNodeOps>(
    src: &C,
    src_index: usize,
    dst: &mut C,
    dst_index: usize,
) -> CapResult<()> {
    // Get source slot
    let src_slot = src.get_slot(src_index).ok_or(CapError::InvalidIndex)?;

    if src_slot.is_empty() {
        return Err(CapError::EmptySlot);
    }

    // Get destination slot
    let dst_slot = dst.get_slot(dst_index).ok_or(CapError::InvalidIndex)?;

    if !dst_slot.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    // Create copy of capability (without original flag)
    let new_slot = CapSlot::new(
        src_slot.object_ref(),
        src_slot.cap_type(),
        src_slot.rights(),
        src_slot.badge(),
        src_slot.flags().without(SlotFlags::IS_ORIGINAL),
    );

    // Write to destination
    let dst_slot = dst.get_slot_mut(dst_index).ok_or(CapError::InvalidIndex)?;
    *dst_slot = new_slot;

    // Update CNode metadata
    dst.meta_mut().increment_used();

    Ok(())
}

/// Copy a capability with CDT tracking.
///
/// Like [`cap_copy`], but also updates the CDT to track the derivation.
pub fn cap_copy_with_cdt<C: CNodeOps, D: CdtOps>(
    src: &C,
    src_index: usize,
    dst: &mut C,
    dst_index: usize,
    cdt: &mut D,
    src_cdt_node: CdtNodeId,
    dst_cnode_ref: crate::slot::ObjectRef,
) -> CapResult<CdtNodeId> {
    // First do the basic copy
    cap_copy(src, src_index, dst, dst_index)?;

    // Allocate a CDT node for the new capability
    let new_node_id = cdt.alloc_node().ok_or(CapError::OutOfMemory)?;

    // Get the source slot info
    let src_slot = src.get_slot(src_index).ok_or(CapError::InvalidIndex)?;

    // Initialise the CDT node
    if let Some(new_node) = cdt.get_node_mut(new_node_id) {
        new_node.object_ref = src_slot.object_ref();
        new_node.slot_cnode = dst_cnode_ref;
        new_node.slot_index = dst_index as u32;
    }

    // Insert as sibling of source (same parent)
    if src_cdt_node.is_valid() {
        cdt.insert_sibling(src_cdt_node, new_node_id);
    }

    Ok(new_node_id)
}

/// Move a capability from source slot to destination slot.
///
/// The source slot becomes empty. CDT membership transfers with the
/// capability (no new CDT node is created).
///
/// # Parameters
///
/// - `src`: Source CNode (can be same as dst)
/// - `src_index`: Index of source slot
/// - `dst`: Destination CNode
/// - `dst_index`: Index of destination slot
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Index out of bounds
/// - [`CapError::EmptySlot`]: Source slot is empty
/// - [`CapError::SlotOccupied`]: Destination slot not empty
pub fn cap_move<C: CNodeOps>(
    src: &mut C,
    src_index: usize,
    dst: &mut C,
    dst_index: usize,
) -> CapResult<()> {
    // Moving to same slot is a no-op
    if core::ptr::eq(src, dst) && src_index == dst_index {
        return Ok(());
    }

    // Get source slot
    let src_slot = src.get_slot(src_index).ok_or(CapError::InvalidIndex)?;

    if src_slot.is_empty() {
        return Err(CapError::EmptySlot);
    }

    // Check destination is empty
    let dst_slot_ref = dst.get_slot(dst_index).ok_or(CapError::InvalidIndex)?;
    if !dst_slot_ref.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    // Copy slot contents
    let cap_data = CapSlot::new(
        src_slot.object_ref(),
        src_slot.cap_type(),
        src_slot.rights(),
        src_slot.badge(),
        src_slot.flags(),
    );

    // Clear source
    let src_slot = src.get_slot_mut(src_index).ok_or(CapError::InvalidIndex)?;
    src_slot.clear();
    src.meta_mut().decrement_used();

    // Write destination
    let dst_slot = dst.get_slot_mut(dst_index).ok_or(CapError::InvalidIndex)?;
    *dst_slot = cap_data;
    dst.meta_mut().increment_used();

    Ok(())
}

/// Mint a derived capability with reduced rights and/or badge.
///
/// Creates a child in the CDT. The new capability has rights that
/// are a subset of the source rights.
///
/// # Parameters
///
/// - `src`: Source CNode
/// - `src_index`: Index of source slot
/// - `dst`: Destination CNode
/// - `dst_index`: Index of destination slot
/// - `new_rights`: Rights for the new capability (must be subset of source)
/// - `badge`: Badge for the new capability
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Index out of bounds
/// - [`CapError::EmptySlot`]: Source slot is empty
/// - [`CapError::SlotOccupied`]: Destination slot not empty
/// - [`CapError::RightsEscalation`]: New rights not subset of source
/// - [`CapError::BadgeNotSupported`]: Object type doesn't support badges
/// - [`CapError::BadgeAlreadySet`]: Source has badge, new badge differs
pub fn cap_mint<C: CNodeOps>(
    src: &C,
    src_index: usize,
    dst: &mut C,
    dst_index: usize,
    new_rights: CapRights,
    badge: Badge,
) -> CapResult<()> {
    // Get source slot
    let src_slot = src.get_slot(src_index).ok_or(CapError::InvalidIndex)?;

    if src_slot.is_empty() {
        return Err(CapError::EmptySlot);
    }

    // Rights can only be reduced, never increased
    if !new_rights.is_subset_of(src_slot.rights()) {
        return Err(CapError::RightsEscalation);
    }

    // Check badge support
    let cap_type = src_slot.cap_type();
    if badge.is_some() && !cap_type.supports_badge() {
        return Err(CapError::BadgeNotSupported);
    }

    // If source has badge, new badge must match or be none
    if src_slot.badge().is_some() && badge.is_some() && badge != src_slot.badge() {
        return Err(CapError::BadgeAlreadySet);
    }

    // Check destination is empty
    let dst_slot_ref = dst.get_slot(dst_index).ok_or(CapError::InvalidIndex)?;
    if !dst_slot_ref.is_empty() {
        return Err(CapError::SlotOccupied);
    }

    // Determine effective badge
    let effective_badge = if badge.is_some() {
        badge
    } else {
        src_slot.badge()
    };

    // Create minted capability
    let new_slot = CapSlot::new(
        src_slot.object_ref(),
        cap_type,
        new_rights,
        effective_badge,
        SlotFlags::IN_CDT, // Minted caps are in CDT
    );

    // Write destination
    let dst_slot = dst.get_slot_mut(dst_index).ok_or(CapError::InvalidIndex)?;
    *dst_slot = new_slot;
    dst.meta_mut().increment_used();

    Ok(())
}

/// Mint with CDT tracking.
///
/// Like [`cap_mint`], but also updates the CDT to track the derivation.
#[allow(clippy::too_many_arguments)]
pub fn cap_mint_with_cdt<C: CNodeOps, D: CdtOps>(
    src: &C,
    src_index: usize,
    dst: &mut C,
    dst_index: usize,
    new_rights: CapRights,
    badge: Badge,
    cdt: &mut D,
    src_cdt_node: CdtNodeId,
    dst_cnode_ref: crate::slot::ObjectRef,
) -> CapResult<CdtNodeId> {
    // First do the basic mint
    cap_mint(src, src_index, dst, dst_index, new_rights, badge)?;

    // Allocate a CDT node for the new capability
    let new_node_id = cdt.alloc_node().ok_or(CapError::OutOfMemory)?;

    // Get the source slot info
    let src_slot = src.get_slot(src_index).ok_or(CapError::InvalidIndex)?;

    // Initialise the CDT node
    if let Some(new_node) = cdt.get_node_mut(new_node_id) {
        new_node.object_ref = src_slot.object_ref();
        new_node.slot_cnode = dst_cnode_ref;
        new_node.slot_index = dst_index as u32;
    }

    // Insert as child of source
    if src_cdt_node.is_valid() {
        cdt.insert_child(src_cdt_node, new_node_id);
    }

    Ok(new_node_id)
}

/// Delete a single capability.
///
/// Removes the capability from the slot. If the capability has
/// children in the CDT, they are reparented to the grandparent.
///
/// # Parameters
///
/// - `cnode`: The CNode containing the capability
/// - `index`: Index of the slot to delete
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Index out of bounds
///
/// # Note
///
/// Deleting an empty slot is a no-op (returns Ok).
pub fn cap_delete<C: CNodeOps>(cnode: &mut C, index: usize) -> CapResult<()> {
    let slot = cnode.get_slot_mut(index).ok_or(CapError::InvalidIndex)?;

    if slot.is_empty() {
        return Ok(()); // Deleting empty slot is a no-op
    }

    slot.clear();
    cnode.meta_mut().decrement_used();

    Ok(())
}

/// Delete with CDT cleanup.
///
/// Like [`cap_delete`], but also handles CDT node cleanup.
pub fn cap_delete_with_cdt<C: CNodeOps, D: CdtOps>(
    cnode: &mut C,
    index: usize,
    cdt: &mut D,
    cdt_node: CdtNodeId,
) -> CapResult<()> {
    // Get the node to find parent for reparenting
    let parent = if let Some(node) = cdt.get_node(cdt_node) {
        node.parent
    } else {
        CdtNodeId::NULL
    };

    // Reparent children to grandparent
    cdt.reparent_children(cdt_node, parent);

    // Remove from CDT
    cdt.remove_from_parent(cdt_node);
    cdt.free_node(cdt_node);

    // Delete the capability
    cap_delete(cnode, index)
}

/// Mutate a capability's rights in place.
///
/// Reduces the rights of an existing capability. This is similar
/// to minting but modifies the capability in place.
///
/// # Parameters
///
/// - `cnode`: The CNode containing the capability
/// - `index`: Index of the slot to mutate
/// - `new_rights`: New rights (must be subset of current)
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Index out of bounds
/// - [`CapError::EmptySlot`]: Slot is empty
/// - [`CapError::RightsEscalation`]: New rights not subset of current
pub fn cap_mutate<C: CNodeOps>(
    cnode: &mut C,
    index: usize,
    new_rights: CapRights,
) -> CapResult<()> {
    let slot = cnode.get_slot(index).ok_or(CapError::InvalidIndex)?;

    if slot.is_empty() {
        return Err(CapError::EmptySlot);
    }

    // Rights can only be reduced
    if !new_rights.is_subset_of(slot.rights()) {
        return Err(CapError::RightsEscalation);
    }

    // Create new slot with reduced rights
    let new_slot = CapSlot::new(
        slot.object_ref(),
        slot.cap_type(),
        new_rights,
        slot.badge(),
        slot.flags(),
    );

    let slot = cnode.get_slot_mut(index).ok_or(CapError::InvalidIndex)?;
    *slot = new_slot;

    Ok(())
}

/// Rotate capabilities between three slots.
///
/// Atomically moves capabilities in a cycle:
/// - slot1 -> slot2
/// - slot2 -> slot3
/// - slot3 -> slot1
///
/// This is useful for implementing certain IPC patterns.
///
/// # Parameters
///
/// - `cnode`: The CNode containing all three slots
/// - `slot1`, `slot2`, `slot3`: Indices of the three slots
///
/// # Errors
///
/// - [`CapError::InvalidIndex`]: Any index out of bounds
pub fn cap_rotate<C: CNodeOps>(
    cnode: &mut C,
    slot1: usize,
    slot2: usize,
    slot3: usize,
) -> CapResult<()> {
    // Get all three slots (must all be valid indices)
    let s1 = cnode.get_slot(slot1).ok_or(CapError::InvalidIndex)?;
    let s2 = cnode.get_slot(slot2).ok_or(CapError::InvalidIndex)?;
    let s3 = cnode.get_slot(slot3).ok_or(CapError::InvalidIndex)?;

    // Copy the contents
    let data1 = CapSlot::new(
        s1.object_ref(),
        s1.cap_type(),
        s1.rights(),
        s1.badge(),
        s1.flags(),
    );
    let data2 = CapSlot::new(
        s2.object_ref(),
        s2.cap_type(),
        s2.rights(),
        s2.badge(),
        s2.flags(),
    );
    let data3 = CapSlot::new(
        s3.object_ref(),
        s3.cap_type(),
        s3.rights(),
        s3.badge(),
        s3.flags(),
    );

    // Rotate: 1->2, 2->3, 3->1
    *cnode.get_slot_mut(slot2).ok_or(CapError::InvalidIndex)? = data1;
    *cnode.get_slot_mut(slot3).ok_or(CapError::InvalidIndex)? = data2;
    *cnode.get_slot_mut(slot1).ok_or(CapError::InvalidIndex)? = data3;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests would require a mock CNode implementation
    // which is complex to set up in unit tests
}
