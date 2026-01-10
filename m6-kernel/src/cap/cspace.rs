//! CSpace resolution - hierarchical CPtr lookup
//!
//! This module implements seL4-style hierarchical CPtr resolution through
//! CNode guards. A CPtr is a 64-bit value interpreted as concatenated
//! indices through a CNode hierarchy.
//!
//! # Resolution Algorithm
//!
//! 1. Start at the task's CSpace root (a CNode)
//! 2. At each CNode:
//!    - Check guard matches at current depth
//!    - Extract index bits from CPtr
//!    - Look up slot at that index
//! 3. If slot contains a CNode capability and bits remain, recurse
//! 4. Otherwise, return the final slot location

use m6_cap::{CNodeOps, CPtr, CptrDepth, ObjectRef, ObjectType};

use crate::cap::cnode_storage::CNodeStorage;
use crate::cap::object_table::{self, KernelObjectType};
use crate::syscall::error::SyscallError;

/// Result of resolving a CPtr to a slot location.
#[derive(Debug, Clone, Copy)]
pub struct SlotLocation {
    /// ObjectRef of the CNode containing the slot.
    pub cnode_ref: ObjectRef,
    /// Index of the slot within the CNode.
    pub slot_index: usize,
}

/// Maximum depth of CSpace resolution to prevent infinite loops.
const MAX_RESOLUTION_DEPTH: usize = 16;

/// Resolve a CPtr to a slot location using the current task's CSpace.
///
/// # Arguments
///
/// * `cptr` - The capability pointer to resolve
/// * `depth_bits` - Number of bits to consume (0 = use CNode radix)
///
/// # Returns
///
/// The resolved slot location, or an error if resolution fails.
pub fn resolve_cptr(cptr: u64, depth_bits: u8) -> Result<SlotLocation, SyscallError> {
    // Get current task's CSpace root
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    let cspace_root: ObjectRef = object_table::with_tcb(current, |tcb| tcb.tcb.cspace_root);

    log::trace!(
        "resolve_cptr: cptr={:#x} current_task={:?} cspace_root={:?}",
        cptr, current, cspace_root
    );

    if !cspace_root.is_valid() {
        log::warn!("resolve_cptr: cspace_root is invalid!");
        return Err(SyscallError::InvalidCap);
    }

    resolve_cptr_from_root(cspace_root, cptr, depth_bits)
}

/// Resolve a CPtr starting from a specific CSpace root.
///
/// # Arguments
///
/// * `root` - The CSpace root CNode
/// * `cptr` - The capability pointer to resolve
/// * `depth_bits` - Number of bits to consume (0 = single-level resolution using CNode's radix)
pub fn resolve_cptr_from_root(
    root: ObjectRef,
    cptr: u64,
    depth_bits: u8,
) -> Result<SlotLocation, SyscallError> {
    let cptr_val = CPtr::from_raw(cptr);

    // If depth_bits is 0, do single-level resolution using the root CNode's radix
    // This provides flat CSpace semantics where cptr = slot_index << (64 - radix)
    let max_depth = if depth_bits == 0 {
        // Get the root CNode's radix for single-level resolution
        let radix = object_table::with_object(root, |obj| {
            if obj.obj_type != KernelObjectType::CNode {
                return 0u8;
            }
            let cnode_ptr = unsafe { obj.data.cnode_ptr };
            if cnode_ptr.is_null() {
                return 0u8;
            }
            let cnode = unsafe { &*cnode_ptr };
            cnode.meta().radix()
        }).unwrap_or(12); // default to radix 12 if lookup fails
        CptrDepth::new(radix)
    } else {
        CptrDepth::new(depth_bits)
    };

    resolve_recursive(root, cptr_val, CptrDepth::START, max_depth, 0)
}

/// Resolve a CNode CPtr and slot index (seL4-style addressing).
///
/// This is the common pattern for capability syscalls where the caller
/// specifies a CNode capability and a slot index within that CNode.
///
/// # Arguments
///
/// * `cnode_cptr` - CPtr to the target CNode
/// * `cnode_depth` - Bits to consume resolving the CNode (0 = auto)
/// * `slot_index` - Slot index within the resolved CNode
pub fn resolve_cnode_slot(
    cnode_cptr: u64,
    cnode_depth: u8,
    slot_index: usize,
) -> Result<SlotLocation, SyscallError> {
    // First resolve the CNode CPtr to find which CNode we're operating on
    let cnode_loc = resolve_cptr(cnode_cptr, cnode_depth)?;

    // Get the CNode and verify the slot index is valid
    let cnode_ref = get_cnode_from_slot(cnode_loc)?;

    log::trace!(
        "resolve_cnode_slot: cnode_ref={:?} checking slot_index={}",
        cnode_ref, slot_index
    );

    // Verify the slot index is within bounds
    let result = object_table::with_object(cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            log::warn!(
                "resolve_cnode_slot: obj_type is {:?}, expected CNode",
                obj.obj_type
            );
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            log::warn!("resolve_cnode_slot: cnode_ptr is null");
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &*cnode_ptr };
        let num_slots = cnode.meta().num_slots();

        log::trace!(
            "resolve_cnode_slot: cnode has {} slots, checking index {}",
            num_slots, slot_index
        );

        if slot_index >= num_slots {
            log::warn!(
                "resolve_cnode_slot: slot_index {} >= num_slots {}",
                slot_index, num_slots
            );
            return Err(SyscallError::InvalidCap);
        }

        Ok(SlotLocation {
            cnode_ref,
            slot_index,
        })
    });

    match result {
        Some(r) => r,
        None => {
            log::warn!(
                "resolve_cnode_slot: with_object returned None for {:?}",
                cnode_ref
            );
            Err(SyscallError::InvalidCap)
        }
    }
}

/// Get the CNode ObjectRef from a resolved slot location.
///
/// The slot at the location must contain a CNode capability.
fn get_cnode_from_slot(loc: SlotLocation) -> Result<ObjectRef, SyscallError> {
    log::trace!(
        "get_cnode_from_slot: cnode_ref={:?} slot_index={}",
        loc.cnode_ref, loc.slot_index
    );

    let result = object_table::with_object(loc.cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            log::warn!("get_cnode_from_slot: obj_type is {:?}, expected CNode", obj.obj_type);
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            log::warn!("get_cnode_from_slot: cnode_ptr is null");
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &*cnode_ptr };
        let slot = cnode.get_slot(loc.slot_index).ok_or_else(|| {
            log::warn!("get_cnode_from_slot: slot {} not found", loc.slot_index);
            SyscallError::InvalidCap
        })?;

        if slot.is_empty() {
            log::warn!("get_cnode_from_slot: slot {} is empty", loc.slot_index);
            return Err(SyscallError::EmptySlot);
        }

        let cap_type = slot.cap_type();
        if cap_type != ObjectType::CNode {
            log::warn!(
                "get_cnode_from_slot: slot {} has type {:?}, expected CNode",
                loc.slot_index, cap_type
            );
            return Err(SyscallError::TypeMismatch);
        }

        Ok(slot.object_ref())
    });

    match result {
        Some(r) => r,
        None => {
            log::warn!("get_cnode_from_slot: with_object returned None for {:?}", loc.cnode_ref);
            Err(SyscallError::InvalidCap)
        }
    }
}

/// Recursive CPtr resolution.
fn resolve_recursive(
    cnode_ref: ObjectRef,
    cptr: CPtr,
    depth: CptrDepth,
    max_depth: CptrDepth,
    recursion_depth: usize,
) -> Result<SlotLocation, SyscallError> {
    // Prevent infinite loops
    if recursion_depth >= MAX_RESOLUTION_DEPTH {
        return Err(SyscallError::DepthExceeded);
    }

    // Check if we've consumed all required bits
    if depth.bits_consumed() >= max_depth.bits_consumed() {
        return Err(SyscallError::DepthExceeded);
    }

    // Get the CNode and resolve one level
    let result = object_table::with_object(cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        // SAFETY: CNode was allocated properly.
        let cnode = unsafe { &*cnode_ptr };

        // Use the m6-cap resolution logic
        let (index, new_depth) = cnode
            .resolve_local(cptr, depth)
            .map_err(crate::syscall::error::cap_error_to_syscall)?;

        // Get the slot
        let slot = cnode.get_slot(index).ok_or(SyscallError::InvalidCap)?;

        // Check if we should continue resolution
        let should_continue = !slot.is_empty()
            && slot.cap_type() == ObjectType::CNode
            && new_depth.bits_consumed() < max_depth.bits_consumed();

        if should_continue {
            // Return the next CNode to recurse into
            Ok((None, Some((slot.object_ref(), new_depth))))
        } else {
            // Final slot reached
            Ok((
                Some(SlotLocation {
                    cnode_ref,
                    slot_index: index,
                }),
                None,
            ))
        }
    })
    .ok_or(SyscallError::InvalidCap)??;

    match result {
        (Some(location), None) => Ok(location),
        (None, Some((next_cnode, new_depth))) => {
            resolve_recursive(next_cnode, cptr, new_depth, max_depth, recursion_depth + 1)
        }
        _ => Err(SyscallError::InvalidCap),
    }
}

/// Access a resolved slot with a closure (immutable).
pub fn with_slot<F, R>(loc: &SlotLocation, f: F) -> Result<R, SyscallError>
where
    F: FnOnce(&m6_cap::CapSlot) -> Result<R, SyscallError>,
{
    object_table::with_object(loc.cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &*cnode_ptr };
        let slot = cnode
            .get_slot(loc.slot_index)
            .ok_or(SyscallError::InvalidCap)?;

        f(slot)
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Access a resolved slot with a closure (mutable).
pub fn with_slot_mut<F, R>(loc: &SlotLocation, f: F) -> Result<R, SyscallError>
where
    F: FnOnce(&mut m6_cap::CapSlot) -> Result<R, SyscallError>,
{
    object_table::with_object(loc.cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &mut *cnode_ptr };
        let slot = cnode
            .get_slot_mut(loc.slot_index)
            .ok_or(SyscallError::InvalidCap)?;

        f(slot)
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Access a CNode by ObjectRef with a closure.
pub fn with_cnode<F, R>(cnode_ref: ObjectRef, f: F) -> Result<R, SyscallError>
where
    F: FnOnce(&CNodeStorage) -> Result<R, SyscallError>,
{
    object_table::with_object(cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &*cnode_ptr };
        f(cnode)
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Access a CNode by ObjectRef with a mutable closure.
pub fn with_cnode_mut<F, R>(cnode_ref: ObjectRef, f: F) -> Result<R, SyscallError>
where
    F: FnOnce(&mut CNodeStorage) -> Result<R, SyscallError>,
{
    object_table::with_object(cnode_ref, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }

        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        let cnode = unsafe { &mut *cnode_ptr };
        f(cnode)
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Access two CNodes with proper lock ordering.
///
/// To prevent deadlocks, CNodes are always accessed in order of their
/// ObjectRef index (lower index first).
///
/// The `swapped` parameter in the callback indicates whether the CNodes
/// were swapped for ordering - if true, the first CNode passed is actually
/// ref2 and the second is ref1.
///
/// # Same CNode Case
///
/// If `ref1 == ref2`, the same CNode is passed twice. The caller must ensure
/// they don't access overlapping slots mutably (which the capability operations
/// guarantee by operating on distinct slot indices).
pub fn with_two_cnodes<F, R>(
    ref1: ObjectRef,
    ref2: ObjectRef,
    f: F,
) -> Result<R, SyscallError>
where
    F: FnOnce(&mut CNodeStorage, &mut CNodeStorage, bool) -> Result<R, SyscallError>,
{
    // Use a single lock acquisition to avoid self-deadlock when nesting
    object_table::with_table(|table| {
        // Handle same-CNode case
        if ref1 == ref2 {
            let obj = table.get(ref1).ok_or(SyscallError::InvalidCap)?;
            if obj.obj_type != KernelObjectType::CNode {
                return Err(SyscallError::TypeMismatch);
            }
            let ptr = unsafe { obj.data.cnode_ptr };
            if ptr.is_null() {
                return Err(SyscallError::InvalidCap);
            }

            // SAFETY: We create two mutable references to the same CNode.
            // This is safe because:
            // 1. The capability operations (copy, move, etc.) operate on
            //    distinct slot indices within the CNode
            // 2. CapSlot is 16 bytes and slots don't overlap
            // 3. The caller ensures they don't modify the same slot twice
            let cnode1 = unsafe { &mut *ptr };
            let cnode2 = unsafe { &mut *ptr };
            return f(cnode1, cnode2, false);
        }

        // Order by ObjectRef index for consistent ordering (not for deadlock
        // prevention since we use a single lock)
        let swapped = ref1.index() > ref2.index();
        let (first_ref, second_ref) = if swapped {
            (ref2, ref1)
        } else {
            (ref1, ref2)
        };

        // Access both objects within the same lock scope
        let obj1 = table.get(first_ref).ok_or(SyscallError::InvalidCap)?;
        if obj1.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }
        let ptr1 = unsafe { obj1.data.cnode_ptr };
        if ptr1.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        let obj2 = table.get(second_ref).ok_or(SyscallError::InvalidCap)?;
        if obj2.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::TypeMismatch);
        }
        let ptr2 = unsafe { obj2.data.cnode_ptr };
        if ptr2.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        // SAFETY: We've verified both pointers are valid CNodes
        // and they are different objects (checked above).
        let cnode1 = unsafe { &mut *ptr1 };
        let cnode2 = unsafe { &mut *ptr2 };

        if swapped {
            f(cnode2, cnode1, swapped)
        } else {
            f(cnode1, cnode2, swapped)
        }
    })
}
