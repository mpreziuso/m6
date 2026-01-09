//! ASID syscall handlers
//!
//! This module implements syscalls for ASID (Address Space Identifier) management:
//! - AsidPoolAssign: Assign an ASID from a pool to a VSpace

use m6_cap::{CapRights, ObjectType};
use m6_cap::objects::vspace::Asid;

use crate::cap::object_table;
use crate::memory::asid::allocate_asid;
use crate::ipc;

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};

/// Handle AsidPoolAssign syscall.
///
/// Assigns an ASID from an ASID pool to a VSpace.
///
/// # ABI
///
/// - x0: ASID pool capability pointer
/// - x1: VSpace capability pointer
///
/// # Returns
///
/// - ASID value on success (positive integer)
/// - Negative error code on failure
pub fn handle_asid_pool_assign(args: &SyscallArgs) -> SyscallResult {
    let asid_pool_cptr = args.arg0;
    let vspace_cptr = args.arg1;

    // Look up ASID pool capability with WRITE permission
    let asid_pool_cap = ipc::lookup_cap(asid_pool_cptr, ObjectType::ASIDPool, CapRights::WRITE)?;

    // Look up VSpace capability with WRITE permission
    let vspace_cap = ipc::lookup_cap(vspace_cptr, ObjectType::VSpace, CapRights::WRITE)?;

    // Allocate ASID from the global allocator
    let allocated = allocate_asid();
    let asid = Asid::new(allocated.asid);

    // Update ASID pool object
    let pool_asid = object_table::with_asid_pool_mut(asid_pool_cap.obj_ref, |pool| {
        // Try to allocate from the pool (this records the VSpace reference)
        pool.allocate(vspace_cap.obj_ref)
            .ok_or(SyscallError::NoMemory)
    })
    .ok_or(SyscallError::InvalidCap)??;

    // Update VSpace object
    object_table::with_vspace_mut(vspace_cap.obj_ref, |vspace| {
        // Check if VSpace already has an ASID
        if vspace.has_asid() {
            return Err(SyscallError::Range); // Use Range as "already assigned"
        }

        // Assign ASID to VSpace
        vspace.assign_asid_with_generation(asid, allocated.generation);
        Ok(())
    })
    .ok_or(SyscallError::InvalidCap)??;

    log::debug!(
        "Assigned ASID {} to VSpace {:?} (generation {})",
        pool_asid,
        vspace_cap.obj_ref,
        allocated.generation
    );

    Ok(pool_asid as i64)
}
