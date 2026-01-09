//! Inter-Process Communication (IPC) subsystem.
//!
//! This module implements seL4-style IPC for the M6 microkernel:
//!
//! # Synchronous IPC (Endpoints)
//!
//! Endpoints provide synchronous message passing between threads:
//! - **Send**: Block until a receiver is ready, transfer message
//! - **Recv**: Block until a sender is ready, receive message and badge
//! - **Call**: Send + wait for reply (RPC pattern)
//! - **ReplyRecv**: Reply to previous caller, then wait for next message
//! - **NBSend/NBRecv**: Non-blocking variants that return immediately
//!
//! # Asynchronous IPC (Notifications)
//!
//! Notifications provide asynchronous signalling:
//! - **Signal**: OR badge into notification's signal word (never blocks)
//! - **Wait**: Block until signalled, return accumulated signal word
//! - **Poll**: Non-blocking check of signal word
//!
//! # Message Format
//!
//! Messages use registers x0-x5 (48 bytes total). The badge is delivered
//! in x6 to the receiver. For larger data, use Frame capabilities for
//! zero-copy transfer.
//!
//! # Capability-Based Access
//!
//! All IPC operations require a valid capability:
//! - Send/NBSend/Signal require WRITE right
//! - Recv/NBRecv/Wait/Poll require READ right
//! - Call requires WRITE + GRANT_REPLY rights

pub mod endpoint;
pub mod message;
pub mod notification;
pub mod queue;

pub use endpoint::{do_call, do_recv, do_reply_recv, do_send};
pub use message::IpcMessage;
pub use notification::{do_poll, do_signal, do_wait};
pub use queue::{ipc_dequeue, ipc_enqueue, ipc_remove};

use m6_cap::{CapRights, ObjectRef, ObjectType};

use crate::cap::object_table::{self, KernelObjectType};
use crate::syscall::error::SyscallError;

/// Capability lookup result.
pub struct CapLookupResult {
    /// Object reference.
    pub obj_ref: ObjectRef,
    /// Badge from the capability.
    pub badge: u64,
    /// Rights from the capability.
    pub rights: CapRights,
}

/// Look up a capability by CPtr for IPC operations.
///
/// For now, this implements a simple flat CSpace lookup where the CPtr
/// is just the slot index. A full implementation would walk the CNode
/// hierarchy.
///
/// # Arguments
///
/// * `cptr` - Capability pointer (slot index for flat CSpace)
/// * `expected_type` - Expected object type (Endpoint or Notification)
/// * `required_rights` - Rights required for the operation
///
/// # Returns
///
/// * `Ok(CapLookupResult)` - Capability found with required rights
/// * `Err(InvalidCap)` - Capability not found or invalid
/// * `Err(NoRights)` - Insufficient rights
/// * `Err(TypeMismatch)` - Wrong object type
pub fn lookup_cap(
    cptr: u64,
    expected_type: ObjectType,
    required_rights: CapRights,
) -> Result<CapLookupResult, SyscallError> {
    // Get current task's CSpace root
    let current = crate::sched::current_task().ok_or(SyscallError::InvalidState)?;

    let cspace_root: ObjectRef = object_table::with_tcb(current, |tcb| tcb.tcb.cspace_root);

    if !cspace_root.is_valid() {
        return Err(SyscallError::InvalidCap);
    }

    // For flat CSpace, cptr is the slot index
    let slot_index = cptr as usize;

    // Look up the slot in the CNode
    let result = object_table::with_object(cspace_root, |obj| {
        if obj.obj_type != KernelObjectType::CNode {
            return Err(SyscallError::InvalidCap);
        }

        // SAFETY: We verified the object type.
        let cnode_ptr = unsafe { obj.data.cnode_ptr };
        if cnode_ptr.is_null() {
            return Err(SyscallError::InvalidCap);
        }

        // SAFETY: CNode was allocated properly.
        let cnode = unsafe { &*cnode_ptr };

        use m6_cap::CNodeOps;
        let slot = cnode.get_slot(slot_index).ok_or(SyscallError::InvalidCap)?;

        // Check if slot is empty
        if slot.is_empty() {
            return Err(SyscallError::EmptySlot);
        }

        // Check object type
        if slot.cap_type() != expected_type {
            return Err(SyscallError::TypeMismatch);
        }

        // Check rights
        let slot_rights = slot.rights();
        if !slot_rights.contains(required_rights) {
            return Err(SyscallError::NoRights);
        }

        Ok(CapLookupResult {
            obj_ref: slot.object_ref(),
            badge: slot.badge().value(),
            rights: slot_rights,
        })
    });

    result.ok_or(SyscallError::InvalidCap)?
}
