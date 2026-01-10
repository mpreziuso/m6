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

pub mod cap_transfer;
pub mod endpoint;
pub mod fault;
pub mod message;
pub mod notification;
pub mod queue;

pub use endpoint::{do_call, do_recv, do_reply_recv, do_send};
pub use fault::{classify_fault, deliver_fault, handle_user_fault, FaultDeliveryError};
pub use message::IpcMessage;
pub use notification::{do_poll, do_signal, do_wait};
pub use queue::{ipc_dequeue, ipc_enqueue, ipc_remove};

use m6_cap::{CapRights, ObjectRef, ObjectType};

use crate::cap::cspace;
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
/// Resolves the CPtr through the hierarchical CSpace using guard-based
/// addressing, then validates the capability type and rights.
///
/// # Arguments
///
/// * `cptr` - Capability pointer resolved through CNode hierarchy
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
    // Resolve CPtr through hierarchical CSpace (depth 0 = auto)
    let loc = cspace::resolve_cptr(cptr, 0)?;

    log::trace!(
        "lookup_cap: cptr={:#x} resolved to cnode={:?} slot={}",
        cptr, loc.cnode_ref, loc.slot_index
    );

    // Access the resolved slot and validate
    cspace::with_slot(&loc, |slot| {
        // Check if slot is empty
        if slot.is_empty() {
            log::trace!("lookup_cap: slot {} is EMPTY", loc.slot_index);
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
    })
}
