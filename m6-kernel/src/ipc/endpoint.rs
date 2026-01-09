//! Endpoint IPC operations.
//!
//! This module implements synchronous IPC via endpoints:
//! - Send/Recv: Basic blocking message transfer
//! - Call/ReplyRecv: RPC pattern with reply capabilities
//! - NBSend/NBRecv: Non-blocking variants

use m6_cap::objects::{EndpointState, ThreadState};
use m6_cap::ObjectRef;

use crate::cap::object_table::{self, KernelObjectType};
use crate::syscall::error::SyscallError;

use super::message::IpcMessage;
use super::queue::{ipc_dequeue, ipc_enqueue};

/// Perform a send operation to an endpoint.
///
/// # Arguments
///
/// * `sender_ref` - TCB reference of the sending thread
/// * `ep_ref` - Endpoint object reference
/// * `badge` - Badge from sender's capability
/// * `msg` - Message to send
/// * `blocking` - If true, block until receiver ready; if false, return WouldBlock
///
/// # Returns
///
/// * `Ok(true)` - Message delivered immediately
/// * `Ok(false)` - Sender blocked (blocking=true, no receiver ready)
/// * `Err(WouldBlock)` - No receiver ready (blocking=false)
pub fn do_send(
    sender_ref: ObjectRef,
    ep_ref: ObjectRef,
    badge: u64,
    msg: &IpcMessage,
    blocking: bool,
) -> Result<bool, SyscallError> {
    object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::RecvQueue => {
                // Receiver waiting - transfer message directly
                let receiver_ref = ipc_dequeue(&mut endpoint.queue_head, &mut endpoint.queue_tail)
                    .expect("RecvQueue but empty queue");

                // Update endpoint state
                if endpoint.queue_head.is_null() {
                    endpoint.state = EndpointState::Idle;
                }

                // Transfer message to receiver
                transfer_message(receiver_ref, msg, badge);

                // Wake receiver
                wake_thread(receiver_ref);

                Ok(true)
            }

            EndpointState::Idle | EndpointState::SendQueue => {
                // No receiver waiting
                if !blocking {
                    return Err(SyscallError::WouldBlock);
                }

                // Store message in sender's TCB for later transfer
                store_pending_message(sender_ref, msg, badge);

                // Block sender
                block_thread(sender_ref, ep_ref, ThreadState::BlockedOnSend);

                // Add to send queue
                endpoint.state = EndpointState::SendQueue;
                ipc_enqueue(&mut endpoint.queue_head, &mut endpoint.queue_tail, sender_ref);

                Ok(false)
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Perform a receive operation from an endpoint.
///
/// # Arguments
///
/// * `receiver_ref` - TCB reference of the receiving thread
/// * `ep_ref` - Endpoint object reference
/// * `blocking` - If true, block until sender ready; if false, return WouldBlock
///
/// # Returns
///
/// * `Ok(Some((badge, msg)))` - Message received immediately
/// * `Ok(None)` - Receiver blocked (blocking=true, no sender ready)
/// * `Err(WouldBlock)` - No sender ready (blocking=false)
pub fn do_recv(
    receiver_ref: ObjectRef,
    ep_ref: ObjectRef,
    blocking: bool,
) -> Result<Option<(u64, IpcMessage)>, SyscallError> {
    object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::SendQueue => {
                // Sender waiting - receive message immediately
                let sender_ref = ipc_dequeue(&mut endpoint.queue_head, &mut endpoint.queue_tail)
                    .expect("SendQueue but empty queue");

                // Update endpoint state
                if endpoint.queue_head.is_null() {
                    endpoint.state = EndpointState::Idle;
                }

                // Get pending message from sender
                let (msg, badge) = get_pending_message(sender_ref);

                // Wake sender
                wake_thread(sender_ref);

                Ok(Some((badge, msg)))
            }

            EndpointState::Idle | EndpointState::RecvQueue => {
                // No sender waiting
                if !blocking {
                    return Err(SyscallError::WouldBlock);
                }

                // Block receiver
                block_thread(receiver_ref, ep_ref, ThreadState::BlockedOnRecv);

                // Add to recv queue
                endpoint.state = EndpointState::RecvQueue;
                ipc_enqueue(
                    &mut endpoint.queue_head,
                    &mut endpoint.queue_tail,
                    receiver_ref,
                );

                Ok(None)
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Perform a call operation (send + wait for reply).
///
/// This is the client side of the RPC pattern. The caller sends a message
/// and blocks waiting for a reply. A one-time Reply capability is created
/// and given to the receiver.
///
/// # Arguments
///
/// * `caller_ref` - TCB reference of the calling thread
/// * `ep_ref` - Endpoint object reference
/// * `badge` - Badge from caller's capability
/// * `msg` - Message to send
///
/// # Returns
///
/// * `Ok(true)` - Message delivered, caller now waiting for reply
/// * `Ok(false)` - Caller blocked in send queue
pub fn do_call(
    caller_ref: ObjectRef,
    ep_ref: ObjectRef,
    badge: u64,
    msg: &IpcMessage,
) -> Result<bool, SyscallError> {
    // Create Reply object
    let reply_ref = create_reply_object(caller_ref)?;

    // Store reply reference in caller's TCB
    let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
        tcb.tcb.reply_slot = reply_ref;
    });

    object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::RecvQueue => {
                // Receiver waiting - transfer message and reply cap
                let receiver_ref = ipc_dequeue(&mut endpoint.queue_head, &mut endpoint.queue_tail)
                    .expect("RecvQueue but empty queue");

                if endpoint.queue_head.is_null() {
                    endpoint.state = EndpointState::Idle;
                }

                // Transfer message to receiver
                transfer_message(receiver_ref, msg, badge);

                // Grant reply capability to receiver
                let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                    tcb.tcb.caller = reply_ref;
                });

                // Block caller waiting for reply
                block_thread(caller_ref, ObjectRef::NULL, ThreadState::BlockedOnReply);

                // Wake receiver
                wake_thread(receiver_ref);

                Ok(true)
            }

            EndpointState::Idle | EndpointState::SendQueue => {
                // No receiver - block caller in send queue
                // The reply cap transfer happens when receiver finally dequeues us
                store_pending_message(caller_ref, msg, badge);
                block_thread(caller_ref, ep_ref, ThreadState::BlockedOnSend);

                endpoint.state = EndpointState::SendQueue;
                ipc_enqueue(&mut endpoint.queue_head, &mut endpoint.queue_tail, caller_ref);

                Ok(false)
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?
}

/// Perform a reply-receive operation.
///
/// This is the server side of the RPC pattern. The server replies to the
/// previous caller (if any) and then waits for the next message.
///
/// # Arguments
///
/// * `server_ref` - TCB reference of the server thread
/// * `ep_ref` - Endpoint object reference
/// * `reply_msg` - Message to send as reply
///
/// # Returns
///
/// * `Ok(Some((badge, msg)))` - Reply sent, new message received
/// * `Ok(None)` - Reply sent (or no caller), server now blocked waiting
pub fn do_reply_recv(
    server_ref: ObjectRef,
    ep_ref: ObjectRef,
    reply_msg: &IpcMessage,
) -> Result<Option<(u64, IpcMessage)>, SyscallError> {
    // First, reply to any waiting caller
    let reply_ref: ObjectRef = object_table::with_tcb(server_ref, |tcb| tcb.tcb.caller);

    if reply_ref.is_valid() {
        do_reply_internal(reply_ref, reply_msg)?;

        // Clear caller reference
        let _: () = object_table::with_tcb_mut(server_ref, |tcb| {
            tcb.tcb.caller = ObjectRef::NULL;
        });
    }

    // Then receive on endpoint
    do_recv(server_ref, ep_ref, true)
}

/// Internal reply operation using Reply capability.
fn do_reply_internal(reply_ref: ObjectRef, msg: &IpcMessage) -> Result<(), SyscallError> {
    let caller_ref = object_table::with_reply_mut(reply_ref, |reply| {
        if reply.is_used() {
            return Err(SyscallError::InvalidState);
        }
        reply.mark_used();
        Ok(reply.caller)
    })
    .ok_or(SyscallError::InvalidCap)??;

    // Transfer reply message to caller
    transfer_message(caller_ref, msg, 0);

    // Wake caller from BlockedOnReply
    let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
        if tcb.tcb.state == ThreadState::BlockedOnReply {
            tcb.tcb.state = ThreadState::Running;
            tcb.ipc_blocked_on = ObjectRef::NULL;
        }
    });

    // Add caller to run queue
    crate::sched::insert_task(caller_ref);

    // Clean up reply object
    // SAFETY: Reply is one-time use, we've marked it used and are done with it.
    unsafe { object_table::free(reply_ref) };

    Ok(())
}

/// Create a new Reply object for a caller.
fn create_reply_object(caller_ref: ObjectRef) -> Result<ObjectRef, SyscallError> {
    use core::mem::ManuallyDrop;
    use m6_cap::objects::ReplyObject;

    let reply_ref =
        object_table::alloc(KernelObjectType::Reply).ok_or(SyscallError::NoMemory)?;

    object_table::with_object_mut(reply_ref, |obj| {
        obj.data.reply = ManuallyDrop::new(ReplyObject::new(caller_ref));
    });

    Ok(reply_ref)
}

/// Store a pending message in a sender's TCB.
fn store_pending_message(tcb_ref: ObjectRef, msg: &IpcMessage, badge: u64) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.ipc_message = msg.regs;
        tcb.ipc_badge = badge;
    });
}

/// Get the pending message from a sender's TCB.
fn get_pending_message(tcb_ref: ObjectRef) -> (IpcMessage, u64) {
    object_table::with_tcb(tcb_ref, |tcb| {
        (IpcMessage::from_regs(tcb.ipc_message), tcb.ipc_badge)
    })
}

/// Transfer a message to a receiver's saved context.
fn transfer_message(receiver_ref: ObjectRef, msg: &IpcMessage, badge: u64) {
    let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
        // Write message to receiver's saved register context
        msg.to_context(&mut tcb.context);
        // Badge goes in x6
        tcb.context.gpr[6] = badge;
    });
}

/// Block a thread on an IPC object.
fn block_thread(tcb_ref: ObjectRef, blocked_on: ObjectRef, state: ThreadState) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = state;
        tcb.ipc_blocked_on = blocked_on;
    });

    // Remove from run queue
    crate::sched::remove_task(tcb_ref);
}

/// Wake a blocked thread.
fn wake_thread(tcb_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::Running;
        tcb.ipc_blocked_on = ObjectRef::NULL;
        tcb.clear_ipc_state();
    });

    // Add to run queue
    crate::sched::insert_task(tcb_ref);
}
