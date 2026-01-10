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
    has_grant: bool,
) -> Result<bool, SyscallError> {
    // Determine action inside endpoint lock, execute outside
    enum Action {
        DeliverTo(ObjectRef),
        BlockInSendQueue,
        WouldBlock,
    }

    let action = object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::RecvQueue => {
                // Get receiver from queue head
                let receiver_ref = endpoint.queue_head;
                if !receiver_ref.is_valid() {
                    panic!("RecvQueue but empty queue");
                }
                Action::DeliverTo(receiver_ref)
            }
            EndpointState::Idle | EndpointState::SendQueue => {
                if !blocking {
                    Action::WouldBlock
                } else {
                    Action::BlockInSendQueue
                }
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?;

    // Execute action OUTSIDE the endpoint lock
    match action {
        Action::DeliverTo(receiver_ref) => {
            // Get next in queue and clear receiver's links
            let next_in_queue: ObjectRef = object_table::with_tcb_mut(receiver_ref, |tcb| {
                let next = tcb.ipc_next;
                tcb.clear_ipc_links();
                next
            });

            // Update endpoint queue state
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.queue_head = next_in_queue;
                if !next_in_queue.is_valid() {
                    endpoint.queue_tail = ObjectRef::NULL;
                    endpoint.state = EndpointState::Idle;
                }
            });

            // Clear prev link of new head if it exists
            if next_in_queue.is_valid() {
                let _: () = object_table::with_tcb_mut(next_in_queue, |new_head| {
                    new_head.ipc_prev = ObjectRef::NULL;
                });
            }

            // Transfer capabilities if Grant right present
            if let Err(e) = super::cap_transfer::transfer_capabilities(sender_ref, receiver_ref, has_grant) {
                log::debug!("Capability transfer failed during send: {:?}", e);
            }

            // Transfer message to receiver
            transfer_message(receiver_ref, msg, badge);

            // Wake receiver
            wake_thread(receiver_ref);

            Ok(true)
        }

        Action::BlockInSendQueue => {
            // Store message in sender's TCB
            store_pending_message(sender_ref, msg, badge);

            // Block sender
            block_thread(sender_ref, ep_ref, ThreadState::BlockedOnSend);

            // Get current queue tail
            let old_tail = object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.queue_tail
            }).ok_or(SyscallError::InvalidCap)?;

            // Set up sender's queue links
            let _: () = object_table::with_tcb_mut(sender_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            // Link old tail to sender
            if old_tail.is_valid() {
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = sender_ref;
                });
            }

            // Update endpoint queue
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.state = EndpointState::SendQueue;
                if old_tail.is_valid() {
                    endpoint.queue_tail = sender_ref;
                } else {
                    // Queue was empty
                    endpoint.queue_head = sender_ref;
                    endpoint.queue_tail = sender_ref;
                }
            });

            Ok(false)
        }

        Action::WouldBlock => Err(SyscallError::WouldBlock),
    }
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
    has_grant: bool,
) -> Result<Option<(u64, IpcMessage)>, SyscallError> {
    // Determine action inside endpoint lock, execute outside
    enum Action {
        ReceiveFrom(ObjectRef),
        Block,
        WouldBlock,
    }

    let action = object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::SendQueue => {
                // Get sender from queue head (don't dequeue inside lock!)
                let sender_ref = endpoint.queue_head;
                if !sender_ref.is_valid() {
                    panic!("SendQueue but empty queue");
                }
                Action::ReceiveFrom(sender_ref)
            }

            EndpointState::Idle | EndpointState::RecvQueue => {
                // No sender waiting
                if !blocking {
                    Action::WouldBlock
                } else {
                    Action::Block
                }
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?;

    // Now execute the action WITHOUT holding any locks
    match action {
        Action::ReceiveFrom(sender_ref) => {
            // Get next in queue and clear sender's links (outside endpoint lock)
            let next_in_queue: ObjectRef = object_table::with_tcb_mut(sender_ref, |tcb| {
                let next = tcb.ipc_next;
                tcb.clear_ipc_links();
                next
            });

            // Update endpoint queue state
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.queue_head = next_in_queue;
                if !next_in_queue.is_valid() {
                    endpoint.queue_tail = ObjectRef::NULL;
                    endpoint.state = EndpointState::Idle;
                }
            });

            // Clear prev link of new head if it exists
            if next_in_queue.is_valid() {
                let _: () = object_table::with_tcb_mut(next_in_queue, |new_head| {
                    new_head.ipc_prev = ObjectRef::NULL;
                });
            }

            // Transfer capabilities if Grant right present
            if let Err(e) = super::cap_transfer::transfer_capabilities(sender_ref, receiver_ref, has_grant) {
                // If capability transfer fails, we still deliver the message
                log::debug!("Capability transfer failed during recv: {:?}", e);
            }

            // Get pending message from sender
            let (msg, badge) = get_pending_message(sender_ref);

            // Check if sender was a Call operation (has reply_slot set)
            let sender_reply_slot: ObjectRef = object_table::with_tcb(sender_ref, |tcb| {
                tcb.tcb.reply_slot
            });

            if sender_reply_slot.is_valid() {
                // This was a Call - transfer reply capability to receiver and keep sender blocked
                log::trace!(
                    "do_recv: sender {:?} was Call, reply_slot={:?}, transferring to receiver {:?}",
                    sender_ref, sender_reply_slot, receiver_ref
                );

                // Grant reply capability to receiver
                let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                    tcb.tcb.caller = sender_reply_slot;
                });

                // Change sender state from BlockedOnSend to BlockedOnReply
                let _: () = object_table::with_tcb_mut(sender_ref, |tcb| {
                    tcb.tcb.state = ThreadState::BlockedOnReply;
                    tcb.ipc_blocked_on = ObjectRef::NULL;
                    // Clear reply_slot since it's been transferred
                    tcb.tcb.reply_slot = ObjectRef::NULL;
                });
            } else {
                // This was a normal Send - wake the sender
                wake_thread(sender_ref);
            }

            Ok(Some((badge, msg)))
        }

        Action::Block => {
            // Block the receiver
            block_thread(receiver_ref, ep_ref, ThreadState::BlockedOnRecv);

            // Get current queue state
            let (_old_head, old_tail) = object_table::with_endpoint_mut(ep_ref, |endpoint| {
                (endpoint.queue_head, endpoint.queue_tail)
            })
            .ok_or(SyscallError::InvalidCap)?;

            // Update TCB queue links (this locks TCBs, not endpoint)
            let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            if old_tail.is_valid() {
                // Link old tail to new entry
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = receiver_ref;
                });
            }

            // Now update endpoint with new queue state
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.state = EndpointState::RecvQueue;
                if old_tail.is_valid() {
                    endpoint.queue_tail = receiver_ref;
                } else {
                    // Queue was empty - new entry is both head and tail
                    endpoint.queue_head = receiver_ref;
                    endpoint.queue_tail = receiver_ref;
                }
            })
            .ok_or(SyscallError::InvalidCap)?;

            Ok(None)
        }

        Action::WouldBlock => Err(SyscallError::WouldBlock),
    }
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
    has_grant: bool,
) -> Result<bool, SyscallError> {
    // Create Reply object BEFORE locking endpoint
    let reply_ref = create_reply_object(caller_ref)?;

    // Store reply reference in caller's TCB BEFORE locking endpoint
    let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
        tcb.tcb.reply_slot = reply_ref;
    });

    // Determine action inside endpoint lock, execute outside
    enum Action {
        DeliverTo(ObjectRef),
        BlockInSendQueue,
    }

    let action = object_table::with_endpoint_mut(ep_ref, |endpoint| {
        match endpoint.state {
            EndpointState::RecvQueue => {
                // Get receiver from queue head
                let receiver_ref = endpoint.queue_head;
                if !receiver_ref.is_valid() {
                    panic!("RecvQueue but empty queue");
                }
                Action::DeliverTo(receiver_ref)
            }
            EndpointState::Idle | EndpointState::SendQueue => {
                Action::BlockInSendQueue
            }
        }
    })
    .ok_or(SyscallError::InvalidCap)?;

    // Execute action OUTSIDE the endpoint lock
    match action {
        Action::DeliverTo(receiver_ref) => {
            // Get next in queue and clear receiver's links (outside endpoint lock)
            let next_in_queue: ObjectRef = object_table::with_tcb_mut(receiver_ref, |tcb| {
                let next = tcb.ipc_next;
                tcb.clear_ipc_links();
                next
            });

            // Update endpoint queue state
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.queue_head = next_in_queue;
                if !next_in_queue.is_valid() {
                    endpoint.queue_tail = ObjectRef::NULL;
                    endpoint.state = EndpointState::Idle;
                }
            });

            // Clear prev link of new head if it exists
            if next_in_queue.is_valid() {
                let _: () = object_table::with_tcb_mut(next_in_queue, |new_head| {
                    new_head.ipc_prev = ObjectRef::NULL;
                });
            }

            // Transfer capabilities if Grant right present
            if let Err(e) = super::cap_transfer::transfer_capabilities(caller_ref, receiver_ref, has_grant) {
                log::debug!("Capability transfer failed during call: {:?}", e);
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

        Action::BlockInSendQueue => {
            // Store message in caller's TCB
            store_pending_message(caller_ref, msg, badge);

            // Block caller
            block_thread(caller_ref, ep_ref, ThreadState::BlockedOnSend);

            // Get current queue tail
            let old_tail = object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.queue_tail
            }).ok_or(SyscallError::InvalidCap)?;

            // Set up caller's queue links
            let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            // Link old tail to caller
            if old_tail.is_valid() {
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = caller_ref;
                });
            }

            // Update endpoint queue
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                endpoint.state = EndpointState::SendQueue;
                if old_tail.is_valid() {
                    endpoint.queue_tail = caller_ref;
                } else {
                    // Queue was empty
                    endpoint.queue_head = caller_ref;
                    endpoint.queue_tail = caller_ref;
                }
            });

            Ok(false)
        }
    }
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
    has_grant: bool,
) -> Result<Option<(u64, IpcMessage)>, SyscallError> {
    // First, reply to any waiting caller
    let reply_ref: ObjectRef = object_table::with_tcb(server_ref, |tcb| tcb.tcb.caller);

    log::trace!(
        "do_reply_recv: server={:?}, reply_ref={:?}, reply_msg[0]={:#x}",
        server_ref, reply_ref, reply_msg.regs[0]
    );

    if reply_ref.is_valid() {
        do_reply_internal(reply_ref, reply_msg)?;

        // Clear caller reference
        let _: () = object_table::with_tcb_mut(server_ref, |tcb| {
            tcb.tcb.caller = ObjectRef::NULL;
        });
    } else {
        log::trace!("do_reply_recv: no caller to reply to");
    }

    // Then receive on endpoint
    do_recv(server_ref, ep_ref, true, has_grant)
}

/// Internal reply operation using Reply capability.
fn do_reply_internal(reply_ref: ObjectRef, msg: &IpcMessage) -> Result<(), SyscallError> {
    log::trace!(
        "do_reply_internal: reply_ref={:?}, msg[0]={:#x}",
        reply_ref, msg.regs[0]
    );

    let caller_ref = object_table::with_reply_mut(reply_ref, |reply| {
        if reply.is_used() {
            return Err(SyscallError::InvalidState);
        }
        reply.mark_used();
        Ok(reply.caller)
    })
    .ok_or(SyscallError::InvalidCap)??;

    log::trace!("do_reply_internal: caller_ref={:?}", caller_ref);

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
        log::trace!(
            "transfer_message: before x0={:#x}, writing msg[0]={:#x}",
            tcb.context.gpr[0], msg.regs[0]
        );
        // Write message to receiver's saved register context
        msg.to_context(&mut tcb.context);
        // Badge goes in x6
        tcb.context.gpr[6] = badge;
        log::trace!("transfer_message: after x0={:#x}", tcb.context.gpr[0]);
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
