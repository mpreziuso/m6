//! Endpoint IPC operations.
//!
//! This module implements synchronous IPC via endpoints:
//! - Send/Recv: Basic blocking message transfer
//! - Call/ReplyRecv: RPC pattern with reply capabilities
//! - NBSend/NBRecv: Non-blocking variants

use m6_cap::ObjectRef;
use m6_cap::objects::{EndpointState, ThreadState};

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
        BlockInSendQueue { old_tail: ObjectRef },
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
                    Action::BlockInSendQueue { old_tail: endpoint.queue_tail }
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
            if let Err(e) =
                super::cap_transfer::transfer_capabilities(sender_ref, receiver_ref, has_grant)
            {
                log::debug!("Capability transfer failed during send: {:?}", e);
            }

            // Transfer message to receiver
            transfer_message(receiver_ref, msg, badge);

            // Wake receiver
            wake_thread(receiver_ref);

            Ok(true)
        }

        Action::BlockInSendQueue { old_tail } => {
            // Store message and block sender before touching the queue.
            store_pending_message(sender_ref, msg, badge);
            block_thread(sender_ref, ep_ref, ThreadState::BlockedOnSend);

            // Set up sender's TCB queue links using old_tail captured atomically
            // with the state decision above.
            let _: () = object_table::with_tcb_mut(sender_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            if old_tail.is_valid() {
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = sender_ref;
                });
            }

            // Commit to the endpoint. An IRQ between the initial state read and here
            // could have changed the endpoint to RecvQueue. Handle both cases.
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                match endpoint.state {
                    EndpointState::Idle | EndpointState::SendQueue => {
                        // No concurrent receiver appeared — enqueue normally.
                        endpoint.state = EndpointState::SendQueue;
                        if old_tail.is_valid() {
                            endpoint.queue_tail = sender_ref;
                        } else {
                            endpoint.queue_head = sender_ref;
                            endpoint.queue_tail = sender_ref;
                        }
                    }
                    EndpointState::RecvQueue => {
                        // A receiver arrived while we were setting up TCB links.
                        // Clear the stale old_tail->ipc_next link we wrote above so
                        // old_tail is not left with a dangling pointer to a sender
                        // that is about to become Running.
                        if old_tail.is_valid() {
                            let _: () = object_table::with_tcb_mut(old_tail, |tcb| {
                                tcb.ipc_next = ObjectRef::NULL;
                            });
                        }
                        // Deliver the message directly to the receiver instead.
                        let receiver_ref = endpoint.queue_head;
                        if receiver_ref.is_valid() {
                            // Dequeue receiver
                            let next: ObjectRef = object_table::with_tcb_mut(receiver_ref, |tcb| {
                                let n = tcb.ipc_next;
                                tcb.clear_ipc_links();
                                n
                            });
                            endpoint.queue_head = next;
                            if !next.is_valid() {
                                endpoint.queue_tail = ObjectRef::NULL;
                                endpoint.state = EndpointState::Idle;
                            }
                            // Unblock sender immediately (message delivered)
                            object_table::with_tcb_mut(sender_ref, |tcb| {
                                tcb.tcb.state = ThreadState::Running;
                                tcb.ipc_blocked_on = ObjectRef::NULL;
                                tcb.clear_ipc_state();
                            });
                            crate::sched::insert_task(sender_ref);
                            // Transfer message and wake receiver
                            transfer_message(receiver_ref, msg, badge);
                            wake_thread(receiver_ref);
                        }
                    }
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
    // seL4 priority: check bound notification before endpoint.
    // If the TCB has a bound notification with pending signals, deliver
    // those immediately without touching the endpoint.
    let bound_notif = object_table::with_tcb(receiver_ref, |tcb| tcb.tcb.bound_notification);
    if bound_notif.is_valid() {
        let signal_word = object_table::with_notification_mut(bound_notif, |notif| {
            if notif.has_signals() {
                Some(notif.poll())
            } else {
                None
            }
        });
        if let Some(Some(word)) = signal_word {
            // Deliver as notification: badge = signal_word, label = 0 (empty message)
            return Ok(Some((word, IpcMessage::new())));
        }
    }

    // Determine action inside endpoint lock, execute outside
    enum Action {
        ReceiveFrom(ObjectRef),
        Block { old_tail: ObjectRef },
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
                    Action::Block { old_tail: endpoint.queue_tail }
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
            if let Err(e) =
                super::cap_transfer::transfer_capabilities(sender_ref, receiver_ref, has_grant)
            {
                log::debug!("Capability transfer failed during recv: {:?}", e);
            }

            // Get pending message from sender
            let (msg, badge) = get_pending_message(sender_ref);

            // Check if sender was a Call operation (has reply_slot set)
            let sender_reply_slot: ObjectRef =
                object_table::with_tcb(sender_ref, |tcb| tcb.tcb.reply_slot);

            if sender_reply_slot.is_valid() {
                // This was a Call - transfer reply capability to receiver and keep sender blocked
                log::trace!(
                    "do_recv: sender {:?} was Call, reply_slot={:?}, transferring to receiver {:?}",
                    sender_ref,
                    sender_reply_slot,
                    receiver_ref
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

        Action::Block { old_tail } => {
            block_thread(receiver_ref, ep_ref, ThreadState::BlockedOnRecv);

            // Set up receiver's TCB queue links using old_tail captured atomically
            // with the state decision above.
            let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            if old_tail.is_valid() {
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = receiver_ref;
                });
            }

            // Commit to the endpoint. An IRQ between the initial state read and here
            // could have changed the endpoint to SendQueue. Handle both cases.
            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                match endpoint.state {
                    EndpointState::Idle | EndpointState::RecvQueue => {
                        // No concurrent sender appeared — enqueue normally.
                        endpoint.state = EndpointState::RecvQueue;
                        if old_tail.is_valid() {
                            endpoint.queue_tail = receiver_ref;
                        } else {
                            endpoint.queue_head = receiver_ref;
                            endpoint.queue_tail = receiver_ref;
                        }
                    }
                    EndpointState::SendQueue => {
                        // A sender arrived concurrently. Deliver immediately.
                        let sender_ref = endpoint.queue_head;
                        if sender_ref.is_valid() {
                            let next: ObjectRef = object_table::with_tcb_mut(sender_ref, |tcb| {
                                let n = tcb.ipc_next;
                                tcb.clear_ipc_links();
                                n
                            });
                            endpoint.queue_head = next;
                            if !next.is_valid() {
                                endpoint.queue_tail = ObjectRef::NULL;
                                endpoint.state = EndpointState::Idle;
                            }
                            // Unblock receiver
                            object_table::with_tcb_mut(receiver_ref, |tcb| {
                                tcb.tcb.state = ThreadState::Running;
                                tcb.ipc_blocked_on = ObjectRef::NULL;
                                tcb.clear_ipc_state();
                            });
                            crate::sched::insert_task(receiver_ref);
                            // Transfer message from sender
                            let (pending_msg, badge) = get_pending_message(sender_ref);
                            transfer_message(receiver_ref, &pending_msg, badge);
                            wake_thread(sender_ref);
                        }
                    }
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
        BlockInSendQueue { old_tail: ObjectRef },
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
                Action::BlockInSendQueue { old_tail: endpoint.queue_tail }
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
            if let Err(e) =
                super::cap_transfer::transfer_capabilities(caller_ref, receiver_ref, has_grant)
            {
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

        Action::BlockInSendQueue { old_tail } => {
            store_pending_message(caller_ref, msg, badge);
            block_thread(caller_ref, ep_ref, ThreadState::BlockedOnSend);

            // Set up caller's TCB queue links using old_tail captured atomically
            // with the state decision above.
            let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
                tcb.ipc_prev = old_tail;
                tcb.ipc_next = ObjectRef::NULL;
            });

            if old_tail.is_valid() {
                let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
                    old_tail_tcb.ipc_next = caller_ref;
                });
            }

            object_table::with_endpoint_mut(ep_ref, |endpoint| {
                match endpoint.state {
                    EndpointState::Idle | EndpointState::SendQueue => {
                        // No concurrent receiver — enqueue normally.
                        endpoint.state = EndpointState::SendQueue;
                        if old_tail.is_valid() {
                            endpoint.queue_tail = caller_ref;
                        } else {
                            endpoint.queue_head = caller_ref;
                            endpoint.queue_tail = caller_ref;
                        }
                    }
                    EndpointState::RecvQueue => {
                        // A receiver arrived concurrently. Clear the stale
                        // old_tail->ipc_next link before proceeding.
                        if old_tail.is_valid() {
                            let _: () = object_table::with_tcb_mut(old_tail, |tcb| {
                                tcb.ipc_next = ObjectRef::NULL;
                            });
                        }
                        let receiver_ref = endpoint.queue_head;
                        if receiver_ref.is_valid() {
                            let next: ObjectRef = object_table::with_tcb_mut(receiver_ref, |tcb| {
                                let n = tcb.ipc_next;
                                tcb.clear_ipc_links();
                                n
                            });
                            endpoint.queue_head = next;
                            if !next.is_valid() {
                                endpoint.queue_tail = ObjectRef::NULL;
                                endpoint.state = EndpointState::Idle;
                            }
                            // Grant reply capability to receiver.
                            let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                                tcb.tcb.caller = reply_ref;
                            });
                            // Transition caller from BlockedOnSend to BlockedOnReply.
                            let _: () = object_table::with_tcb_mut(caller_ref, |tcb| {
                                tcb.tcb.state = ThreadState::BlockedOnReply;
                                tcb.ipc_blocked_on = ObjectRef::NULL;
                                tcb.tcb.reply_slot = ObjectRef::NULL;
                                tcb.clear_ipc_state();
                            });
                            // Transfer message and wake receiver.
                            transfer_message(receiver_ref, msg, badge);
                            wake_thread(receiver_ref);
                        }
                    }
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
        server_ref,
        reply_ref,
        reply_msg.regs[0]
    );

    if reply_ref.is_valid() {
        do_reply_internal(server_ref, reply_ref, reply_msg, has_grant)?;

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
fn do_reply_internal(
    server_ref: ObjectRef,
    reply_ref: ObjectRef,
    msg: &IpcMessage,
    has_grant: bool,
) -> Result<(), SyscallError> {
    log::trace!(
        "do_reply_internal: reply_ref={:?}, msg[0]={:#x}",
        reply_ref,
        msg.regs[0]
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

    // Transfer capabilities from server to caller if Grant right present
    if let Err(e) = super::cap_transfer::transfer_capabilities(server_ref, caller_ref, has_grant) {
        log::debug!("Capability transfer failed during reply: {:?}", e);
    }

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

    let reply_ref = object_table::alloc(KernelObjectType::Reply).ok_or(SyscallError::NoMemory)?;

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
            tcb.context.gpr[0],
            msg.regs[0]
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
