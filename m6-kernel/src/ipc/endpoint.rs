//! Endpoint IPC operations.
//!
//! This module implements synchronous IPC via endpoints:
//! - Send/Recv: Basic blocking message transfer
//! - Call/ReplyRecv: RPC pattern with reply capabilities
//! - NBSend/NBRecv: Non-blocking variants

use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;

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

    let action = match object_table::ipc_dequeue_recv(ep_ref).ok_or(SyscallError::InvalidCap)? {
        object_table::IpcDequeueResult::Dequeued(receiver_ref) => Action::DeliverTo(receiver_ref),
        object_table::IpcDequeueResult::NoneQueued { old_tail } => {
            if !blocking {
                Action::WouldBlock
            } else {
                Action::BlockInSendQueue { old_tail }
            }
        }
    };

    // Execute action OUTSIDE the endpoint lock
    match action {
        Action::DeliverTo(receiver_ref) => {
            // Dequeue was performed atomically inside the initial endpoint lock.
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

            // Commit atomically — all queue manipulation happens within
            // one lock acquisition to prevent self-deadlock on SMP.
            let commit = object_table::ipc_send_commit(ep_ref, sender_ref, old_tail);

            if let Some(object_table::IpcSendCommitResult::Recovery(info)) = commit {
                // A receiver arrived concurrently. Deliver message directly.

                // Unblock sender (current thread).
                let _: () = object_table::with_tcb_mut(sender_ref, |tcb| {
                    tcb.tcb.state = ThreadState::Running;
                    tcb.ipc_blocked_on = ObjectRef::NULL;
                    tcb.clear_ipc_state();
                });
                crate::sched::insert_task(sender_ref);

                // Transfer capabilities if Grant right present.
                if let Err(e) = super::cap_transfer::transfer_capabilities(
                    sender_ref,
                    info.receiver_ref,
                    has_grant,
                ) {
                    log::debug!("Capability transfer failed during send recovery: {:?}", e);
                }

                // Transfer message and wake receiver.
                transfer_message(info.receiver_ref, msg, badge);
                wake_thread(info.receiver_ref);
            }

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

    let action = match object_table::ipc_dequeue_send(ep_ref).ok_or(SyscallError::InvalidCap)? {
        object_table::IpcDequeueResult::Dequeued(sender_ref) => Action::ReceiveFrom(sender_ref),
        object_table::IpcDequeueResult::NoneQueued { old_tail } => {
            if !blocking {
                Action::WouldBlock
            } else {
                Action::Block { old_tail }
            }
        }
    };

    // Now execute the action WITHOUT holding any locks
    match action {
        Action::ReceiveFrom(sender_ref) => {
            // Dequeue was performed atomically inside the initial endpoint lock.
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

            // Commit to the endpoint atomically. All queue manipulation and
            // sender TCB field reads happen within one lock acquisition to
            // prevent self-deadlock on SMP recovery paths.
            let commit = object_table::ipc_recv_commit(ep_ref, receiver_ref, old_tail)
                .ok_or(SyscallError::InvalidCap)?;

            match commit {
                object_table::IpcRecvCommitResult::Enqueued => Ok(None),
                object_table::IpcRecvCommitResult::Recovery(info) => {
                    // A sender arrived concurrently. Deliver its message
                    // through the return value so the syscall handler writes
                    // it to the kernel stack (not TCB.context which would be
                    // overwritten since we're the current thread).

                    // Unblock receiver (current thread).
                    let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                        tcb.tcb.state = ThreadState::Running;
                        tcb.ipc_blocked_on = ObjectRef::NULL;
                        tcb.clear_ipc_state();
                    });
                    crate::sched::insert_task(receiver_ref);

                    // Transfer capabilities if Grant right present.
                    if let Err(e) = super::cap_transfer::transfer_capabilities(
                        info.sender_ref,
                        receiver_ref,
                        has_grant,
                    ) {
                        log::debug!("Capability transfer failed during recv recovery: {:?}", e);
                    }

                    let msg = IpcMessage::from_regs(info.pending_msg);

                    if info.sender_reply_slot.is_valid() {
                        // Sender used Call: transfer reply cap, keep sender blocked.
                        let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
                            tcb.tcb.caller = info.sender_reply_slot;
                        });
                        let _: () = object_table::with_tcb_mut(info.sender_ref, |tcb| {
                            tcb.tcb.state = ThreadState::BlockedOnReply;
                            tcb.ipc_blocked_on = ObjectRef::NULL;
                            tcb.tcb.reply_slot = ObjectRef::NULL;
                            tcb.clear_ipc_state();
                        });
                    } else {
                        // Sender used Send: wake it.
                        wake_thread(info.sender_ref);
                    }

                    Ok(Some((info.badge, msg)))
                }
            }
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

    let action = match object_table::ipc_dequeue_recv(ep_ref).ok_or(SyscallError::InvalidCap)? {
        object_table::IpcDequeueResult::Dequeued(receiver_ref) => Action::DeliverTo(receiver_ref),
        object_table::IpcDequeueResult::NoneQueued { old_tail } => {
            Action::BlockInSendQueue { old_tail }
        }
    };

    // Execute action OUTSIDE the endpoint lock
    match action {
        Action::DeliverTo(receiver_ref) => {
            // Dequeue was performed atomically inside the initial endpoint lock.
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

            // Commit atomically — all queue manipulation happens within
            // one lock acquisition to prevent self-deadlock on SMP.
            let commit = object_table::ipc_send_commit(ep_ref, caller_ref, old_tail);

            if let Some(object_table::IpcSendCommitResult::Recovery(info)) = commit {
                // A receiver arrived concurrently. Deliver message directly.

                // Transfer capabilities if Grant right present.
                if let Err(e) = super::cap_transfer::transfer_capabilities(
                    caller_ref,
                    info.receiver_ref,
                    has_grant,
                ) {
                    log::debug!("Capability transfer failed during call recovery: {:?}", e);
                }

                // Grant reply capability to receiver.
                let _: () = object_table::with_tcb_mut(info.receiver_ref, |tcb| {
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
                transfer_message(info.receiver_ref, msg, badge);
                wake_thread(info.receiver_ref);
            }

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

/// Stage a message for delivery to a receiver.
///
/// Instead of writing directly to `TCB.context` (which races with
/// `save_context` on SMP), we write to the `ipc_message`/`ipc_badge`
/// staging fields and set `ipc_msg_pending`. The dispatcher applies
/// these to the exception frame in `restore_context`, which is
/// guaranteed to run after `save_context` has completed.
fn transfer_message(receiver_ref: ObjectRef, msg: &IpcMessage, badge: u64) {
    let _: () = object_table::with_tcb_mut(receiver_ref, |tcb| {
        log::trace!(
            "transfer_message: staging msg[0]={:#x}, badge={:#x} for {:?}",
            msg.regs[0],
            badge,
            receiver_ref
        );
        tcb.ipc_message = msg.regs;
        tcb.ipc_badge = badge;
        tcb.ipc_msg_pending = true;
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
///
/// Only clears blocking metadata and queue links — not `ipc_message`/
/// `ipc_badge`/`ipc_msg_pending`, because `transfer_message` may have
/// staged an incoming message that `restore_context` still needs to apply.
fn wake_thread(tcb_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::Running;
        tcb.ipc_blocked_on = ObjectRef::NULL;
        tcb.clear_ipc_links();
    });

    // Add to run queue
    crate::sched::insert_task(tcb_ref);
}
