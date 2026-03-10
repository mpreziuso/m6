//! Notification IPC operations.
//!
//! This module implements asynchronous signalling via notifications:
//! - Signal: OR badge into signal word (never blocks)
//! - Wait: Block until signalled, return accumulated word
//! - Poll: Non-blocking check of signal word

use m6_cap::ObjectRef;
use m6_cap::objects::{EndpointState, ThreadState};

use crate::cap::object_table;
use crate::syscall::error::SyscallError;

/// Signal a notification object.
///
/// The badge is OR'd into the notification's signal word. If a thread is
/// waiting on the notification, it is woken and receives the accumulated
/// signal word.
///
/// This operation never blocks.
///
/// # Arguments
///
/// * `notif_ref` - Notification object reference
/// * `badge` - Badge to OR into signal word
///
/// # Returns
///
/// * `Ok(())` - Signal delivered
/// * `Err(InvalidCap)` - Invalid notification reference
pub fn do_signal(notif_ref: ObjectRef, badge: u64) -> Result<(), SyscallError> {
    // IMPORTANT: The object table uses a single global IrqSpinMutex.
    // All with_* calls acquire the SAME lock. Nesting them deadlocks.
    // We use separate lock acquisitions for notification, TCB, and endpoint.

    enum Action {
        None,
        MaybeWakeBound(ObjectRef),
        WakeWaiter(ObjectRef),
    }

    // Phase 1: Signal and determine potential wake target.
    // Only access notification state — do NOT touch TCBs here.
    let action = object_table::with_notification_mut(notif_ref, |notif| {
        notif.signal(badge);

        // Priority 1: bound TCB (check TCB state outside the lock)
        if notif.bound_tcb.is_valid() {
            return Action::MaybeWakeBound(notif.bound_tcb);
        }

        // Priority 2: waiter in queue (dequeue outside the lock)
        if notif.queue_head.is_valid() {
            return Action::WakeWaiter(notif.queue_head);
        }

        Action::None
    })
    .ok_or(SyscallError::InvalidCap)?;

    // Phase 2+: Execute action with separate lock acquisitions.
    match action {
        Action::None => {}

        Action::MaybeWakeBound(tcb_ref) => {
            // Check TCB state (separate lock acquisition from notification)
            let (tcb_state, ep_ref) =
                object_table::with_tcb(tcb_ref, |tcb| (tcb.tcb.state, tcb.ipc_blocked_on));

            if tcb_state == ThreadState::BlockedOnRecv {
                // Consume accumulated signals (re-acquire notification lock)
                let signal_word =
                    object_table::with_notification_mut(notif_ref, |notif| notif.poll())
                        .unwrap_or(0);

                // Dequeue from endpoint's recv queue.
                // Inline ipc_remove: each step is a separate lock acquisition
                // to avoid nesting TCB locks inside endpoint lock.
                if ep_ref.is_valid() {
                    let (prev, next) =
                        object_table::with_tcb(tcb_ref, |tcb| (tcb.ipc_prev, tcb.ipc_next));

                    if prev.is_valid() {
                        let _: () = object_table::with_tcb_mut(prev, |p| {
                            p.ipc_next = next;
                        });
                    }
                    if next.is_valid() {
                        let _: () = object_table::with_tcb_mut(next, |n| {
                            n.ipc_prev = prev;
                        });
                    }

                    object_table::with_endpoint_mut(ep_ref, |endpoint| {
                        if !prev.is_valid() {
                            endpoint.queue_head = next;
                        }
                        if !next.is_valid() {
                            endpoint.queue_tail = prev;
                        }
                        if !endpoint.queue_head.is_valid() {
                            endpoint.state = EndpointState::Idle;
                        }
                    });

                    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
                        tcb.clear_ipc_links();
                    });
                }

                deliver_notification_to_recv(tcb_ref, signal_word);
                wake_thread(tcb_ref);
            }
            // If not BlockedOnRecv, signals remain accumulated.
            // do_recv will find them on the next recv call.
        }

        Action::WakeWaiter(waiter_ref) => {
            // Manual dequeue: get next from TCB (TCB lock, not notification lock)
            let next_in_queue = object_table::with_tcb_mut(waiter_ref, |tcb| {
                let next = tcb.ipc_next;
                tcb.clear_ipc_links();
                next
            });

            // Update notification queue and consume signals (notification lock)
            let signal_word = object_table::with_notification_mut(notif_ref, |notif| {
                notif.queue_head = next_in_queue;
                if !next_in_queue.is_valid() {
                    notif.queue_tail = ObjectRef::NULL;
                }
                notif.poll()
            })
            .unwrap_or(0);

            // Clear prev link of new queue head (TCB lock)
            if next_in_queue.is_valid() {
                let _: () = object_table::with_tcb_mut(next_in_queue, |new_head| {
                    new_head.ipc_prev = ObjectRef::NULL;
                });
            }

            deliver_signal(waiter_ref, signal_word);
            wake_thread(waiter_ref);
        }
    }

    Ok(())
}

/// Wait on a notification.
///
/// If signals are pending (signal word non-zero), returns immediately with
/// the accumulated signal word. Otherwise, blocks until signalled.
///
/// # Arguments
///
/// * `waiter_ref` - TCB reference of waiting thread
/// * `notif_ref` - Notification object reference
///
/// # Returns
///
/// * `Ok(Some(word))` - Signals received immediately
/// * `Ok(None)` - Thread blocked, will be woken when signalled
/// * `Err(InvalidCap)` - Invalid notification reference
pub fn do_wait(waiter_ref: ObjectRef, notif_ref: ObjectRef) -> Result<Option<u64>, SyscallError> {
    // IMPORTANT: The object table uses a single global IrqSpinMutex.
    // block_thread and ipc_enqueue call with_tcb_mut, so they MUST NOT
    // be called inside with_notification_mut — that would deadlock.
    // We split into separate lock acquisitions.

    // Phase 1: Check for pending signals (notification lock only).
    let poll_result = object_table::with_notification_mut(notif_ref, |notif| {
        if notif.has_signals() {
            Some(notif.poll())
        } else {
            None
        }
    })
    .ok_or(SyscallError::InvalidCap)?;

    if let Some(word) = poll_result {
        return Ok(Some(word));
    }

    // Phase 2: No signals — block the thread (TCB lock, separate).
    block_thread(waiter_ref, notif_ref);

    // Phase 3: Enqueue in notification wait queue.
    // Inline ipc_enqueue to keep each lock acquisition separate.
    let old_tail = object_table::with_notification_mut(notif_ref, |notif| notif.queue_tail)
        .unwrap_or(ObjectRef::NULL);

    let _: () = object_table::with_tcb_mut(waiter_ref, |tcb| {
        tcb.ipc_prev = old_tail;
        tcb.ipc_next = ObjectRef::NULL;
    });

    if old_tail.is_valid() {
        let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
            old_tail_tcb.ipc_next = waiter_ref;
        });
    }

    object_table::with_notification_mut(notif_ref, |notif| {
        if !old_tail.is_valid() {
            notif.queue_head = waiter_ref;
        }
        notif.queue_tail = waiter_ref;
    });

    Ok(None)
}

/// Poll a notification (non-blocking).
///
/// Returns the current signal word and clears it. If no signals are
/// pending, returns 0 without blocking.
///
/// # Arguments
///
/// * `notif_ref` - Notification object reference
///
/// # Returns
///
/// * `Ok(word)` - Signal word (0 if no signals)
/// * `Err(InvalidCap)` - Invalid notification reference
pub fn do_poll(notif_ref: ObjectRef) -> Result<u64, SyscallError> {
    object_table::with_notification_mut(notif_ref, |notif| notif.poll())
        .ok_or(SyscallError::InvalidCap)
}

/// Deliver signal word to a thread waiting directly on a notification.
///
/// For direct `wait`, the signal word is returned in x0.
fn deliver_signal(tcb_ref: ObjectRef, signal_word: u64) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.context.gpr[0] = signal_word;
    });
}

/// Deliver notification signal to a bound TCB woken from endpoint recv.
///
/// Uses the recv return convention: label=0 in x0, badge=signal_word in x6,
/// empty message in x1-x4. This matches what `do_recv` returns when it finds
/// pending signals on the bound notification (the synchronous path).
fn deliver_notification_to_recv(tcb_ref: ObjectRef, signal_word: u64) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.context.gpr[0] = 0; // label = 0 (notification)
        tcb.context.gpr[1] = 0; // msg[0] = empty
        tcb.context.gpr[2] = 0; // msg[1] = empty
        tcb.context.gpr[3] = 0; // msg[2] = empty
        tcb.context.gpr[4] = 0; // msg[3] = empty
        tcb.context.gpr[6] = signal_word; // badge = signal word
    });
}

/// Block a thread waiting on a notification.
fn block_thread(tcb_ref: ObjectRef, notif_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::BlockedOnNotification;
        tcb.ipc_blocked_on = notif_ref;
    });

    // Remove from run queue
    crate::sched::remove_task(tcb_ref);
}

/// Wake a thread blocked on a notification.
fn wake_thread(tcb_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::Running;
        tcb.ipc_blocked_on = ObjectRef::NULL;
        tcb.clear_ipc_state();
    });

    // Add to run queue
    crate::sched::insert_task(tcb_ref);
}
