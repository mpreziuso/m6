//! Notification IPC operations.
//!
//! This module implements asynchronous signalling via notifications:
//! - Signal: OR badge into signal word (never blocks)
//! - Wait: Block until signalled, return accumulated word
//! - Poll: Non-blocking check of signal word

use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;

use crate::cap::object_table;
use crate::syscall::error::SyscallError;

use super::queue::{ipc_dequeue, ipc_enqueue};

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
    object_table::with_notification_mut(notif_ref, |notif| {
        // OR badge into signal word
        notif.signal(badge);

        // If there's a waiter, wake them with the accumulated signals
        if notif.queue_head.is_valid() {
            let waiter_ref = ipc_dequeue(&mut notif.queue_head, &mut notif.queue_tail)
                .expect("queue_head valid but dequeue failed");

            // Get and clear signal word
            let signal_word = notif.poll();

            // Deliver signal word to waiter
            deliver_signal(waiter_ref, signal_word);

            // Wake waiter
            wake_thread(waiter_ref);
        }

        Ok(())
    })
    .ok_or(SyscallError::InvalidCap)?
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
    object_table::with_notification_mut(notif_ref, |notif| {
        if notif.has_signals() {
            // Signals pending - return immediately
            let word = notif.poll();
            Ok(Some(word))
        } else {
            // No signals - block waiting
            block_thread(waiter_ref, notif_ref);

            // Add to wait queue
            ipc_enqueue(&mut notif.queue_head, &mut notif.queue_tail, waiter_ref);

            Ok(None)
        }
    })
    .ok_or(SyscallError::InvalidCap)?
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

/// Deliver signal word to a waiting thread's saved context.
fn deliver_signal(tcb_ref: ObjectRef, signal_word: u64) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        // Signal word is returned in x0
        tcb.context.gpr[0] = signal_word;
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
