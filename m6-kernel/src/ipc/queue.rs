//! IPC wait queue operations.
//!
//! This module provides intrusive doubly-linked queue operations for
//! managing threads blocked on IPC operations. Uses the `ipc_next` and
//! `ipc_prev` fields in `TcbFull`.
//!
//! # Queue Invariants
//!
//! - Empty queue: `head.is_null() && tail.is_null()`
//! - Single element: `head == tail` and `head.ipc_next/prev.is_null()`
//! - FIFO ordering: dequeue returns head, enqueue adds at tail

use m6_cap::ObjectRef;

use crate::cap::object_table;

/// Enqueue a TCB at the tail of an IPC wait queue.
///
/// # Arguments
///
/// * `head` - Mutable reference to queue head pointer
/// * `tail` - Mutable reference to queue tail pointer
/// * `tcb_ref` - TCB to enqueue
///
/// # Panics
///
/// Panics if `tcb_ref` does not refer to a valid TCB.
pub fn ipc_enqueue(head: &mut ObjectRef, tail: &mut ObjectRef, tcb_ref: ObjectRef) {
    debug_assert!(tcb_ref.is_valid(), "cannot enqueue null TCB");

    let old_tail = *tail;

    // Set the new TCB's links: prev = old tail, next = null
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.ipc_prev = old_tail;
        tcb.ipc_next = ObjectRef::NULL;
    });

    if old_tail.is_valid() {
        // Link old tail to new entry
        let _: () = object_table::with_tcb_mut(old_tail, |old_tail_tcb| {
            old_tail_tcb.ipc_next = tcb_ref;
        });
    } else {
        // Queue was empty - new entry is also head
        *head = tcb_ref;
    }

    // New entry is always the new tail
    *tail = tcb_ref;
}

/// Dequeue a TCB from the head of an IPC wait queue.
///
/// Returns `None` if the queue is empty.
///
/// # Arguments
///
/// * `head` - Mutable reference to queue head pointer
/// * `tail` - Mutable reference to queue tail pointer
pub fn ipc_dequeue(head: &mut ObjectRef, tail: &mut ObjectRef) -> Option<ObjectRef> {
    if !head.is_valid() {
        return None;
    }

    let tcb_ref = *head;

    // Get the next element and clear the dequeued TCB's links
    let next: ObjectRef = object_table::with_tcb_mut(tcb_ref, |tcb| {
        let next = tcb.ipc_next;
        tcb.clear_ipc_links();
        next
    });

    // Update head to next element
    *head = next;

    if next.is_valid() {
        // Clear prev link of new head
        let _: () = object_table::with_tcb_mut(next, |new_head| {
            new_head.ipc_prev = ObjectRef::NULL;
        });
    } else {
        // Queue is now empty
        *tail = ObjectRef::NULL;
    }

    Some(tcb_ref)
}

/// Remove a specific TCB from an IPC wait queue.
///
/// This is used for cancellation or timeout handling when a thread
/// needs to be removed from the middle of a queue.
///
/// # Arguments
///
/// * `head` - Mutable reference to queue head pointer
/// * `tail` - Mutable reference to queue tail pointer
/// * `tcb_ref` - TCB to remove
///
/// # Note
///
/// The caller must ensure `tcb_ref` is actually in this queue.
pub fn ipc_remove(head: &mut ObjectRef, tail: &mut ObjectRef, tcb_ref: ObjectRef) {
    if !tcb_ref.is_valid() {
        return;
    }

    // Get the TCB's neighbours
    let (prev, next): (ObjectRef, ObjectRef) =
        object_table::with_tcb(tcb_ref, |tcb| (tcb.ipc_prev, tcb.ipc_next));

    // Update predecessor's next pointer
    if prev.is_valid() {
        let _: () = object_table::with_tcb_mut(prev, |prev_tcb| {
            prev_tcb.ipc_next = next;
        });
    } else {
        // We were the head
        *head = next;
    }

    // Update successor's prev pointer
    if next.is_valid() {
        let _: () = object_table::with_tcb_mut(next, |next_tcb| {
            next_tcb.ipc_prev = prev;
        });
    } else {
        // We were the tail
        *tail = prev;
    }

    // Clear the removed TCB's links
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.clear_ipc_links();
    });
}

/// Check if a queue is empty.
#[inline]
#[must_use]
pub fn is_empty(head: ObjectRef) -> bool {
    !head.is_valid()
}

/// Get the length of the queue.
///
/// Note: This is O(n) and should only be used for debugging.
#[must_use]
pub fn queue_len(head: ObjectRef) -> usize {
    let mut count = 0;
    let mut current = head;

    while current.is_valid() {
        count += 1;
        current = object_table::with_tcb(current, |tcb| tcb.ipc_next);
    }

    count
}
