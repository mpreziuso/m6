//! Endpoint capability - synchronous IPC
//!
//! An endpoint is a synchronous IPC destination. Threads can send messages
//! to and receive messages from endpoints. Endpoints support badging for
//! sender identification.
//!
//! # IPC Model
//!
//! - **Send**: Block until a receiver is ready, transfer message
//! - **Receive**: Block until a sender is ready, receive message
//! - **Call**: Send + wait for reply (creates one-time reply capability)
//! - **ReplyRecv**: Reply to previous call + wait for next
//!
//! # Badging
//!
//! When a capability to an endpoint is minted with a badge, that badge
//! is delivered to the receiver along with the message. This allows
//! servers to identify clients without needing separate authentication.
//!
//! # Thread Queues
//!
//! Endpoints maintain queues of blocked threads:
//! - If threads are waiting to receive, senders block until one receives
//! - If threads are waiting to send, receivers block until one sends
//! - The endpoint is never in both states simultaneously

use crate::slot::ObjectRef;

/// Endpoint state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EndpointState {
    /// No threads waiting (idle endpoint).
    #[default]
    Idle = 0,
    /// Threads waiting to send (sender queue non-empty).
    SendQueue = 1,
    /// Threads waiting to receive (receiver queue non-empty).
    RecvQueue = 2,
}

/// Endpoint object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct EndpointObject {
    /// Current state.
    pub state: EndpointState,
    /// Head of waiting thread queue (TCB reference).
    pub queue_head: ObjectRef,
    /// Tail of waiting thread queue.
    pub queue_tail: ObjectRef,
}

impl EndpointObject {
    /// Create a new endpoint.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            queue_head: ObjectRef::NULL,
            queue_tail: ObjectRef::NULL,
        }
    }

    /// Check if the endpoint is idle (no waiting threads).
    #[inline]
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, EndpointState::Idle)
    }

    /// Check if threads are waiting to send.
    #[inline]
    #[must_use]
    pub const fn has_senders(&self) -> bool {
        matches!(self.state, EndpointState::SendQueue)
    }

    /// Check if threads are waiting to receive.
    #[inline]
    #[must_use]
    pub const fn has_receivers(&self) -> bool {
        matches!(self.state, EndpointState::RecvQueue)
    }

    /// Check if the queue is empty.
    #[inline]
    #[must_use]
    pub const fn is_queue_empty(&self) -> bool {
        self.queue_head.is_null()
    }
}

/// Notification state.
///
/// A notification is an asynchronous signalling mechanism. It contains
/// a single word that is OR'd with incoming signals. Threads can wait
/// on notifications or poll them.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct NotificationObject {
    /// Accumulated signal word.
    pub signal_word: u64,
    /// Head of waiting thread queue.
    pub queue_head: ObjectRef,
    /// Tail of waiting thread queue.
    pub queue_tail: ObjectRef,
    /// Bound TCB (for combined IPC + notification waiting).
    pub bound_tcb: ObjectRef,
}

impl NotificationObject {
    /// Create a new notification.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            signal_word: 0,
            queue_head: ObjectRef::NULL,
            queue_tail: ObjectRef::NULL,
            bound_tcb: ObjectRef::NULL,
        }
    }

    /// Signal the notification with a badge.
    ///
    /// The badge is OR'd into the signal word.
    #[inline]
    pub fn signal(&mut self, badge: u64) {
        self.signal_word |= badge;
    }

    /// Poll the notification (non-blocking).
    ///
    /// Returns the signal word and clears it.
    #[inline]
    pub fn poll(&mut self) -> u64 {
        let word = self.signal_word;
        self.signal_word = 0;
        word
    }

    /// Check if any signals are pending.
    #[inline]
    #[must_use]
    pub const fn has_signals(&self) -> bool {
        self.signal_word != 0
    }

    /// Check if a TCB is bound.
    #[inline]
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.bound_tcb.is_valid()
    }
}

/// Reply object.
///
/// A reply capability is a one-time capability created during a Call
/// operation. It allows the server to reply to the client.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct ReplyObject {
    /// The TCB waiting for the reply.
    pub caller: ObjectRef,
    /// Whether this reply has been used.
    pub used: bool,
}

impl ReplyObject {
    /// Create a new reply object.
    #[inline]
    #[must_use]
    pub const fn new(caller: ObjectRef) -> Self {
        Self {
            caller,
            used: false,
        }
    }

    /// Check if the reply has been used.
    #[inline]
    #[must_use]
    pub const fn is_used(&self) -> bool {
        self.used
    }

    /// Mark the reply as used.
    #[inline]
    pub fn mark_used(&mut self) {
        self.used = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_idle() {
        let ep = EndpointObject::new();
        assert!(ep.is_idle());
        assert!(ep.is_queue_empty());
        assert!(!ep.has_senders());
        assert!(!ep.has_receivers());
    }

    #[test]
    fn test_notification_signal() {
        let mut notif = NotificationObject::new();
        assert!(!notif.has_signals());

        notif.signal(0x01);
        notif.signal(0x10);
        assert!(notif.has_signals());
        assert_eq!(notif.signal_word, 0x11);

        let word = notif.poll();
        assert_eq!(word, 0x11);
        assert!(!notif.has_signals());
    }
}
