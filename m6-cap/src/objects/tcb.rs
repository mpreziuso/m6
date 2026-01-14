//! Thread Control Block capability
//!
//! A TCB (Thread Control Block) represents a thread of execution.
//! It contains the thread's register context, scheduling parameters,
//! and references to associated capabilities.
//!
//! # Associated Resources
//!
//! Each TCB references:
//! - **CSpace**: Root CNode for capability addressing
//! - **VSpace**: Virtual address space
//! - **IPC Buffer**: Shared memory for IPC message data
//! - **Fault Endpoint**: Where faults are delivered
//! - **Scheduling Context**: CPU time budget
//! - **Bound Notification**: For combined waiting

use m6_common::{PhysAddr, VirtAddr};

use crate::slot::ObjectRef;

/// Thread state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ThreadState {
    /// Not yet configured/started.
    #[default]
    Inactive = 0,
    /// Ready to run or currently running.
    Running = 1,
    /// Blocked waiting to send on an endpoint.
    BlockedOnSend = 2,
    /// Blocked waiting to receive from an endpoint.
    BlockedOnRecv = 3,
    /// Blocked waiting on a notification.
    BlockedOnNotification = 4,
    /// Blocked waiting for a reply.
    BlockedOnReply = 5,
    /// Explicitly suspended.
    Suspended = 6,
    /// Restarting after a fault.
    Restart = 7,
}

impl ThreadState {
    /// Check if the thread is runnable.
    #[inline]
    #[must_use]
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if the thread is blocked.
    #[inline]
    #[must_use]
    pub const fn is_blocked(self) -> bool {
        matches!(
            self,
            Self::BlockedOnSend
                | Self::BlockedOnRecv
                | Self::BlockedOnNotification
                | Self::BlockedOnReply
        )
    }

    /// Check if the thread can be scheduled.
    #[inline]
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Running | Self::Restart)
    }
}

/// Thread priority.
///
/// Higher values mean higher priority. Priority 0 is the lowest,
/// priority 255 is the highest.
pub type Priority = u8;

/// Maximum priority value.
pub const MAX_PRIORITY: Priority = 255;

/// Default priority for new threads.
pub const DEFAULT_PRIORITY: Priority = 128;

/// TCB object metadata.
///
/// Stored in the kernel's object table. The full TCB includes
/// register context which is stored separately.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TcbObject {
    /// Current thread state.
    pub state: ThreadState,
    /// Thread priority.
    pub priority: Priority,
    /// Maximum controlled priority (for priority inheritance).
    pub max_priority: Priority,
    /// Scheduling domain (for partitioning).
    pub domain: u8,
    /// Time slice remaining (in ticks).
    pub time_slice: u16,
    /// CSpace root capability.
    pub cspace_root: ObjectRef,
    /// VSpace (address space).
    pub vspace: ObjectRef,
    /// IPC buffer frame.
    pub ipc_buffer: ObjectRef,
    /// IPC buffer virtual address (for user-space access).
    pub ipc_buffer_addr: VirtAddr,
    /// IPC buffer physical address (for kernel access via direct map).
    pub ipc_buffer_phys: PhysAddr,
    /// Fault endpoint (receives fault messages).
    pub fault_endpoint: ObjectRef,
    /// Scheduling context (CPU time budget).
    pub sched_context: ObjectRef,
    /// Bound notification (for combined waiting).
    pub bound_notification: ObjectRef,
    /// Reply capability slot (for call operations).
    pub reply_slot: ObjectRef,
    /// Caller capability (who called us).
    pub caller: ObjectRef,
    /// CPU affinity (which CPU this thread runs on, -1 for any).
    pub affinity: i8,
    /// Exit code (set when thread exits via TcbExit).
    pub exit_code: i32,
    /// Thread name (for debugging).
    pub name: [u8; 16],
}

impl TcbObject {
    /// Create a new TCB object.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ThreadState::Inactive,
            priority: DEFAULT_PRIORITY,
            max_priority: MAX_PRIORITY,
            domain: 0,
            time_slice: 0,
            cspace_root: ObjectRef::NULL,
            vspace: ObjectRef::NULL,
            ipc_buffer: ObjectRef::NULL,
            ipc_buffer_addr: VirtAddr::new(0),
            ipc_buffer_phys: PhysAddr::new(0),
            fault_endpoint: ObjectRef::NULL,
            sched_context: ObjectRef::NULL,
            bound_notification: ObjectRef::NULL,
            reply_slot: ObjectRef::NULL,
            caller: ObjectRef::NULL,
            affinity: -1,
            exit_code: 0,
            name: [0; 16],
        }
    }

    /// Check if the thread is properly configured.
    #[inline]
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.cspace_root.is_valid() && self.vspace.is_valid()
    }

    /// Check if the thread has a fault endpoint.
    #[inline]
    #[must_use]
    pub const fn has_fault_endpoint(&self) -> bool {
        self.fault_endpoint.is_valid()
    }

    /// Check if the thread has a bound notification.
    #[inline]
    #[must_use]
    pub const fn has_bound_notification(&self) -> bool {
        self.bound_notification.is_valid()
    }

    /// Set the thread name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(self.name.len());
        self.name[..len].copy_from_slice(&name[..len]);
        if len < self.name.len() {
            self.name[len..].fill(0);
        }
    }
}

impl Default for TcbObject {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_state() {
        assert!(!ThreadState::Inactive.is_runnable());
        assert!(ThreadState::Running.is_runnable());
        assert!(ThreadState::BlockedOnSend.is_blocked());
    }

    #[test]
    fn test_tcb_creation() {
        let tcb = TcbObject::new();
        assert!(!tcb.is_configured());
        assert_eq!(tcb.state, ThreadState::Inactive);
        assert_eq!(tcb.priority, DEFAULT_PRIORITY);
    }
}
