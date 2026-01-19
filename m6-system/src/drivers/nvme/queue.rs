//! NVMe Queue Management
//!
//! Manages NVMe submission and completion queues, command tracking,
//! and doorbell operations.

#![allow(dead_code)]

use super::command::{NvmeCommand, NvmeCompletion};
use super::controller::NvmeController;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

/// Status field offset in NvmeCompletion (byte offset of `status` field)
const COMPLETION_STATUS_OFFSET: usize = 14;

/// Phase bit position in status field (bit 0)
const PHASE_BIT_OFFSET: usize = 0;

/// NVMe Submission Queue
pub struct NvmeSq {
    /// Virtual address of queue memory
    entries: *mut NvmeCommand,
    /// IOVA for device configuration
    iova: u64,
    /// Queue depth
    depth: u16,
    /// Queue ID
    qid: u16,
    /// Current tail index
    tail: u16,
    /// Next command ID to use
    next_cid: u16,
}

impl NvmeSq {
    /// Calculate memory size required for the queue.
    #[inline]
    #[must_use]
    pub const fn memory_size(depth: u16) -> usize {
        (depth as usize) * core::mem::size_of::<NvmeCommand>()
    }

    /// Create a new submission queue.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `vaddr` points to valid, zeroed DMA memory
    /// - The memory is at least `memory_size(depth)` bytes
    /// - The memory is mapped in IOSpace at `iova`
    #[inline]
    pub unsafe fn new(vaddr: *mut NvmeCommand, iova: u64, depth: u16, qid: u16) -> Self {
        Self {
            entries: vaddr,
            iova,
            depth,
            qid,
            tail: 0,
            next_cid: 0,
        }
    }

    /// Get the queue ID.
    #[inline]
    #[must_use]
    pub const fn qid(&self) -> u16 {
        self.qid
    }

    /// Get the IOVA for device configuration.
    #[inline]
    #[must_use]
    pub const fn iova(&self) -> u64 {
        self.iova
    }

    /// Get the queue depth.
    #[inline]
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Allocate a command ID.
    fn alloc_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid = (self.next_cid + 1) % self.depth;
        cid
    }

    /// Submit a command to the queue.
    ///
    /// Returns the command ID if successful.
    pub fn submit(&mut self, mut cmd: NvmeCommand) -> Option<u16> {
        let slot = self.tail;
        let cid = self.alloc_cid();

        // Update command ID in CDW0
        cmd.cdw0 = (cmd.cdw0 & 0xFFFF) | ((cid as u32) << 16);

        // Write command to queue
        // SAFETY: entries is valid, slot is within bounds
        unsafe {
            write_volatile(self.entries.add(slot as usize), cmd);
        }

        // Memory barrier before doorbell
        fence(Ordering::Release);

        // Advance tail
        self.tail = (self.tail + 1) % self.depth;

        Some(cid)
    }

    /// Get the current tail value for doorbell.
    #[inline]
    #[must_use]
    pub const fn tail(&self) -> u16 {
        self.tail
    }

    /// Ring the doorbell for this queue.
    #[inline]
    pub fn ring_doorbell(&self, ctrl: &NvmeController) {
        ctrl.ring_sq_doorbell(self.qid, self.tail);
    }
}

// SAFETY: NvmeSq can be sent if the underlying memory is valid
unsafe impl Send for NvmeSq {}

/// NVMe Completion Queue
pub struct NvmeCq {
    /// Virtual address of queue memory
    entries: *const NvmeCompletion,
    /// IOVA for device configuration
    iova: u64,
    /// Queue depth
    depth: u16,
    /// Queue ID
    qid: u16,
    /// Current head index
    head: u16,
    /// Current expected phase bit
    phase: bool,
}

impl NvmeCq {
    /// Calculate memory size required for the queue.
    #[inline]
    #[must_use]
    pub const fn memory_size(depth: u16) -> usize {
        (depth as usize) * core::mem::size_of::<NvmeCompletion>()
    }

    /// Create a new completion queue.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `vaddr` points to valid, zeroed DMA memory
    /// - The memory is at least `memory_size(depth)` bytes
    /// - The memory is mapped in IOSpace at `iova`
    #[inline]
    pub unsafe fn new(vaddr: *const NvmeCompletion, iova: u64, depth: u16, qid: u16) -> Self {
        Self {
            entries: vaddr,
            iova,
            depth,
            qid,
            head: 0,
            phase: true, // Initial phase is 1
        }
    }

    /// Get the queue ID.
    #[inline]
    #[must_use]
    pub const fn qid(&self) -> u16 {
        self.qid
    }

    /// Get the IOVA for device configuration.
    #[inline]
    #[must_use]
    pub const fn iova(&self) -> u64 {
        self.iova
    }

    /// Get the queue depth.
    #[inline]
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Check if there's a valid completion to process.
    #[must_use]
    pub fn has_completion(&self) -> bool {
        fence(Ordering::Acquire);

        // SAFETY: entries is valid, head is within bounds
        let entry = unsafe { read_volatile(self.entries.add(self.head as usize)) };

        // Check phase bit matches expected
        entry.phase() == self.phase
    }

    /// Pop the next completion entry.
    pub fn pop(&mut self) -> Option<NvmeCompletion> {
        if !self.has_completion() {
            return None;
        }

        // SAFETY: entries is valid, head is within bounds
        let entry = unsafe { read_volatile(self.entries.add(self.head as usize)) };

        // Advance head
        self.head = (self.head + 1) % self.depth;

        // Toggle phase on wrap-around
        if self.head == 0 {
            self.phase = !self.phase;
        }

        Some(entry)
    }

    /// Get the current head value for doorbell.
    #[inline]
    #[must_use]
    pub const fn head(&self) -> u16 {
        self.head
    }

    /// Ring the doorbell for this queue.
    #[inline]
    pub fn ring_doorbell(&self, ctrl: &NvmeController) {
        ctrl.ring_cq_doorbell(self.qid, self.head);
    }
}

// SAFETY: NvmeCq can be sent if the underlying memory is valid
unsafe impl Send for NvmeCq {}

/// NVMe Queue Pair (SQ + CQ)
pub struct NvmeQueuePair {
    /// Submission queue
    pub sq: NvmeSq,
    /// Completion queue
    pub cq: NvmeCq,
    /// Interrupt vector for this queue pair
    pub vector: u16,
}

impl NvmeQueuePair {
    /// Create a new queue pair.
    ///
    /// # Safety
    ///
    /// See safety requirements for `NvmeSq::new` and `NvmeCq::new`.
    pub unsafe fn new(sq: NvmeSq, cq: NvmeCq, vector: u16) -> Self {
        Self { sq, cq, vector }
    }

    /// Submit a command and ring the doorbell.
    pub fn submit(&mut self, cmd: NvmeCommand, ctrl: &NvmeController) -> Option<u16> {
        let cid = self.sq.submit(cmd)?;
        self.sq.ring_doorbell(ctrl);
        Some(cid)
    }

    /// Poll for and process completions.
    ///
    /// Returns the completion if one is available.
    pub fn poll_completion(&mut self, ctrl: &NvmeController) -> Option<NvmeCompletion> {
        let cqe = self.cq.pop()?;
        self.cq.ring_doorbell(ctrl);
        Some(cqe)
    }
}

/// Command tracker for managing in-flight commands.
///
/// Tracks which command IDs are in use and their associated context.
pub struct CommandTracker<T, const N: usize> {
    /// Slot data (context associated with each command)
    slots: [Option<T>; N],
    /// Number of slots in use
    in_flight: usize,
}

impl<T: Copy, const N: usize> CommandTracker<T, N> {
    /// Create a new command tracker.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            in_flight: 0,
        }
    }

    /// Check if a slot is available.
    #[inline]
    #[must_use]
    pub fn is_slot_free(&self, cid: u16) -> bool {
        (cid as usize) < N && self.slots[cid as usize].is_none()
    }

    /// Allocate a slot for a command.
    ///
    /// Returns `true` if successful, `false` if the slot is already in use.
    pub fn allocate(&mut self, cid: u16, context: T) -> bool {
        let idx = cid as usize;
        if idx >= N || self.slots[idx].is_some() {
            return false;
        }
        self.slots[idx] = Some(context);
        self.in_flight += 1;
        true
    }

    /// Complete a command and return its context.
    pub fn complete(&mut self, cid: u16) -> Option<T> {
        let idx = cid as usize;
        if idx >= N {
            return None;
        }
        let context = self.slots[idx].take();
        if context.is_some() {
            self.in_flight -= 1;
        }
        context
    }

    /// Get the context for a command without completing it.
    #[inline]
    #[must_use]
    pub fn get(&self, cid: u16) -> Option<&T> {
        let idx = cid as usize;
        if idx >= N {
            return None;
        }
        self.slots[idx].as_ref()
    }

    /// Get the number of commands in flight.
    #[inline]
    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Check if there are no commands in flight.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.in_flight == 0
    }
}

impl<T: Copy, const N: usize> Default for CommandTracker<T, N> {
    fn default() -> Self {
        Self::new()
    }
}
