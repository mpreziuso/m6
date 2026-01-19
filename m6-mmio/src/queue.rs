//! Generic Submission/Completion Queue Engine
//!
//! Provides reusable queue structures for NVMe-style command submission and
//! completion with phase bit handling. This can be used for any protocol that
//! uses similar producer-consumer ring structures.
//!
//! # Queue Model
//!
//! ## Submission Queue (SQ)
//!
//! - Driver (producer) writes entries and updates tail
//! - Device (consumer) reads entries and updates head
//! - Driver tracks head from completion status
//!
//! ## Completion Queue (CQ)
//!
//! - Device (producer) writes entries with phase bit
//! - Driver (consumer) reads entries and updates head via doorbell
//! - Phase bit indicates valid entries (toggles each wrap-around)
//!
//! # Memory Requirements
//!
//! Queue memory must be:
//! - Physically contiguous (for DMA)
//! - Aligned to entry size
//! - Mapped in IOSpace with appropriate IOVA

use crate::barrier::{read_barrier, write_barrier};
use core::ptr::{read_volatile, write_volatile};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Trait for queue entries that can be safely used in DMA.
///
/// Entries must be POD (Plain Old Data) types that can be safely:
/// - Copied to/from DMA buffers
/// - Interpreted as raw bytes
pub trait QueueEntry:
    Copy + Default + Sized + FromBytes + IntoBytes + Immutable + KnownLayout
{
    /// Size of this entry type in bytes.
    const SIZE: usize = core::mem::size_of::<Self>();
}

// Blanket implementation for any type meeting the requirements
impl<T> QueueEntry for T where
    T: Copy + Default + Sized + FromBytes + IntoBytes + Immutable + KnownLayout
{
}

/// Submission Queue for sending commands to a device.
///
/// The driver writes entries to the queue and rings the doorbell to notify
/// the device. The device updates the head pointer to indicate which entries
/// it has consumed.
pub struct SubmissionQueue<E: QueueEntry> {
    /// Pointer to the entry array in DMA memory
    entries: *mut E,
    /// IOVA of the queue (for device configuration)
    iova: u64,
    /// Number of entries in the queue
    depth: u16,
    /// Current tail index (next entry to write)
    tail: u16,
    /// Last known head index (from completions)
    head: u16,
}

impl<E: QueueEntry> SubmissionQueue<E> {
    /// Calculate the memory size required for this queue.
    #[inline]
    #[must_use]
    pub const fn memory_size(depth: u16) -> usize {
        (depth as usize) * E::SIZE
    }

    /// Create a new submission queue.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `vaddr` points to valid, zeroed DMA memory
    /// - The memory is at least `memory_size(depth)` bytes
    /// - The memory is mapped in IOSpace at `iova`
    /// - The memory remains valid for the lifetime of this queue
    #[inline]
    pub unsafe fn new(vaddr: *mut E, iova: u64, depth: u16) -> Self {
        Self {
            entries: vaddr,
            iova,
            depth,
            tail: 0,
            head: 0,
        }
    }

    /// Get the IOVA of this queue for device configuration.
    #[inline]
    #[must_use]
    pub const fn iova(&self) -> u64 {
        self.iova
    }

    /// Get the depth (number of entries) of this queue.
    #[inline]
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Check if the queue is full.
    ///
    /// The queue is full when incrementing tail would make it equal to head.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        let next_tail = (self.tail + 1) % self.depth;
        next_tail == self.head
    }

    /// Check if the queue is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tail == self.head
    }

    /// Get the number of free slots in the queue.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> u16 {
        if self.tail >= self.head {
            self.depth - 1 - (self.tail - self.head)
        } else {
            self.head - self.tail - 1
        }
    }

    /// Submit an entry to the queue.
    ///
    /// Returns the slot index if successful, `None` if the queue is full.
    /// The caller must ring the doorbell after submitting to notify the device.
    pub fn submit(&mut self, entry: E) -> Option<u16> {
        if self.is_full() {
            return None;
        }

        let slot = self.tail;

        // Write the entry to the queue
        // SAFETY: entries pointer is valid, slot is within bounds
        unsafe {
            write_volatile(self.entries.add(slot as usize), entry);
        }

        // Memory barrier before updating tail
        write_barrier();

        // Update tail (wraps around)
        self.tail = (self.tail + 1) % self.depth;

        Some(slot)
    }

    /// Get the doorbell value to write after submitting entries.
    ///
    /// This is the new tail index that should be written to the doorbell
    /// register to notify the device of new entries.
    #[inline]
    #[must_use]
    pub const fn doorbell_value(&self) -> u16 {
        self.tail
    }

    /// Update the head pointer from completion information.
    ///
    /// This should be called when processing completions to free up
    /// slots in the submission queue.
    #[inline]
    pub fn update_head(&mut self, head: u16) {
        debug_assert!(head < self.depth, "Head index out of bounds");
        self.head = head;
    }

    /// Get a reference to an entry by slot index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the slot is valid and the entry has been written.
    #[inline]
    pub unsafe fn get_entry(&self, slot: u16) -> &E {
        debug_assert!(slot < self.depth, "Slot index out of bounds");
        // SAFETY: Caller guarantees slot is valid
        unsafe { &*self.entries.add(slot as usize) }
    }

    /// Get a mutable reference to an entry by slot index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the slot is valid and no concurrent access occurs.
    #[inline]
    pub unsafe fn get_entry_mut(&mut self, slot: u16) -> &mut E {
        debug_assert!(slot < self.depth, "Slot index out of bounds");
        // SAFETY: Caller guarantees slot is valid and exclusive access
        unsafe { &mut *self.entries.add(slot as usize) }
    }
}

// SAFETY: SubmissionQueue can be sent between threads if entries memory is valid
unsafe impl<E: QueueEntry + Send> Send for SubmissionQueue<E> {}

/// Completion Queue for receiving status from a device.
///
/// The device writes completion entries with a phase bit to indicate validity.
/// The driver polls for new completions and updates the head via doorbell.
pub struct CompletionQueue<E: QueueEntry> {
    /// Pointer to the entry array in DMA memory
    entries: *const E,
    /// IOVA of the queue (for device configuration)
    iova: u64,
    /// Number of entries in the queue
    depth: u16,
    /// Current head index (next entry to read)
    head: u16,
    /// Current expected phase bit value
    phase: bool,
    /// Offset of the phase bit within the status field (bit position)
    phase_bit_offset: usize,
    /// Size of the status field in bytes (typically 2 for NVMe)
    status_field_offset: usize,
}

impl<E: QueueEntry> CompletionQueue<E> {
    /// Calculate the memory size required for this queue.
    #[inline]
    #[must_use]
    pub const fn memory_size(depth: u16) -> usize {
        (depth as usize) * E::SIZE
    }

    /// Create a new completion queue.
    ///
    /// # Arguments
    ///
    /// - `vaddr`: Pointer to queue memory (must be zeroed)
    /// - `iova`: IOVA of the queue for device configuration
    /// - `depth`: Number of entries in the queue
    /// - `status_field_offset`: Byte offset of the status field in the entry
    /// - `phase_bit_offset`: Bit position of the phase bit in the status field
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `vaddr` points to valid, zeroed DMA memory
    /// - The memory is at least `memory_size(depth)` bytes
    /// - The memory is mapped in IOSpace at `iova`
    /// - The memory remains valid for the lifetime of this queue
    #[inline]
    pub unsafe fn new(
        vaddr: *const E,
        iova: u64,
        depth: u16,
        status_field_offset: usize,
        phase_bit_offset: usize,
    ) -> Self {
        Self {
            entries: vaddr,
            iova,
            depth,
            head: 0,
            phase: true, // Initial phase is 1
            phase_bit_offset,
            status_field_offset,
        }
    }

    /// Get the IOVA of this queue for device configuration.
    #[inline]
    #[must_use]
    pub const fn iova(&self) -> u64 {
        self.iova
    }

    /// Get the depth (number of entries) of this queue.
    #[inline]
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Check if there is a valid completion to process.
    ///
    /// This reads the phase bit of the current head entry to determine
    /// if the device has written a new completion.
    #[must_use]
    pub fn has_completion(&self) -> bool {
        // Memory barrier to ensure we see the latest writes
        read_barrier();

        // Read the status field from the current head entry
        // SAFETY: entries pointer is valid, head is within bounds
        let entry_ptr = unsafe { self.entries.add(self.head as usize) };
        let entry_bytes = entry_ptr as *const u8;

        // Read the status field (as u16, which is typical for NVMe)
        // SAFETY: status_field_offset is within entry bounds
        let status =
            unsafe { read_volatile(entry_bytes.add(self.status_field_offset) as *const u16) };

        // Extract the phase bit
        let phase_bit = (status >> self.phase_bit_offset) & 1;

        // Check if it matches our expected phase
        phase_bit == (self.phase as u16)
    }

    /// Pop the next completion entry if available.
    ///
    /// Returns `Some(entry)` if a valid completion is available, `None` otherwise.
    /// The caller should ring the doorbell after processing completions.
    pub fn pop(&mut self) -> Option<E> {
        if !self.has_completion() {
            return None;
        }

        // Read the entry
        // SAFETY: entries pointer is valid, head is within bounds
        let entry = unsafe { read_volatile(self.entries.add(self.head as usize)) };

        // Advance head
        self.head = (self.head + 1) % self.depth;

        // Toggle phase when we wrap around
        if self.head == 0 {
            self.phase = !self.phase;
        }

        Some(entry)
    }

    /// Get the doorbell value to write after processing completions.
    ///
    /// This is the new head index that should be written to the doorbell
    /// register to indicate which entries have been consumed.
    #[inline]
    #[must_use]
    pub const fn doorbell_value(&self) -> u16 {
        self.head
    }

    /// Get the current head index.
    #[inline]
    #[must_use]
    pub const fn head(&self) -> u16 {
        self.head
    }

    /// Get a reference to an entry by slot index without consuming it.
    ///
    /// # Safety
    ///
    /// The caller must ensure the slot contains a valid completion.
    #[inline]
    pub unsafe fn peek_entry(&self, slot: u16) -> &E {
        debug_assert!(slot < self.depth, "Slot index out of bounds");
        // SAFETY: Caller guarantees slot is valid
        unsafe { &*self.entries.add(slot as usize) }
    }
}

// SAFETY: CompletionQueue can be sent between threads if entries memory is valid
unsafe impl<E: QueueEntry + Send> Send for CompletionQueue<E> {}

/// A paired submission and completion queue.
///
/// Provides a convenient wrapper for managing related SQ/CQ pairs.
pub struct QueuePair<S: QueueEntry, C: QueueEntry> {
    /// Submission queue
    pub sq: SubmissionQueue<S>,
    /// Completion queue
    pub cq: CompletionQueue<C>,
    /// Queue ID (for doorbells)
    pub qid: u16,
}

impl<S: QueueEntry, C: QueueEntry> QueuePair<S, C> {
    /// Create a new queue pair.
    ///
    /// # Safety
    ///
    /// See safety requirements for `SubmissionQueue::new` and `CompletionQueue::new`.
    #[inline]
    pub unsafe fn new(sq: SubmissionQueue<S>, cq: CompletionQueue<C>, qid: u16) -> Self {
        Self { sq, cq, qid }
    }
}
