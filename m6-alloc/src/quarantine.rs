//! Quarantine for delayed reuse
//!
//! Feature-gated under the `quarantine` feature.
//! Delays reuse of freed memory to make use-after-free bugs more likely
//! to be detected.

use core::alloc::Layout;

use crate::config::{MAX_QUARANTINE_BYTES, QUARANTINE_SIZE};

/// Entry in the quarantine queue
#[derive(Debug, Clone, Copy)]
pub struct QuarantineEntry {
    /// Pointer to the freed memory
    pub ptr: *mut u8,
    /// Layout of the allocation
    pub size: usize,
    /// Whether this is a large allocation
    pub is_large: bool,
}

impl QuarantineEntry {
    /// Create an empty entry
    const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            size: 0,
            is_large: false,
        }
    }

    /// Check if this entry is empty
    pub fn is_empty(&self) -> bool {
        self.ptr.is_null()
    }
}

/// Circular buffer queue for quarantined allocations
pub struct QuarantineQueue {
    /// Circular buffer of entries
    entries: [QuarantineEntry; QUARANTINE_SIZE],
    /// Head index (next to dequeue)
    head: usize,
    /// Tail index (next to enqueue)
    tail: usize,
    /// Current count
    count: usize,
    /// Total bytes in quarantine
    bytes: usize,
}

impl QuarantineQueue {
    /// Create an empty quarantine queue
    pub const fn new() -> Self {
        Self {
            entries: [const { QuarantineEntry::empty() }; QUARANTINE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            bytes: 0,
        }
    }

    /// Check if the queue is full
    pub fn is_full(&self) -> bool {
        self.count >= QUARANTINE_SIZE
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if we should flush due to byte limit
    pub fn should_flush(&self) -> bool {
        self.bytes >= MAX_QUARANTINE_BYTES
    }

    /// Add an entry to quarantine
    ///
    /// Returns entries that should be flushed if the queue is full or
    /// over the byte limit.
    pub fn quarantine(&mut self, entry: QuarantineEntry) -> Option<QuarantineEntry> {
        let to_flush = if self.is_full() || self.should_flush() {
            self.dequeue()
        } else {
            None
        };

        // Add new entry
        self.entries[self.tail] = entry;
        self.tail = (self.tail + 1) % QUARANTINE_SIZE;
        self.count += 1;
        self.bytes += entry.size;

        to_flush
    }

    /// Remove the oldest entry from quarantine
    pub fn dequeue(&mut self) -> Option<QuarantineEntry> {
        if self.is_empty() {
            return None;
        }

        let entry = self.entries[self.head];
        self.entries[self.head] = QuarantineEntry::empty();
        self.head = (self.head + 1) % QUARANTINE_SIZE;
        self.count -= 1;
        self.bytes -= entry.size;

        Some(entry)
    }

    /// Flush all entries from quarantine
    pub fn flush_all(&mut self) -> FlushIterator<'_> {
        FlushIterator { queue: self }
    }

    /// Get the number of entries in quarantine
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the total bytes in quarantine
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Default for QuarantineQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator that flushes all entries from a quarantine queue
pub struct FlushIterator<'a> {
    queue: &'a mut QuarantineQueue,
}

impl Iterator for FlushIterator<'_> {
    type Item = QuarantineEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.queue.dequeue()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_basic() {
        let mut queue = QuarantineQueue::new();

        let entry = QuarantineEntry {
            ptr: 0x1000 as *mut u8,
            size: 64,
            is_large: false,
        };

        let flushed = queue.quarantine(entry);
        assert!(flushed.is_none());
        assert_eq!(queue.count(), 1);
        assert_eq!(queue.bytes(), 64);
    }

    #[test]
    fn test_quarantine_dequeue() {
        let mut queue = QuarantineQueue::new();

        let entry1 = QuarantineEntry {
            ptr: 0x1000 as *mut u8,
            size: 64,
            is_large: false,
        };
        let entry2 = QuarantineEntry {
            ptr: 0x2000 as *mut u8,
            size: 128,
            is_large: false,
        };

        queue.quarantine(entry1);
        queue.quarantine(entry2);

        let dequeued = queue.dequeue();
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().ptr, 0x1000 as *mut u8);
        assert_eq!(queue.count(), 1);
    }
}
