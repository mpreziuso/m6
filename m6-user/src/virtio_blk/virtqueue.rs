//! VirtIO split virtqueue implementation.
//!
//! This implements the legacy split virtqueue format for VirtIO devices.
//! Each virtqueue consists of three parts:
//! - Descriptor table: array of buffer descriptors
//! - Available ring: driver-written ring of available descriptor heads
//! - Used ring: device-written ring of consumed descriptor heads

#![allow(dead_code)]

use core::sync::atomic::{fence, Ordering};

/// Descriptor flags
pub mod desc_flags {
    /// Buffer continues via the next field
    pub const NEXT: u16 = 1;
    /// Buffer is write-only (device writes, driver reads)
    pub const WRITE: u16 = 2;
    /// Buffer contains a list of indirect descriptors
    pub const INDIRECT: u16 = 4;
}

/// Virtqueue descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    /// Physical address of the buffer
    pub addr: u64,
    /// Length of the buffer in bytes
    pub len: u32,
    /// Descriptor flags
    pub flags: u16,
    /// Index of next descriptor if NEXT flag is set
    pub next: u16,
}

/// Available ring header
#[repr(C)]
pub struct VirtqAvail {
    /// Flags (bit 0 = no_interrupt)
    pub flags: u16,
    /// Next available slot index
    pub idx: u16,
    // Followed by ring[queue_size] of u16 descriptor indices
    // Then optional used_event u16 if VIRTIO_F_EVENT_IDX
}

/// Used ring element
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    /// Descriptor head index that was consumed
    pub id: u32,
    /// Total bytes written to the descriptor chain
    pub len: u32,
}

/// Used ring header
#[repr(C)]
pub struct VirtqUsed {
    /// Flags (bit 0 = no_notify)
    pub flags: u16,
    /// Next used slot index
    pub idx: u16,
    // Followed by ring[queue_size] of VirtqUsedElem
    // Then optional avail_event u16 if VIRTIO_F_EVENT_IDX
}

/// Split virtqueue structure.
///
/// This manages a single virtqueue with its descriptor table, available ring,
/// and used ring. Memory must be physically contiguous and aligned.
pub struct Virtqueue {
    /// Number of entries in the queue
    queue_size: u16,
    /// Pointer to descriptor table
    desc: *mut VirtqDesc,
    /// Pointer to available ring
    avail: *mut VirtqAvail,
    /// Pointer to used ring
    used: *mut VirtqUsed,
    /// Next available descriptor index
    free_head: u16,
    /// Number of free descriptors
    num_free: u16,
    /// Last seen used index
    last_used_idx: u16,
}

impl Virtqueue {
    /// Required alignment for virtqueue structures
    pub const ALIGN: usize = 4096;

    /// Calculate total memory needed for a virtqueue.
    ///
    /// Returns (desc_size, avail_size, used_size, total_size)
    pub fn memory_layout(queue_size: u16) -> (usize, usize, usize, usize) {
        let qs = queue_size as usize;
        let desc_size = qs * core::mem::size_of::<VirtqDesc>();
        let avail_size = 4 + qs * 2 + 2; // flags + idx + ring + used_event
        let used_size = 4 + qs * core::mem::size_of::<VirtqUsedElem>() + 2; // flags + idx + ring + avail_event

        // Align each section
        let desc_aligned = (desc_size + Self::ALIGN - 1) & !(Self::ALIGN - 1);
        let avail_aligned = (avail_size + Self::ALIGN - 1) & !(Self::ALIGN - 1);
        let used_aligned = (used_size + Self::ALIGN - 1) & !(Self::ALIGN - 1);

        (desc_aligned, avail_aligned, used_aligned, desc_aligned + avail_aligned + used_aligned)
    }

    /// Create a new virtqueue.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `base` points to properly aligned, physically contiguous memory
    /// - Memory is at least `memory_layout(queue_size).3` bytes
    /// - Memory is zeroed before calling this function
    pub unsafe fn new(base: *mut u8, queue_size: u16) -> Self {
        // SAFETY: Caller guarantees base is valid and properly sized
        unsafe {
            let (desc_size, avail_size, _used_size, _total) = Self::memory_layout(queue_size);

            let desc = base as *mut VirtqDesc;
            let avail = base.add(desc_size) as *mut VirtqAvail;
            let used = base.add(desc_size + avail_size) as *mut VirtqUsed;

            // Initialise descriptor free list
            for i in 0..(queue_size - 1) {
                (*desc.add(i as usize)).next = i + 1;
            }

            Self {
                queue_size,
                desc,
                avail,
                used,
                free_head: 0,
                num_free: queue_size,
                last_used_idx: 0,
            }
        }
    }

    /// Get physical addresses for device configuration.
    ///
    /// Returns (desc_addr, avail_addr, used_addr) as offsets from base.
    pub fn addresses(&self) -> (u64, u64, u64) {
        let base = self.desc as u64;
        let (desc_size, avail_size, _used_size, _total) = Self::memory_layout(self.queue_size);
        (base, base + desc_size as u64, base + desc_size as u64 + avail_size as u64)
    }

    /// Get queue size.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Allocate a descriptor from the free list.
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }

        let idx = self.free_head;
        // SAFETY: free_head is always within bounds
        let next = unsafe { (*self.desc.add(idx as usize)).next };
        self.free_head = next;
        self.num_free -= 1;
        Some(idx)
    }

    /// Free a descriptor back to the free list.
    fn free_desc(&mut self, idx: u16) {
        // SAFETY: idx should be a valid descriptor index
        unsafe {
            (*self.desc.add(idx as usize)).next = self.free_head;
        }
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Free a descriptor chain starting at `head`.
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            // SAFETY: idx is within bounds
            let desc = unsafe { &*self.desc.add(idx as usize) };
            let flags = desc.flags;
            let next = desc.next;

            self.free_desc(idx);

            if flags & desc_flags::NEXT == 0 {
                break;
            }
            idx = next;
        }
    }

    /// Add a single buffer to the queue.
    ///
    /// Returns the descriptor head index on success.
    pub fn add_buf(&mut self, addr: u64, len: u32, write: bool) -> Option<u16> {
        let idx = self.alloc_desc()?;

        // SAFETY: idx was just allocated and is valid
        unsafe {
            let desc = &mut *self.desc.add(idx as usize);
            desc.addr = addr;
            desc.len = len;
            desc.flags = if write { desc_flags::WRITE } else { 0 };
            desc.next = 0;
        }

        // Add to available ring
        // SAFETY: avail is valid and idx is within bounds
        unsafe {
            let avail = &mut *self.avail;
            let ring_idx = avail.idx as usize % self.queue_size as usize;
            let ring = (avail as *mut VirtqAvail).add(1) as *mut u16;
            *ring.add(ring_idx) = idx;

            // Memory barrier before updating idx
            fence(Ordering::Release);

            avail.idx = avail.idx.wrapping_add(1);
        }

        Some(idx)
    }

    /// Add a descriptor chain (request header + data + status) for block I/O.
    ///
    /// This is the common pattern for VirtIO block requests:
    /// - desc[0]: request header (device reads)
    /// - desc[1]: data buffer (device reads for write, device writes for read)
    /// - desc[2]: status byte (device writes)
    ///
    /// Returns the descriptor head index on success.
    pub fn add_block_request(
        &mut self,
        header_addr: u64,
        header_len: u32,
        data_addr: u64,
        data_len: u32,
        status_addr: u64,
        is_write: bool,
    ) -> Option<u16> {
        // Need 3 descriptors
        if self.num_free < 3 {
            return None;
        }

        let head = self.alloc_desc()?;
        let data_idx = self.alloc_desc()?;
        let status_idx = self.alloc_desc()?;

        // SAFETY: indices are valid
        unsafe {
            // Header descriptor (device reads)
            let desc0 = &mut *self.desc.add(head as usize);
            desc0.addr = header_addr;
            desc0.len = header_len;
            desc0.flags = desc_flags::NEXT;
            desc0.next = data_idx;

            // Data descriptor
            let desc1 = &mut *self.desc.add(data_idx as usize);
            desc1.addr = data_addr;
            desc1.len = data_len;
            // For read: device writes; for write: device reads
            desc1.flags = desc_flags::NEXT | if !is_write { desc_flags::WRITE } else { 0 };
            desc1.next = status_idx;

            // Status descriptor (device writes)
            let desc2 = &mut *self.desc.add(status_idx as usize);
            desc2.addr = status_addr;
            desc2.len = 1;
            desc2.flags = desc_flags::WRITE;
            desc2.next = 0;
        }

        // Add to available ring
        // SAFETY: avail is valid
        unsafe {
            let avail = &mut *self.avail;
            let ring_idx = avail.idx as usize % self.queue_size as usize;
            let ring = (avail as *mut VirtqAvail).add(1) as *mut u16;
            *ring.add(ring_idx) = head;

            fence(Ordering::Release);
            avail.idx = avail.idx.wrapping_add(1);
        }

        Some(head)
    }

    /// Check if there are used buffers to process.
    pub fn has_used(&self) -> bool {
        fence(Ordering::Acquire);
        // SAFETY: used is valid
        let used_idx = unsafe { (*self.used).idx };
        used_idx != self.last_used_idx
    }

    /// Get the next used buffer.
    ///
    /// Returns (descriptor_head, bytes_written) if available.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::Acquire);

        // SAFETY: used is valid
        let used_idx = unsafe { (*self.used).idx };
        if used_idx == self.last_used_idx {
            return None;
        }

        let ring_idx = self.last_used_idx as usize % self.queue_size as usize;
        // SAFETY: ring_idx is within bounds
        let elem = unsafe {
            let ring = (self.used as *const VirtqUsed).add(1) as *const VirtqUsedElem;
            *ring.add(ring_idx)
        };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        Some((elem.id as u16, elem.len))
    }
}

// SAFETY: Virtqueue can be sent between threads if the underlying memory is valid
unsafe impl Send for Virtqueue {}
