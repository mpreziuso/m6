//! Span metadata and storage
//!
//! A span is a contiguous region of memory dedicated to a single size class.
//! Span metadata is stored out-of-line from user objects for security.

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use crate::config::{MAX_SPANS, NUM_SIZE_CLASSES, PAGE_SIZE, SIZE_CLASSES};

/// Reference to a span (index into span storage)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanRef(u32);

impl SpanRef {
    /// Create a span reference from an index
    pub const fn from_index(index: usize) -> Self {
        Self(index as u32)
    }

    /// Get the index of this span reference
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Null/invalid span reference
    pub const NULL: Self = Self(u32::MAX);

    /// Check if this is a null reference
    pub const fn is_null(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Span metadata stored out-of-line from user objects
///
/// Each span serves a single size class and is subdivided into fixed-size slots.
/// The metadata tracks allocation state via a bitmap for double-free detection
/// and maintains a freelist of available slots.
#[repr(C)]
pub struct SpanMeta {
    /// Virtual address of span start
    base_addr: usize,

    /// Size class index (0..NUM_SIZE_CLASSES)
    size_class: u8,

    /// Number of pages in this span
    page_count: u8,

    /// Reserved for alignment
    _reserved: u16,

    /// Number of allocated slots
    allocated_count: AtomicU16,

    /// Total number of slots in this span
    total_slots: u16,

    /// Head of encoded freelist (pointer XORed with secret)
    pub freelist_head: AtomicU64,

    /// Allocation bitmap for double-free detection
    /// Each bit represents one slot (1 = allocated, 0 = free)
    /// Supports up to 512 slots per span (8 * 64 bits)
    alloc_bitmap: [AtomicU64; 8],

    /// Frame capability pointer for unmapping
    frame_cptr: u64,

    /// Next span in list (partial/full/empty)
    next: AtomicU64,

    /// Previous span in list
    prev: AtomicU64,
}

impl SpanMeta {
    /// Create uninitialised span metadata
    const fn uninit() -> Self {
        Self {
            base_addr: 0,
            size_class: 0,
            page_count: 0,
            _reserved: 0,
            allocated_count: AtomicU16::new(0),
            total_slots: 0,
            freelist_head: AtomicU64::new(0),
            alloc_bitmap: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            frame_cptr: 0,
            next: AtomicU64::new(SpanRef::NULL.0 as u64),
            prev: AtomicU64::new(SpanRef::NULL.0 as u64),
        }
    }

    /// Initialise a span with the given parameters
    pub fn init(
        &mut self,
        base_addr: usize,
        size_class: usize,
        page_count: usize,
        frame_cptr: u64,
    ) {
        let class = &SIZE_CLASSES[size_class];
        let total_slots = (page_count * PAGE_SIZE) / class.size;

        self.base_addr = base_addr;
        self.size_class = size_class as u8;
        self.page_count = page_count as u8;
        self.allocated_count = AtomicU16::new(0);
        self.total_slots = total_slots as u16;
        self.freelist_head = AtomicU64::new(0);
        self.frame_cptr = frame_cptr;
        self.next = AtomicU64::new(SpanRef::NULL.0 as u64);
        self.prev = AtomicU64::new(SpanRef::NULL.0 as u64);

        // Clear bitmap
        for word in &self.alloc_bitmap {
            word.store(0, Ordering::Relaxed);
        }
    }

    /// Get the base address of this span
    pub fn base_addr(&self) -> usize {
        self.base_addr
    }

    /// Get the size class index
    pub fn size_class(&self) -> usize {
        self.size_class as usize
    }

    /// Get the slot size for this span
    pub fn slot_size(&self) -> usize {
        SIZE_CLASSES[self.size_class as usize].size
    }

    /// Get the number of pages in this span
    pub fn page_count(&self) -> usize {
        self.page_count as usize
    }

    /// Get the total number of slots
    pub fn total_slots(&self) -> usize {
        self.total_slots as usize
    }

    /// Get the number of allocated slots
    pub fn allocated_count(&self) -> usize {
        self.allocated_count.load(Ordering::Relaxed) as usize
    }

    /// Check if the span is full (no free slots)
    pub fn is_full(&self) -> bool {
        self.allocated_count() >= self.total_slots()
    }

    /// Check if the span is empty (no allocated slots)
    pub fn is_empty(&self) -> bool {
        self.allocated_count() == 0
    }

    /// Get the frame capability pointer
    pub fn frame_cptr(&self) -> u64 {
        self.frame_cptr
    }

    /// Get the end address of this span
    pub fn end_addr(&self) -> usize {
        self.base_addr + (self.page_count as usize * PAGE_SIZE)
    }

    /// Check if an address is within this span
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base_addr && addr < self.end_addr()
    }

    /// Convert an address to a slot index within this span
    ///
    /// Returns None if the address is outside the span or not slot-aligned.
    pub fn addr_to_slot(&self, addr: usize) -> Option<usize> {
        if addr < self.base_addr {
            return None;
        }

        let offset = addr - self.base_addr;
        let slot_size = self.slot_size();

        if !offset.is_multiple_of(slot_size) {
            return None; // Not slot-aligned
        }

        let slot_idx = offset / slot_size;
        if slot_idx >= self.total_slots as usize {
            return None;
        }

        Some(slot_idx)
    }

    /// Convert a slot index to an address
    pub fn slot_to_addr(&self, slot_idx: usize) -> usize {
        self.base_addr + (slot_idx * self.slot_size())
    }

    /// Check if a slot is allocated (bitmap check)
    pub fn is_slot_allocated(&self, slot_idx: usize) -> bool {
        let word_idx = slot_idx / 64;
        let bit_idx = slot_idx % 64;
        let word = self.alloc_bitmap[word_idx].load(Ordering::Relaxed);
        (word >> bit_idx) & 1 == 1
    }

    /// Mark a slot as allocated in the bitmap
    ///
    /// Returns true if the slot was previously free (successful allocation).
    /// Returns false if already allocated (double-alloc attempt).
    pub fn mark_allocated(&self, slot_idx: usize) -> bool {
        let word_idx = slot_idx / 64;
        let bit_idx = slot_idx % 64;
        let mask = 1u64 << bit_idx;

        let old = self.alloc_bitmap[word_idx].fetch_or(mask, Ordering::AcqRel);
        let was_free = (old >> bit_idx) & 1 == 0;

        if was_free {
            self.allocated_count.fetch_add(1, Ordering::Relaxed);
        }

        was_free
    }

    /// Mark a slot as free in the bitmap
    ///
    /// Returns true if the slot was previously allocated (successful free).
    /// Returns false if already free (double-free attempt).
    pub fn mark_free(&self, slot_idx: usize) -> bool {
        let word_idx = slot_idx / 64;
        let bit_idx = slot_idx % 64;
        let mask = 1u64 << bit_idx;

        let old = self.alloc_bitmap[word_idx].fetch_and(!mask, Ordering::AcqRel);
        let was_allocated = (old >> bit_idx) & 1 == 1;

        if was_allocated {
            self.allocated_count.fetch_sub(1, Ordering::Relaxed);
        }

        was_allocated
    }

    /// Get the next span reference
    pub fn next(&self) -> SpanRef {
        SpanRef(self.next.load(Ordering::Relaxed) as u32)
    }

    /// Set the next span reference
    pub fn set_next(&self, next: SpanRef) {
        self.next.store(next.0 as u64, Ordering::Relaxed);
    }

    /// Get the previous span reference
    pub fn prev(&self) -> SpanRef {
        SpanRef(self.prev.load(Ordering::Relaxed) as u32)
    }

    /// Set the previous span reference
    pub fn set_prev(&self, prev: SpanRef) {
        self.prev.store(prev.0 as u64, Ordering::Relaxed);
    }
}

/// Storage for span metadata
///
/// Pre-allocated array of SpanMeta structures with a freelist
/// for allocating new spans.
pub struct SpanStorage {
    /// Array of span metadata
    spans: [SpanMeta; MAX_SPANS],

    /// Head of freelist (index of first free span slot)
    free_head: SpanRef,

    /// Number of active spans
    active_count: usize,
}

impl SpanStorage {
    /// Create new span storage
    pub const fn new() -> Self {
        Self {
            spans: [const { SpanMeta::uninit() }; MAX_SPANS],
            free_head: SpanRef::from_index(0),
            active_count: 0,
        }
    }

    /// Initialise the span storage freelist
    ///
    /// Must be called before using the storage.
    pub fn init(&mut self) {
        // Link all spans into a freelist
        for i in 0..MAX_SPANS - 1 {
            self.spans[i].set_next(SpanRef::from_index(i + 1));
        }
        self.spans[MAX_SPANS - 1].set_next(SpanRef::NULL);
        self.free_head = SpanRef::from_index(0);
        self.active_count = 0;
    }

    /// Allocate a span slot from storage
    ///
    /// Returns a reference to the allocated span, or None if no slots available.
    pub fn alloc_span(&mut self) -> Option<SpanRef> {
        if self.free_head.is_null() {
            return None;
        }

        let span_ref = self.free_head;
        let span = &self.spans[span_ref.index()];
        self.free_head = span.next();
        self.active_count += 1;

        Some(span_ref)
    }

    /// Free a span slot back to storage
    pub fn free_span(&mut self, span_ref: SpanRef) {
        let span = &self.spans[span_ref.index()];
        span.set_next(self.free_head);
        self.free_head = span_ref;
        self.active_count -= 1;
    }

    /// Get a reference to a span by index
    pub fn get(&self, span_ref: SpanRef) -> &SpanMeta {
        &self.spans[span_ref.index()]
    }

    /// Get a mutable reference to a span by index
    pub fn get_mut(&mut self, span_ref: SpanRef) -> &mut SpanMeta {
        &mut self.spans[span_ref.index()]
    }

    /// Find the span containing an address
    ///
    /// This is O(n) but typically spans are few and this is only
    /// called on free() which is less frequent than alloc().
    pub fn find_span(&self, addr: usize) -> Option<SpanRef> {
        for i in 0..MAX_SPANS {
            let span = &self.spans[i];
            if span.base_addr != 0 && span.contains(addr) {
                return Some(SpanRef::from_index(i));
            }
        }
        None
    }

    /// Number of active spans
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for SpanStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-size-class span lists
pub struct SizeClassSpans {
    /// Partial spans (have free slots)
    pub partial_head: SpanRef,

    /// Full spans (no free slots)
    pub full_head: SpanRef,

    /// Empty spans (all slots free, candidates for return to pool)
    pub empty_head: SpanRef,

    /// Count of partial spans
    pub partial_count: usize,

    /// Count of full spans
    pub full_count: usize,

    /// Count of empty spans
    pub empty_count: usize,
}

impl SizeClassSpans {
    /// Create empty span lists
    pub const fn new() -> Self {
        Self {
            partial_head: SpanRef::NULL,
            full_head: SpanRef::NULL,
            empty_head: SpanRef::NULL,
            partial_count: 0,
            full_count: 0,
            empty_count: 0,
        }
    }

    /// Add a span to the partial list
    pub fn add_partial(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        span.set_next(self.partial_head);
        span.set_prev(SpanRef::NULL);

        if !self.partial_head.is_null() {
            storage.get(self.partial_head).set_prev(span_ref);
        }

        self.partial_head = span_ref;
        self.partial_count += 1;
    }

    /// Remove a span from the partial list
    pub fn remove_partial(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        let prev = span.prev();
        let next = span.next();

        if !prev.is_null() {
            storage.get(prev).set_next(next);
        } else {
            self.partial_head = next;
        }

        if !next.is_null() {
            storage.get(next).set_prev(prev);
        }

        self.partial_count -= 1;
    }

    /// Add a span to the full list
    pub fn add_full(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        span.set_next(self.full_head);
        span.set_prev(SpanRef::NULL);

        if !self.full_head.is_null() {
            storage.get(self.full_head).set_prev(span_ref);
        }

        self.full_head = span_ref;
        self.full_count += 1;
    }

    /// Remove a span from the full list
    pub fn remove_full(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        let prev = span.prev();
        let next = span.next();

        if !prev.is_null() {
            storage.get(prev).set_next(next);
        } else {
            self.full_head = next;
        }

        if !next.is_null() {
            storage.get(next).set_prev(prev);
        }

        self.full_count -= 1;
    }

    /// Add a span to the empty list
    pub fn add_empty(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        span.set_next(self.empty_head);
        span.set_prev(SpanRef::NULL);

        if !self.empty_head.is_null() {
            storage.get(self.empty_head).set_prev(span_ref);
        }

        self.empty_head = span_ref;
        self.empty_count += 1;
    }

    /// Remove a span from the empty list
    pub fn remove_empty(&mut self, span_ref: SpanRef, storage: &SpanStorage) {
        let span = storage.get(span_ref);
        let prev = span.prev();
        let next = span.next();

        if !prev.is_null() {
            storage.get(prev).set_next(next);
        } else {
            self.empty_head = next;
        }

        if !next.is_null() {
            storage.get(next).set_prev(prev);
        }

        self.empty_count -= 1;
    }
}

impl Default for SizeClassSpans {
    fn default() -> Self {
        Self::new()
    }
}

/// All size class span lists
pub struct AllSizeClassSpans {
    /// Per-size-class span lists
    pub classes: [SizeClassSpans; NUM_SIZE_CLASSES],
}

impl AllSizeClassSpans {
    /// Create new span lists for all size classes
    pub const fn new() -> Self {
        Self {
            classes: [const { SizeClassSpans::new() }; NUM_SIZE_CLASSES],
        }
    }
}

impl Default for AllSizeClassSpans {
    fn default() -> Self {
        Self::new()
    }
}
