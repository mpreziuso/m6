//! Core allocator implementation
//!
//! The main allocator state and allocation/deallocation logic.

use core::alloc::Layout;
use core::ptr;

use crate::config::{PAGE_SIZE, SIZE_CLASSES};
use crate::error::{AllocError, FreelistError};
use crate::freelist::{init_span_freelist, pop_freelist, push_freelist};
use crate::large::{LargeEntry, SyncLargeSideTable, mapped_size, pages_for_size};
use crate::lock::SpinLock;
use crate::size_class::find_size_class_aligned;
use crate::span::{AllSizeClassSpans, SpanRef, SpanStorage};
use crate::traits::{AllocatedPages, PagePool, SecretProvider, VmProvider, VmRights};

#[cfg(feature = "stats")]
use crate::stats::AllocatorStats;

#[cfg(feature = "quarantine")]
use crate::quarantine::QuarantineQueue;

/// Allocator configuration
pub struct AllocatorConfig {
    /// Base virtual address for the heap
    pub heap_base: usize,
    /// Maximum heap size in bytes
    pub heap_size: usize,
}

/// Core allocator state
pub struct Allocator<V, P, S>
where
    V: VmProvider,
    P: PagePool,
    S: SecretProvider,
{
    /// Virtual memory provider
    vm: V,
    /// Page pool for allocating physical pages
    pool: P,
    /// Secret provider for freelist encoding
    #[allow(dead_code)]
    secret: S,

    /// Span metadata storage
    spans: SpinLock<SpanStorage>,

    /// Per-size-class span lists
    size_class_spans: SpinLock<AllSizeClassSpans>,

    /// Large allocation side table
    large_table: SyncLargeSideTable,

    /// Heap virtual address range
    heap_base: usize,
    heap_size: usize,

    /// Next virtual address for allocation
    next_vaddr: SpinLock<usize>,

    /// Cached encoding secret
    encoding_secret: u64,

    /// Quarantine queue (feature-gated)
    #[cfg(feature = "quarantine")]
    quarantine: SpinLock<QuarantineQueue>,

    /// Statistics (feature-gated)
    #[cfg(feature = "stats")]
    stats: SpinLock<AllocatorStats>,

    /// Whether the allocator is poisoned due to corruption
    poisoned: core::sync::atomic::AtomicBool,
}

impl<V, P, S> Allocator<V, P, S>
where
    V: VmProvider,
    P: PagePool,
    S: SecretProvider,
{
    /// Create a new allocator
    ///
    /// # Arguments
    /// * `vm` - Virtual memory provider
    /// * `pool` - Page pool for physical pages
    /// * `secret` - Secret provider for freelist encoding
    /// * `config` - Allocator configuration
    pub fn new(vm: V, pool: P, secret: S, config: AllocatorConfig) -> Self {
        let encoding_secret = secret.get_secret();

        let mut spans = SpanStorage::new();
        spans.init();

        Self {
            vm,
            pool,
            secret,
            spans: SpinLock::new(spans),
            size_class_spans: SpinLock::new(AllSizeClassSpans::new()),
            large_table: SyncLargeSideTable::new(),
            heap_base: config.heap_base,
            heap_size: config.heap_size,
            next_vaddr: SpinLock::new(config.heap_base),
            encoding_secret,
            #[cfg(feature = "quarantine")]
            quarantine: SpinLock::new(QuarantineQueue::new()),
            #[cfg(feature = "stats")]
            stats: SpinLock::new(AllocatorStats::new()),
            poisoned: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Check if the allocator is poisoned
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Mark the allocator as poisoned
    fn poison(&self) {
        self.poisoned
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    /// Allocate memory with the given layout
    ///
    /// # Safety
    /// The returned pointer must be deallocated with the same layout.
    pub fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.is_poisoned() {
            return ptr::null_mut();
        }

        // Handle zero-size allocations
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        // Try small allocation first
        if let Some(class_idx) = find_size_class_aligned(layout.size(), layout.align()) {
            match self.alloc_small(class_idx) {
                Ok(ptr) => {
                    #[cfg(feature = "debug-poison")]
                    if !ptr.is_null() {
                        crate::poison::poison_alloc(ptr, layout.size());
                    }
                    return ptr;
                }
                Err(_) => return ptr::null_mut(),
            }
        }

        // Fall back to large allocation
        match self.alloc_large(layout) {
            Ok(ptr) => {
                #[cfg(feature = "debug-poison")]
                if !ptr.is_null() {
                    crate::poison::poison_alloc(ptr, layout.size());
                }
                ptr
            }
            Err(_) => ptr::null_mut(),
        }
    }

    /// Deallocate memory
    ///
    /// # Safety
    /// The pointer must have been allocated by this allocator with the given layout.
    pub unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || layout.size() == 0 {
            return;
        }

        if self.is_poisoned() {
            return;
        }

        #[cfg(feature = "debug-poison")]
        crate::poison::poison_free(ptr, layout.size());

        let addr = ptr as usize;

        // Check if this is a large allocation
        if let Some(entry) = self.large_table.lookup(addr) {
            if let Err(e) = self.free_large(addr, entry) {
                self.handle_error(e);
            }
            return;
        }

        // Must be a small allocation - find its span
        let span_ref = {
            let spans = self.spans.lock();
            spans.find_span(addr)
        };

        if let Some(span_ref) = span_ref {
            if let Err(e) = self.free_small(addr, span_ref) {
                self.handle_error(e);
            }
        } else {
            // Unknown pointer - could be corruption or misuse
            self.poison();
        }
    }

    /// Allocate from a size class
    fn alloc_small(&self, class_idx: usize) -> Result<*mut u8, AllocError> {
        // Try to allocate from an existing partial span
        let span_ref = {
            let spans = self.size_class_spans.lock();
            let class_spans = &spans.classes[class_idx];
            if !class_spans.partial_head.is_null() {
                Some(class_spans.partial_head)
            } else {
                None
            }
        };

        if let Some(span_ref) = span_ref {
            let spans = self.spans.lock();
            let span = spans.get(span_ref);

            // SAFETY: Span is mapped
            match unsafe { pop_freelist(span, self.encoding_secret) } {
                Ok(Some(addr)) => {
                    // Mark slot as allocated in bitmap
                    if let Some(slot_idx) = span.addr_to_slot(addr) {
                        let was_free = span.mark_allocated(slot_idx);
                        if !was_free {
                            // Double-alloc - corruption
                            drop(spans);
                            self.poison();
                            return Err(AllocError::Poisoned);
                        }
                    }

                    // Check if span is now full
                    if span.is_full() {
                        drop(spans);
                        self.move_span_to_full(span_ref, class_idx);
                    }

                    #[cfg(feature = "stats")]
                    {
                        let mut stats = self.stats.lock();
                        stats.live_bytes += SIZE_CLASSES[class_idx].size;
                        stats.total_allocs += 1;
                    }

                    return Ok(addr as *mut u8);
                }
                Ok(None) => {
                    // Span is full, move to full list
                    drop(spans);
                    self.move_span_to_full(span_ref, class_idx);
                }
                Err(e) => {
                    drop(spans);
                    self.handle_freelist_error(e);
                    return Err(AllocError::Poisoned);
                }
            }
        }

        // Need to create a new span
        self.create_span_and_alloc(class_idx)
    }

    /// Create a new span and allocate from it
    fn create_span_and_alloc(&self, class_idx: usize) -> Result<*mut u8, AllocError> {
        let class = &SIZE_CLASSES[class_idx];

        // Allocate virtual address space
        let vaddr = {
            let mut next = self.next_vaddr.lock();
            let addr = *next;
            let size = class.span_pages * PAGE_SIZE;

            if addr + size > self.heap_base + self.heap_size {
                return Err(AllocError::OutOfMemory);
            }

            *next = addr + size;
            addr
        };

        // Allocate physical pages
        let pages = self
            .pool
            .alloc_pages(class.span_pages)
            .map_err(|_| AllocError::OutOfMemory)?;

        // Map the pages - each page has its own frame capability at a consecutive slot
        for i in 0..class.span_pages {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            let page_frame_cptr = pages.frame_cptr_for(i);
            if self
                .vm
                .map_frame(page_vaddr, page_frame_cptr, VmRights::RW)
                .is_err()
            {
                // Unmap already mapped pages
                for j in 0..i {
                    let unmap_vaddr = vaddr + (j * PAGE_SIZE);
                    let _ = self.vm.unmap_frame(unmap_vaddr);
                }
                // Return pages to pool
                let _ = self.pool.free_pages(pages);
                return Err(AllocError::MapFailed);
            }
        }

        // Allocate span metadata
        let span_ref = {
            let mut spans = self.spans.lock();
            spans.alloc_span().ok_or(AllocError::NoFreeSpans)?
        };

        // Initialise the span
        {
            let mut spans = self.spans.lock();
            let span = spans.get_mut(span_ref);
            span.init(vaddr, class_idx, class.span_pages, pages.frame_cptr);

            // Initialise freelist
            // SAFETY: We just mapped this memory
            unsafe {
                init_span_freelist(span, self.encoding_secret);
            }
        }

        // Add to partial list
        {
            let spans = self.spans.lock();
            let mut class_spans = self.size_class_spans.lock();
            class_spans.classes[class_idx].add_partial(span_ref, &spans);
        }

        #[cfg(feature = "stats")]
        {
            let mut stats = self.stats.lock();
            stats.committed_bytes += class.span_pages * PAGE_SIZE;
        }

        // Now allocate from the new span
        let spans = self.spans.lock();
        let span = spans.get(span_ref);

        // SAFETY: Span is mapped
        match unsafe { pop_freelist(span, self.encoding_secret) } {
            Ok(Some(addr)) => {
                if let Some(slot_idx) = span.addr_to_slot(addr) {
                    span.mark_allocated(slot_idx);
                }

                #[cfg(feature = "stats")]
                {
                    let mut stats = self.stats.lock();
                    stats.live_bytes += class.size;
                    stats.total_allocs += 1;
                }

                Ok(addr as *mut u8)
            }
            Ok(None) => Err(AllocError::OutOfMemory),
            Err(e) => {
                self.handle_freelist_error(e);
                Err(AllocError::Poisoned)
            }
        }
    }

    /// Free a small allocation
    fn free_small(&self, addr: usize, span_ref: SpanRef) -> Result<(), AllocError> {
        let spans = self.spans.lock();
        let span = spans.get(span_ref);
        let class_idx = span.size_class();

        // Validate the address
        let slot_idx = span.addr_to_slot(addr).ok_or_else(|| {
            self.poison();
            AllocError::Poisoned
        })?;

        // Check bitmap for double-free
        #[cfg(any(debug_assertions, feature = "release-double-free"))]
        {
            if !span.is_slot_allocated(slot_idx) {
                drop(spans);
                self.poison();
                return Err(AllocError::Poisoned);
            }
        }

        // Mark as free in bitmap
        let was_allocated = span.mark_free(slot_idx);
        if !was_allocated {
            drop(spans);
            self.poison();
            return Err(AllocError::Poisoned);
        }

        let was_full = span.allocated_count() + 1 == span.total_slots();
        let is_now_empty = span.is_empty();

        // Push onto freelist
        // SAFETY: We validated the address
        unsafe {
            push_freelist(span, addr, self.encoding_secret);
        }

        drop(spans);

        #[cfg(feature = "stats")]
        {
            let mut stats = self.stats.lock();
            stats.live_bytes = stats.live_bytes.saturating_sub(slot_size);
            stats.total_frees += 1;
        }

        // Update span lists
        if was_full {
            // Move from full to partial
            self.move_span_to_partial(span_ref, class_idx);
        }

        if is_now_empty {
            // Could return span to pool here
            // For now, keep it in partial list
        }

        Ok(())
    }

    /// Allocate a large allocation (direct-mapped)
    fn alloc_large(&self, layout: Layout) -> Result<*mut u8, AllocError> {
        let size = layout.size();
        let align = layout.align();

        // Calculate pages needed
        let page_count = pages_for_size(size.max(align));
        let map_size = mapped_size(size.max(align));

        #[cfg(feature = "guard-pages")]
        let total_pages = page_count + 1; // Extra page for guard
        #[cfg(not(feature = "guard-pages"))]
        let total_pages = page_count;

        // Allocate virtual address space
        let vaddr = {
            let mut next = self.next_vaddr.lock();
            let addr = *next;

            // Align if necessary
            let aligned_addr = if align > PAGE_SIZE {
                (addr + align - 1) & !(align - 1)
            } else {
                addr
            };

            let total_size = total_pages * PAGE_SIZE;
            if aligned_addr + total_size > self.heap_base + self.heap_size {
                return Err(AllocError::OutOfMemory);
            }

            *next = aligned_addr + total_size;
            aligned_addr
        };

        // Allocate physical pages
        let pages = self
            .pool
            .alloc_pages(page_count)
            .map_err(|_| AllocError::OutOfMemory)?;

        // Map the pages (not the guard page) - each page has its own frame capability
        for i in 0..page_count {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            let page_frame_cptr = pages.frame_cptr_for(i);
            if self
                .vm
                .map_frame(page_vaddr, page_frame_cptr, VmRights::RW)
                .is_err()
            {
                // Unmap already mapped pages
                for j in 0..i {
                    let unmap_vaddr = vaddr + (j * PAGE_SIZE);
                    let _ = self.vm.unmap_frame(unmap_vaddr);
                }
                // Return pages to pool
                let _ = self.pool.free_pages(pages);
                return Err(AllocError::MapFailed);
            }
        }

        // Record in side table
        let entry = LargeEntry {
            vaddr,
            requested_size: size,
            mapped_size: map_size,
            page_count,
            frame_cptr: pages.frame_cptr,
            #[cfg(feature = "guard-pages")]
            has_guard: true,
        };

        self.large_table.insert(entry)?;

        #[cfg(feature = "stats")]
        {
            let mut stats = self.stats.lock();
            stats.live_bytes += size;
            stats.committed_bytes += map_size;
            stats.total_allocs += 1;
        }

        Ok(vaddr as *mut u8)
    }

    /// Free a large allocation
    fn free_large(&self, addr: usize, entry: LargeEntry) -> Result<(), AllocError> {
        // Remove from side table
        self.large_table.remove(addr);

        // Unmap pages
        for i in 0..entry.page_count {
            let page_vaddr = addr + (i * PAGE_SIZE);
            let _ = self.vm.unmap_frame(page_vaddr);
        }

        // Return pages to pool
        let pages = AllocatedPages {
            frame_cptr: entry.frame_cptr,
            count: entry.page_count,
        };
        let _ = self.pool.free_pages(pages);

        #[cfg(feature = "stats")]
        {
            let mut stats = self.stats.lock();
            stats.live_bytes = stats.live_bytes.saturating_sub(entry.requested_size);
            stats.committed_bytes = stats.committed_bytes.saturating_sub(entry.mapped_size);
            stats.total_frees += 1;
        }

        Ok(())
    }

    /// Move a span from partial to full list
    fn move_span_to_full(&self, span_ref: SpanRef, class_idx: usize) {
        let spans = self.spans.lock();
        let mut class_spans = self.size_class_spans.lock();
        let class = &mut class_spans.classes[class_idx];

        class.remove_partial(span_ref, &spans);
        class.add_full(span_ref, &spans);
    }

    /// Move a span from full to partial list
    fn move_span_to_partial(&self, span_ref: SpanRef, class_idx: usize) {
        let spans = self.spans.lock();
        let mut class_spans = self.size_class_spans.lock();
        let class = &mut class_spans.classes[class_idx];

        class.remove_full(span_ref, &spans);
        class.add_partial(span_ref, &spans);
    }

    /// Handle a freelist error
    fn handle_freelist_error(&self, _error: FreelistError) {
        self.poison();
    }

    /// Handle a general error
    fn handle_error(&self, error: AllocError) {
        if matches!(error, AllocError::Poisoned) {
            self.poison();
        }
    }

    /// Get statistics (if feature enabled)
    #[cfg(feature = "stats")]
    pub fn stats(&self) -> crate::stats::AllocatorStats {
        self.stats.lock().clone()
    }
}
