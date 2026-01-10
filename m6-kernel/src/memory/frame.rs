//! Physical Frame Allocator
//!
//! Provides bitmap-based physical memory management.

use core::sync::atomic::{AtomicBool, Ordering};
use m6_arch::IrqSpinMutex;
use m6_common::memory::{page, MemoryMap};

use super::translate::{phys_to_virt, phys_to_virt_checked};

// -- Alignment Helpers

/// Align value up to the given power-of-two alignment
#[inline]
const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Align value down to the given power-of-two alignment
#[inline]
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

// -- Frame Allocator Error Types

/// Errors that can occur during frame allocation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocError {
    /// Requested frame range is out of bounds
    OutOfBounds {
        requested_start: usize,
        requested_end: usize,
        valid_start: usize,
        valid_end: usize,
    },
    /// Not enough contiguous frames available
    InsufficientContiguous { requested: usize, largest_free: usize },
    /// Not enough total frames available
    InsufficientTotal { requested: usize, available: usize },
    /// Bitmap is too small to cover the frame range
    BitmapTooSmall { required_entries: usize, actual_entries: usize },
    /// Allocator not initialised
    NotInitialised,
    /// Zero-count operation requested
    ZeroCount,
}

// -- Physical Frame Allocator

/// Physical frame allocator using a bitmap.
///
/// Each bit in the bitmap represents one 4KB frame:
/// - 1 = allocated
/// - 0 = free
///
/// # Invariants
///
/// - `free_frames` always equals the number of zero bits in the bitmap
/// - `bitmap.len() * 64 >= total_frames`
/// - All operations that would violate bounds return errors or panic
pub struct FrameAllocator {
    /// Bitmap of allocated frames (1 = allocated, 0 = free)
    bitmap: &'static mut [u64],
    /// Total number of frames managed
    total_frames: usize,
    /// Number of free frames (invariant: must match actual bitmap state)
    free_frames: usize,
    /// First frame number managed by this allocator
    first_frame: usize,
    /// Hint for next allocation search (optimisation)
    search_hint: usize,
}

impl FrameAllocator {
    /// Bits per bitmap entry
    const BITS_PER_ENTRY: usize = 64;

    /// Create a new frame allocator.
    ///
    /// # Arguments
    ///
    /// * `bitmap` - Mutable slice of u64s for the allocation bitmap
    /// * `first_frame` - First frame number managed by this allocator
    /// * `total_frames` - Total number of frames to manage
    ///
    /// # Safety
    ///
    /// - The bitmap memory must be valid for the lifetime of the allocator
    /// - The bitmap must not be accessed by other code while the allocator exists
    /// - `bitmap` must be large enough to hold `(total_frames + 63) / 64` entries
    ///
    /// # Panics
    ///
    /// Panics if the bitmap is too small for the requested frame count.
    pub unsafe fn new(
        bitmap: &'static mut [u64],
        first_frame: usize,
        total_frames: usize,
    ) -> Self {
        let required_entries = total_frames.div_ceil(Self::BITS_PER_ENTRY);

        assert!(
            bitmap.len() >= required_entries,
            "Bitmap too small: need {} entries for {} frames, got {}",
            required_entries,
            total_frames,
            bitmap.len()
        );

        // Mark all frames as allocated initially (safe default)
        for entry in bitmap.iter_mut() {
            *entry = !0;
        }

        Self {
            bitmap,
            total_frames,
            free_frames: 0,
            first_frame,
            search_hint: 0,
        }
    }

    /// Convert an absolute frame number to a relative index within this allocator.
    ///
    /// # Panics
    ///
    /// Panics if the frame is below `first_frame`.
    #[inline]
    #[expect(dead_code)]
    fn to_relative(&self, frame: usize) -> usize {
        assert!(
            frame >= self.first_frame,
            "Frame {} is below first_frame {}",
            frame,
            self.first_frame
        );
        frame - self.first_frame
    }

    /// Check if a relative frame index is within bounds.
    #[inline]
    #[expect(dead_code)]
    fn is_valid_relative(&self, relative: usize) -> bool {
        relative < self.total_frames
    }

    /// Get the bitmap entry and bit position for a relative frame index.
    #[inline]
    fn bitmap_pos(&self, relative: usize) -> (usize, usize) {
        (relative / Self::BITS_PER_ENTRY, relative % Self::BITS_PER_ENTRY)
    }

    /// Check if a relative frame is free.
    #[inline]
    fn is_frame_free(&self, relative: usize) -> bool {
        let (entry, bit) = self.bitmap_pos(relative);
        (self.bitmap[entry] >> bit) & 1 == 0
    }

    /// Mark a range of frames as free.
    ///
    /// # Arguments
    ///
    /// * `start_frame` - Absolute frame number to start freeing
    /// * `count` - Number of frames to free
    ///
    /// # Returns
    ///
    /// `Ok(freed_count)` - Number of frames actually freed (excludes already-free frames)
    /// `Err(FrameAllocError)` - If the range is invalid
    pub fn free_range(&mut self, start_frame: usize, count: usize) -> Result<usize, FrameAllocError> {
        if count == 0 {
            return Ok(0);
        }

        // Validate bounds
        if start_frame < self.first_frame {
            return Err(FrameAllocError::OutOfBounds {
                requested_start: start_frame,
                requested_end: start_frame + count,
                valid_start: self.first_frame,
                valid_end: self.first_frame + self.total_frames,
            });
        }

        let relative_start = start_frame - self.first_frame;
        let relative_end = relative_start + count;

        if relative_end > self.total_frames {
            return Err(FrameAllocError::OutOfBounds {
                requested_start: start_frame,
                requested_end: start_frame + count,
                valid_start: self.first_frame,
                valid_end: self.first_frame + self.total_frames,
            });
        }

        let mut freed = 0;

        for relative in relative_start..relative_end {
            let (entry, bit) = self.bitmap_pos(relative);
            let was_allocated = (self.bitmap[entry] >> bit) & 1 == 1;

            if was_allocated {
                self.bitmap[entry] &= !(1 << bit);
                freed += 1;
            }
        }

        self.free_frames += freed;

        // Update search hint if we freed frames before current hint
        if relative_start < self.search_hint {
            self.search_hint = relative_start;
        }

        Ok(freed)
    }

    /// Mark a range of frames as allocated.
    ///
    /// # Arguments
    ///
    /// * `start_frame` - Absolute frame number to start marking
    /// * `count` - Number of frames to mark allocated
    ///
    /// # Returns
    ///
    /// `Ok(marked_count)` - Number of frames actually marked (excludes already-allocated frames)
    /// `Err(FrameAllocError)` - If the range is invalid
    pub fn mark_allocated(&mut self, start_frame: usize, count: usize) -> Result<usize, FrameAllocError> {
        if count == 0 {
            return Ok(0);
        }

        // Validate bounds
        if start_frame < self.first_frame {
            return Err(FrameAllocError::OutOfBounds {
                requested_start: start_frame,
                requested_end: start_frame + count,
                valid_start: self.first_frame,
                valid_end: self.first_frame + self.total_frames,
            });
        }

        let relative_start = start_frame - self.first_frame;
        let relative_end = relative_start + count;

        if relative_end > self.total_frames {
            return Err(FrameAllocError::OutOfBounds {
                requested_start: start_frame,
                requested_end: start_frame + count,
                valid_start: self.first_frame,
                valid_end: self.first_frame + self.total_frames,
            });
        }

        let mut marked = 0;

        for relative in relative_start..relative_end {
            let (entry, bit) = self.bitmap_pos(relative);
            let was_free = (self.bitmap[entry] >> bit) & 1 == 0;

            if was_free {
                self.bitmap[entry] |= 1 << bit;
                marked += 1;
            }
        }

        // Invariant: free_frames must not underflow
        assert!(
            self.free_frames >= marked,
            "free_frames accounting error: tried to subtract {} from {}",
            marked,
            self.free_frames
        );
        self.free_frames -= marked;

        Ok(marked)
    }

    /// Allocate a single frame.
    ///
    /// The returned frame contains uninitialised/stale data.
    /// Use `alloc_zeroed()` if you need zero-initialised memory.
    #[must_use]
    pub fn alloc(&mut self) -> Option<usize> {
        self.alloc_contiguous(1)
    }

    /// Allocate contiguous frames.
    ///
    /// Uses first-fit with a search hint for improved performance.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of contiguous frames needed
    ///
    /// # Returns
    ///
    /// The absolute frame number of the first frame in the allocated range,
    /// or `None` if allocation failed.
    #[must_use]
    pub fn alloc_contiguous(&mut self, count: usize) -> Option<usize> {
        if count == 0 || self.free_frames < count {
            return None;
        }

        // Start search from hint, then wrap around if needed
        let found = self
            .find_contiguous_run(self.search_hint, self.total_frames, count)
            .or_else(|| self.find_contiguous_run(0, self.search_hint, count));

        if let Some(relative_start) = found {
            // Mark as allocated (this cannot fail since we validated the range)
            let abs_start = self.first_frame + relative_start;
            self.mark_allocated(abs_start, count)
                .expect("internal error: validated range failed to mark");

            // Update hint to after this allocation
            self.search_hint = relative_start + count;
            if self.search_hint >= self.total_frames {
                self.search_hint = 0;
            }

            Some(abs_start)
        } else {
            None
        }
    }

    /// Find a contiguous run of free frames in the given range.
    ///
    /// Returns the relative frame index of the start of the run, or None.
    fn find_contiguous_run(&self, start: usize, end: usize, count: usize) -> Option<usize> {
        if start >= end || count == 0 {
            return None;
        }

        let mut run_start = start;
        let mut run_length = 0;
        let mut frame = start;

        while frame < end {
            let (entry_idx, _) = self.bitmap_pos(frame);

            // Optimization: skip fully-allocated words
            if entry_idx < self.bitmap.len() && self.bitmap[entry_idx] == !0 {
                // Entire word is allocated, skip to next word
                let next_word_start = (entry_idx + 1) * Self::BITS_PER_ENTRY;
                frame = next_word_start.min(end);
                run_length = 0;
                continue;
            }

            if self.is_frame_free(frame) {
                if run_length == 0 {
                    run_start = frame;
                }
                run_length += 1;

                if run_length >= count {
                    return Some(run_start);
                }
            } else {
                run_length = 0;
            }

            frame += 1;
        }

        None
    }

    /// Free a single frame.
    ///
    /// # Panics
    ///
    /// Panics if the frame is out of bounds.
    pub fn free(&mut self, frame: usize) {
        self.free_range(frame, 1)
            .expect("failed to free frame: out of bounds");
    }

    /// Get the number of free frames.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_frames
    }

    /// Get the total number of frames managed.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.total_frames
    }

    /// Get the first frame number managed.
    #[must_use]
    pub fn first_frame(&self) -> usize {
        self.first_frame
    }

    /// Convert frame number to physical address.
    #[must_use]
    pub fn frame_to_phys(&self, frame: usize) -> u64 {
        // Use checked arithmetic to prevent overflow
        frame
            .checked_mul(page::SIZE_4K)
            .expect("frame_to_phys overflow") as u64
    }

    /// Convert physical address to frame number.
    #[must_use]
    pub fn phys_to_frame(&self, phys: u64) -> usize {
        (phys as usize) / page::SIZE_4K
    }

    /// Verify the free_frames invariant by counting actual free bits.
    ///
    /// This is expensive (O(n)) and should only be used for debugging.
    #[cfg(debug_assertions)]
    pub fn verify_invariants(&self) -> bool {
        let mut actual_free = 0;

        for frame in 0..self.total_frames {
            if self.is_frame_free(frame) {
                actual_free += 1;
            }
        }

        actual_free == self.free_frames
    }
}

// -- Global Frame Allocator

/// Global frame allocator instance.
/// Uses IrqSpinMutex to prevent deadlock when ISRs need allocation.
static FRAME_ALLOCATOR: IrqSpinMutex<Option<FrameAllocator>> = IrqSpinMutex::new(None);

/// Guard against double initialisation of the frame allocator
static FRAME_ALLOCATOR_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Information about reserved memory regions that must be marked allocated
#[derive(Debug, Clone, Copy)]
pub struct ReservedRegion {
    /// Physical start address
    pub phys_start: u64,
    /// Size in bytes
    pub size: usize,
    /// Description for logging
    pub name: &'static str,
}

/// Initialise the frame allocator from the memory map using bootloader-provided bitmap.
///
/// # Arguments
///
/// * `memory_map` - Memory map from bootloader
/// * `bitmap_phys` - Physical address of the bitmap (allocated by bootloader)
/// * `bitmap_size` - Size of the bitmap in bytes
/// * `max_phys` - Maximum physical address from memory map
/// * `reserved` - Additional regions to mark as allocated (kernel, page tables, etc.)
///
/// # Safety
///
/// - Must be called exactly once during kernel initialisation
/// - `bitmap_phys` must point to valid, writable memory accessible via direct map
/// - `bitmap_size` must be correct for the allocated bitmap
/// - All `reserved` regions must be valid
///
/// # Panics
///
/// Panics if:
/// - Called more than once
/// - No usable memory regions found
/// - Bitmap is too small for the memory range
pub(super) unsafe fn init_frame_allocator(
    memory_map: &MemoryMap,
    bitmap_phys: u64,
    bitmap_size: usize,
    max_phys: u64,
    reserved: &[ReservedRegion],
) {
    if FRAME_ALLOCATOR_INITIALISED.swap(true, Ordering::SeqCst) {
        panic!("init_frame_allocator() called more than once");
    }

    // Find the total physical memory range from usable regions
    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;

    for region in memory_map.iter() {
        if region.memory_type.is_usable() {
            min_addr = min_addr.min(region.base);
            max_addr = max_addr.max(region.end());
        }
    }

    // Use the bootloader-provided max_phys_addr as the upper bound
    // (it may include non-usable regions we need to track)
    max_addr = max_addr.max(max_phys);

    if min_addr >= max_addr {
        panic!("No usable memory regions found in memory map");
    }

    // Align the range to frame boundaries (conservative: expand the managed range)
    let first_frame = (align_down(min_addr, page::SIZE_4K as u64) as usize) / page::SIZE_4K;
    let last_frame = (align_up(max_addr, page::SIZE_4K as u64) as usize) / page::SIZE_4K;
    let total_frames = last_frame - first_frame;

    log::info!(
        "Frame allocator: frames {:#x}..{:#x} ({} frames, {} MB)",
        first_frame,
        last_frame,
        total_frames,
        (total_frames * page::SIZE_4K) / (1024 * 1024)
    );

    // Access bitmap via direct physical map
    let bitmap_virt = phys_to_virt(bitmap_phys);
    let bitmap_entries = bitmap_size / core::mem::size_of::<u64>();

    // Validate bitmap is large enough for the physical memory range
    let required_entries = total_frames.div_ceil(64); // 64 bits per u64
    let required_bytes = required_entries * core::mem::size_of::<u64>();
    if bitmap_size < required_bytes {
        panic!(
            "Bitmap buffer too small for physical memory: need {} bytes for {} MB, \
             but buffer is only {} bytes",
            required_bytes,
            (total_frames * page::SIZE_4K) / (1024 * 1024),
            bitmap_size
        );
    }

    // SAFETY: Bootloader allocated this bitmap and passed it via BootInfo.
    // We access it via the direct physical map which is set up before kernel entry.
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_virt as *mut u64, bitmap_entries)
    };

    // SAFETY: We've verified this is the first call and bitmap is valid
    let mut allocator = unsafe { FrameAllocator::new(bitmap, first_frame, total_frames) };

    // Free usable memory regions (with proper alignment)
    for region in memory_map.iter() {
        if region.memory_type.is_usable() {
            // Align inward: start up, end down (conservative - don't free partial frames)
            let aligned_start = align_up(region.base, page::SIZE_4K as u64);
            let aligned_end = align_down(region.end(), page::SIZE_4K as u64);

            if aligned_end > aligned_start {
                let start_frame = (aligned_start as usize) / page::SIZE_4K;
                let frame_count = ((aligned_end - aligned_start) as usize) / page::SIZE_4K;

                match allocator.free_range(start_frame, frame_count) {
                    Ok(freed) => {
                        log::debug!(
                            "  Freed {} frames at {:#x}..{:#x}",
                            freed,
                            aligned_start,
                            aligned_end
                        );
                    }
                    Err(e) => {
                        log::warn!("  Failed to free region {:#x}..{:#x}: {:?}",
                            region.base, region.end(), e);
                    }
                }
            }
        }
    }

    // Reserve additional regions (kernel image, page tables, bitmap, heap, etc.)
    for region in reserved {
        let start = align_down(region.phys_start, page::SIZE_4K as u64);
        let end = align_up(region.phys_start + region.size as u64, page::SIZE_4K as u64);
        let start_frame = (start as usize) / page::SIZE_4K;
        let frame_count = ((end - start) as usize) / page::SIZE_4K;

        match allocator.mark_allocated(start_frame, frame_count) {
            Ok(marked) => {
                log::debug!(
                    "  Reserved {} frames for {} at {:#x}..{:#x}",
                    marked,
                    region.name,
                    start,
                    end
                );
            }
            Err(e) => {
                log::warn!(
                    "Failed to reserve {} at {:#x}: {:?}",
                    region.name,
                    region.phys_start,
                    e
                );
            }
        }
    }

    let free_mb = (allocator.free_count() * page::SIZE_4K) / (1024 * 1024);
    let total_mb = (allocator.total_count() * page::SIZE_4K) / (1024 * 1024);
    log::info!(
        "Frame allocator initialised: {} MB free / {} MB total",
        free_mb,
        total_mb
    );

    #[cfg(debug_assertions)]
    {
        assert!(
            allocator.verify_invariants(),
            "Frame allocator invariants violated after initialisation"
        );
    }

    *FRAME_ALLOCATOR.lock() = Some(allocator);
}

/// Allocate a physical frame.
///
/// Returns the physical address of the allocated frame, or `None` if allocation failed.
/// The frame contains uninitialised/stale data.
///
/// This function is interrupt-safe (uses IrqSpinMutex).
#[must_use]
pub fn alloc_frame() -> Option<u64> {
    let mut guard = FRAME_ALLOCATOR.lock();
    guard
        .as_mut()
        .and_then(|alloc| alloc.alloc())
        .map(|frame| {
            frame
                .checked_mul(page::SIZE_4K)
                .expect("frame address overflow") as u64
        })
}

/// Allocate a physical frame and zero its contents.
///
/// Returns the physical address of the allocated frame, or `None` if allocation failed.
/// The frame is guaranteed to contain all zeros.
///
/// This should be used when allocating frames that will be mapped to userspace
/// or otherwise exposed to less-trusted code (capability security boundary).
///
/// This function is interrupt-safe (uses IrqSpinMutex).
#[must_use]
pub fn alloc_frame_zeroed() -> Option<u64> {
    let phys = alloc_frame()?;

    // Zero the frame via direct physical map
    // SAFETY: We just allocated this frame, so we have exclusive access.
    // phys_to_virt will validate the address is in range.
    if let Some(virt) = phys_to_virt_checked(phys) {
        unsafe {
            core::ptr::write_bytes(virt as *mut u8, 0, page::SIZE_4K);
        }
        Some(phys)
    } else {
        // Frame is outside direct map range - this is a serious problem
        // Free the frame and return None
        log::error!(
            "Allocated frame {:#x} is outside direct map range, cannot zero",
            phys
        );
        free_frame(phys);
        None
    }
}

/// Allocate contiguous physical frames.
///
/// Returns the physical address of the first frame, or `None` if allocation failed.
///
/// This function is interrupt-safe (uses IrqSpinMutex).
#[must_use]
pub fn alloc_frames(count: usize) -> Option<u64> {
    let mut guard = FRAME_ALLOCATOR.lock();
    guard
        .as_mut()
        .and_then(|alloc| alloc.alloc_contiguous(count))
        .map(|frame| {
            frame
                .checked_mul(page::SIZE_4K)
                .expect("frame address overflow") as u64
        })
}

/// Allocate contiguous physical frames and zero their contents.
///
/// Returns the physical address of the first frame, or `None` if allocation failed.
///
/// This function is interrupt-safe (uses IrqSpinMutex).
#[must_use]
pub fn alloc_frames_zeroed(count: usize) -> Option<u64> {
    let phys = alloc_frames(count)?;
    let total_size = count * page::SIZE_4K;

    if let Some(virt) = phys_to_virt_checked(phys) {
        // Also verify the end is in range
        if phys_to_virt_checked(phys + total_size as u64 - 1).is_some() {
            unsafe {
                core::ptr::write_bytes(virt as *mut u8, 0, total_size);
            }
            return Some(phys);
        }
    }

    // Frames are outside direct map range
    log::error!(
        "Allocated frames {:#x}..{:#x} are outside direct map range",
        phys,
        phys + total_size as u64
    );
    // Free the frames
    for i in 0..count {
        free_frame(phys + (i * page::SIZE_4K) as u64);
    }
    None
}

/// Free a physical frame.
///
/// This function is interrupt-safe (uses IrqSpinMutex).
///
/// # Panics
///
/// Panics if the frame is out of bounds.
pub fn free_frame(phys_addr: u64) {
    let frame = (phys_addr as usize) / page::SIZE_4K;
    let mut guard = FRAME_ALLOCATOR.lock();
    if let Some(alloc) = guard.as_mut() {
        alloc.free(frame);
    }
}

/// Get memory statistics.
///
/// Returns (free_bytes, total_bytes).
///
/// This function is interrupt-safe (uses IrqSpinMutex).
#[must_use]
pub fn memory_stats() -> (usize, usize) {
    let guard = FRAME_ALLOCATOR.lock();
    if let Some(alloc) = guard.as_ref() {
        (
            alloc.free_count() * page::SIZE_4K,
            alloc.total_count() * page::SIZE_4K,
        )
    } else {
        (0, 0)
    }
}
