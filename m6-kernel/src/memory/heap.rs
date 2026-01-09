//! Kernel Heap Allocator
//!
//! Provides dynamic kernel heap management with on-demand growth.

use buddy_system_allocator::LockedHeap;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use m6_arch::registers::ttbr1_base_address;
use m6_common::memory::page;
use m6_paging::arch::arm64::mapping::map_page;
use m6_paging::arch::arm64::tables::{L0Table, PgTable};
use m6_paging::{
    MapAttributes, MemoryType, PageAllocator, PtePermissions, TPA, PA, VA,
    PhysMemoryRegion, VirtMemoryRegion,
};

use super::frame::{alloc_frame_zeroed, free_frame};
use super::layout::virt;
use super::translate::phys_to_virt;

// -- Constants

/// Minimum heap growth increment (1 MB)
const HEAP_GROWTH_INCREMENT: usize = 1024 * 1024;

// -- Global Heap Allocator

/// Guard against double initialisation of the heap
static HEAP_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Global heap allocator using buddy system.
/// Order 32 supports allocations up to 2^32 bytes.
#[global_allocator]
static ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

/// Initialise the kernel heap allocator using bootloader-provided memory.
///
/// # Safety
///
/// Must be called exactly once before any heap allocations.
/// `heap_phys` must point to valid, writable physical memory of at least `size` bytes.
/// The memory must be identity-mappable via the direct physical map.
pub(super) unsafe fn init_heap(heap_phys: u64, size: usize) {
    if HEAP_INITIALISED.swap(true, Ordering::SeqCst) {
        panic!("init_heap() called more than once");
    }

    // Convert to virtual address via direct physical map
    let heap_virt = phys_to_virt(heap_phys);

    // SAFETY: Caller guarantees memory is valid and properly sized.
    unsafe {
        ALLOCATOR.lock().init(heap_virt as usize, size);
    }

    log::info!(
        "Kernel heap initialised: {} KB at virt {:#x} (phys {:#x})",
        size / 1024,
        heap_virt,
        heap_phys
    );
}

// -- Dynamic Kernel Heap

/// Errors that can occur during heap growth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    /// Failed to allocate physical frames
    FrameAllocationFailed,
    /// Failed to map pages into heap VA region
    MappingFailed,
    /// Heap would exceed maximum size
    HeapFull,
    /// Heap not initialised
    NotInitialised,
}

/// Dynamic kernel heap manager
///
/// Tracks committed heap memory and allows growth by allocating
/// physical frames and mapping them into the kernel heap VA region.
pub struct KernelHeap {
    /// Start of kernel heap virtual address region
    heap_start: u64,
    /// Currently committed heap size (atomically updated)
    committed_size: AtomicUsize,
    /// Maximum heap size (256 MB VA reservation)
    max_size: usize,
}

impl KernelHeap {
    /// Create a new kernel heap manager
    pub const fn new(heap_start: u64, max_size: usize) -> Self {
        Self {
            heap_start,
            committed_size: AtomicUsize::new(0),
            max_size,
        }
    }

    /// Get the current committed heap size
    #[inline]
    pub fn committed_size(&self) -> usize {
        self.committed_size.load(Ordering::Relaxed)
    }

    /// Grow the heap by allocating and mapping additional memory
    ///
    /// # Arguments
    /// * `additional` - Minimum bytes to add (will be rounded up to page boundary)
    ///
    /// # Safety
    /// Must not be called concurrently (use external synchronization).
    pub unsafe fn grow(&self, additional: usize) -> Result<usize, HeapError> {
        // Round up to page boundary
        let additional_pages = additional.div_ceil(page::SIZE_4K);
        let additional_aligned = additional_pages * page::SIZE_4K;

        // Check if we'd exceed max size
        let current = self.committed_size.load(Ordering::Acquire);
        let new_size = current.checked_add(additional_aligned).ok_or(HeapError::HeapFull)?;
        if new_size > self.max_size {
            return Err(HeapError::HeapFull);
        }

        // Get the L0 page table from TTBR1
        let ttbr1_phys = ttbr1_base_address();
        let l0_tpa: TPA<L0Table> = TPA::new(ttbr1_phys);
        let mut l0 = unsafe { L0Table::from_pa(l0_tpa) };

        // Create a page allocator for intermediate page tables
        let mut allocator = KernelPageAllocator;

        // Map each new page
        let heap_region_start = self.heap_start + current as u64;
        for i in 0..additional_pages {
            // Allocate a zeroed physical frame
            let phys = alloc_frame_zeroed().ok_or(HeapError::FrameAllocationFailed)?;

            // Calculate virtual address for this page
            let virt = heap_region_start + (i * page::SIZE_4K) as u64;

            // Create mapping attributes
            let attrs = MapAttributes::new(
                PhysMemoryRegion::new(PA::new(phys), page::SIZE_4K),
                VirtMemoryRegion::new(VA::new(virt), page::SIZE_4K),
                MemoryType::Normal,
                PtePermissions::rw(false), // Kernel read-write, not user-accessible
            );

            // Map the page
            if let Err(_e) = map_page(&mut l0, PA::new(phys), VA::new(virt), &attrs, &mut allocator) {
                // Failed to map - free the frame we just allocated
                free_frame(phys);
                return Err(HeapError::MappingFailed);
            }

            // Invalidate TLB for this address
            // SAFETY: We just created this mapping
            unsafe {
                invalidate_tlb_va(virt);
            }
        }

        // Update committed size
        self.committed_size.store(new_size, Ordering::Release);

        // Add the new region to the buddy allocator
        // SAFETY: We just mapped this memory
        unsafe {
            ALLOCATOR.lock().add_to_heap(heap_region_start as usize, heap_region_start as usize + additional_aligned);
        }

        log::info!(
            "Heap grown by {} KB (total: {} KB / {} KB)",
            additional_aligned / 1024,
            new_size / 1024,
            self.max_size / 1024
        );

        Ok(additional_aligned)
    }
}

/// Global kernel heap instance
pub(super) static KERNEL_HEAP: KernelHeap = KernelHeap::new(
    virt::KERNEL_HEAP_START,
    virt::KERNEL_HEAP_VA_SIZE,
);

/// Page allocator that uses the kernel frame allocator
struct KernelPageAllocator;

impl PageAllocator for KernelPageAllocator {
    fn allocate_table<T>(&mut self) -> Option<TPA<T>> {
        let phys = alloc_frame_zeroed()?;
        // SAFETY: phys is a valid physical address of a zeroed page
        Some(TPA::new(phys))
    }
}

/// Invalidate TLB entry for a specific virtual address
///
/// # Safety
/// The caller must ensure this is appropriate for the mapping state.
#[inline]
unsafe fn invalidate_tlb_va(va: u64) {
    // TLBI VAE1IS - TLB Invalidate by VA, EL1, Inner Shareable
    // This invalidates the TLB entry on all cores
    unsafe {
        core::arch::asm!(
            "dsb ishst",           // Ensure stores complete before TLB invalidation
            "tlbi vaae1is, {0}",   // Invalidate by VA, All ASIDs, EL1, Inner Shareable
            "dsb ish",             // Ensure TLB invalidation completes
            "isb",                 // Synchronize instruction stream
            in(reg) va >> 12,      // VA is shifted right by 12 bits for TLBI
            options(nostack, preserves_flags)
        );
    }
}

/// Try to grow the kernel heap
///
/// This is called when the heap allocator fails to satisfy an allocation.
/// Returns the number of bytes added, or an error.
///
/// # Safety
/// Must be called with appropriate synchronization (typically from OOM handler).
pub unsafe fn try_grow_heap(min_size: usize) -> Result<usize, HeapError> {
    // Grow by at least HEAP_GROWTH_INCREMENT or the requested size
    let growth = min_size.max(HEAP_GROWTH_INCREMENT);

    // SAFETY: Caller ensures appropriate synchronization
    unsafe { KERNEL_HEAP.grow(growth) }
}

// -- Out-of-Memory Handler

/// Out-of-memory handler for the global allocator.
///
/// This is called when a heap allocation fails. We attempt to grow the heap
/// dynamically before giving up. Note that the alloc_error_handler cannot
/// retry the allocation - it must diverge. However, we grow the heap so that
/// future allocations have a better chance of succeeding.
#[alloc_error_handler]
fn oom_handler(layout: core::alloc::Layout) -> ! {
    // Calculate how much we need - at least the requested size plus some buffer
    let needed = layout.size().max(HEAP_GROWTH_INCREMENT);

    // Try to grow the heap
    // SAFETY: We're in the OOM handler, which is effectively single-threaded
    // for this allocation path
    match unsafe { try_grow_heap(needed) } {
        Ok(grown) => {
            // We grew the heap, but can't retry from here.
            // Log success and panic - the system should be restarted or
            // the allocation retried at a higher level.
            panic!(
                "Kernel heap OOM: grew heap by {} KB but cannot retry allocation \
                 (size={}, align={}). System may need restart.",
                grown / 1024,
                layout.size(),
                layout.align()
            );
        }
        Err(HeapError::HeapFull) => {
            panic!(
                "Kernel heap exhausted: cannot grow beyond {} KB \
                 (requested size={}, align={})",
                virt::KERNEL_HEAP_VA_SIZE / 1024,
                layout.size(),
                layout.align()
            );
        }
        Err(HeapError::FrameAllocationFailed) => {
            panic!(
                "Kernel heap OOM: no physical memory available for heap growth \
                 (requested size={}, align={})",
                layout.size(),
                layout.align()
            );
        }
        Err(e) => {
            panic!(
                "Kernel heap allocation failed: size={}, align={}, error={:?}",
                layout.size(),
                layout.align(),
                e
            );
        }
    }
}
