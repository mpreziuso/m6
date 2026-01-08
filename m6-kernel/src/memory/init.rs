//! Memory Subsystem Initialization
//!
//! High-level orchestration of frame allocator and heap setup.

use m6_common::boot::{BootInfo, KERNEL_PHYS_MAP_BASE};
use m6_common::memory::page;

use super::frame::{self, ReservedRegion};
use super::heap;

/// Initial kernel heap size (4 MB)
const INITIAL_HEAP_SIZE: usize = 4 * 1024 * 1024;

/// Initialise memory subsystems from boot info.
///
/// This is the main entry point for memory initialisation. It sets up:
/// 1. Dynamic physical map size from boot info
/// 2. Physical frame allocator using bootloader-provided bitmap
/// 3. Kernel heap allocator using freshly allocated frames
///
/// # Safety
///
/// - Must be called exactly once during early kernel initialisation
/// - Must be called before any heap allocations
/// - `boot_info` must be valid and from a trusted bootloader
/// - The kernel must be running with the direct physical map already set up
///
/// # Panics
///
/// Panics if initialisation fails or if called more than once.
pub unsafe fn init_memory_from_boot_info(boot_info: &BootInfo) {
    // Set dynamic physical map size FIRST (needed for phys_to_virt)
    super::set_max_phys_addr(boot_info.max_phys_addr);

    // Configure m6-paging's phys_to_virt offset for page table operations
    // This enables m6-paging to convert physical addresses to virtual addresses
    // when accessing page tables via the direct physical map
    m6_paging::set_phys_to_virt_offset(KERNEL_PHYS_MAP_BASE);

    log::info!(
        "Physical memory: {} MB (max addr {:#x})",
        boot_info.max_phys_addr / (1024 * 1024),
        boot_info.max_phys_addr
    );

    // Build the list of reserved regions
    let reserved = [
        ReservedRegion {
            phys_start: boot_info.kernel_phys_base.0,
            size: boot_info.kernel_size as usize,
            name: "kernel",
        },
        ReservedRegion {
            phys_start: boot_info.page_table_base.0,
            size: boot_info.page_table_size as usize,
            name: "page_tables",
        },
        ReservedRegion {
            phys_start: boot_info.frame_bitmap_phys.0,
            size: boot_info.frame_bitmap_size as usize,
            name: "frame_bitmap",
        },
    ];

    // Initialise the frame allocator with bootloader-provided bitmap
    // SAFETY: Called exactly once, bitmap is from trusted bootloader
    unsafe {
        frame::init_frame_allocator(
            &boot_info.memory_map,
            boot_info.frame_bitmap_phys.0,
            boot_info.frame_bitmap_size as usize,
            boot_info.max_phys_addr,
            &reserved,
        );
    }

    // Allocate frames for initial heap
    let heap_frames = INITIAL_HEAP_SIZE / page::SIZE_4K;
    let heap_phys = frame::alloc_frames_zeroed(heap_frames)
        .expect("Failed to allocate initial kernel heap");

    log::info!(
        "Allocated {} KB for initial heap at phys {:#x}",
        INITIAL_HEAP_SIZE / 1024,
        heap_phys
    );

    // Initialise the heap
    // SAFETY: Called exactly once, heap_phys is freshly allocated zeroed memory
    unsafe {
        heap::init_heap(heap_phys, INITIAL_HEAP_SIZE);
    }

    log::info!("Memory subsystems initialised");
}
