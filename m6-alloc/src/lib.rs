//! M6 Userspace Heap Allocator
//!
//! A hardened heap allocator for the M6 microkernel, designed to integrate
//! with capability-based memory management.
//!
//! # Features
//!
//! - **Segregated size classes**: Small allocations use fixed-size slots
//!   within spans for efficiency
//! - **Encoded freelists**: Pointers are XOR-encoded with a per-process
//!   secret to harden against exploitation
//! - **Double-free detection**: Per-span bitmaps track allocation state
//! - **Large allocation tracking**: Direct-mapped allocations are tracked
//!   in a side table
//!
//! # Optional Features
//!
//! - `quarantine`: Delayed reuse of freed memory
//! - `guard-pages`: Unmapped guard pages after large allocations
//! - `debug-poison`: Memory poisoning patterns
//! - `release-double-free`: Bitmap checks in release builds
//! - `stats`: Statistics collection
//!
//! # Usage
//!
//! ```ignore
//! use m6_alloc::{init, AllocatorConfig, M6GlobalAlloc};
//!
//! #[global_allocator]
//! static ALLOCATOR: M6GlobalAlloc = M6GlobalAlloc;
//!
//! // In your runtime initialisation:
//! unsafe {
//!     init(vm_provider, page_pool, secret_provider, AllocatorConfig {
//!         heap_base: 0x4000_0000,
//!         heap_size: 128 * 1024 * 1024, // 128 MiB
//!     }).expect("failed to initialise allocator");
//! }
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod allocator;
pub mod config;
pub mod error;
pub mod freelist;
pub mod large;
pub mod lock;
pub mod size_class;
pub mod span;
pub mod traits;

#[cfg(feature = "debug-poison")]
pub mod poison;

#[cfg(feature = "quarantine")]
pub mod quarantine;

#[cfg(feature = "stats")]
pub mod stats;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

pub use allocator::{Allocator, AllocatorConfig};
pub use error::{AllocError, FreelistError};
pub use traits::{AllocatedPages, PagePool, SecretProvider, VmProvider, VmRights};

/// Function pointer types for type-erased allocation
type AllocFn = unsafe fn(*const (), Layout) -> *mut u8;
type DeallocFn = unsafe fn(*const (), *mut u8, Layout);

/// Type-erased allocator storage
///
/// We use a fixed-size buffer to store the allocator with type-erased
/// trait objects. This allows the global allocator to work with any
/// implementation of the provider traits.
struct AllocatorStorage {
    /// Whether the allocator is initialised
    initialised: AtomicBool,
    /// Storage for the allocator (type-erased)
    /// The actual allocator is stored as raw bytes and accessed via
    /// function pointers stored during init.
    storage: UnsafeCell<[u8; ALLOCATOR_STORAGE_SIZE]>,
    /// Allocation function pointer
    alloc_fn: UnsafeCell<Option<AllocFn>>,
    /// Deallocation function pointer
    dealloc_fn: UnsafeCell<Option<DeallocFn>>,
    /// Pointer to the allocator within storage
    allocator_ptr: UnsafeCell<*const ()>,
}

/// Size of allocator storage (should be enough for Allocator<V, P, S>)
const ALLOCATOR_STORAGE_SIZE: usize = 4096;

// SAFETY: AllocatorStorage uses atomics and function pointers for synchronisation
unsafe impl Sync for AllocatorStorage {}

impl AllocatorStorage {
    const fn new() -> Self {
        Self {
            initialised: AtomicBool::new(false),
            storage: UnsafeCell::new([0u8; ALLOCATOR_STORAGE_SIZE]),
            alloc_fn: UnsafeCell::new(None),
            dealloc_fn: UnsafeCell::new(None),
            allocator_ptr: UnsafeCell::new(ptr::null()),
        }
    }
}

/// Global allocator storage
static ALLOCATOR_STORAGE: AllocatorStorage = AllocatorStorage::new();

/// Initialisation lock
static INIT_LOCK: lock::RawSpinLock = lock::RawSpinLock::new();

/// Initialise the global allocator
///
/// This function must be called exactly once before any allocations are made.
/// The provided trait implementations must remain valid for the lifetime of
/// the program.
///
/// # Safety
///
/// - Must be called exactly once
/// - The trait implementations must be valid for 'static lifetime
/// - No allocations may occur before this function completes
///
/// # Example
///
/// ```ignore
/// unsafe {
///     m6_alloc::init(vm, pool, secret, AllocatorConfig {
///         heap_base: 0x4000_0000,
///         heap_size: 128 * 1024 * 1024,
///     })?;
/// }
/// ```
pub unsafe fn init<V, P, S>(
    vm: V,
    pool: P,
    secret: S,
    config: AllocatorConfig,
) -> Result<(), AllocError>
where
    V: VmProvider + 'static,
    P: PagePool + 'static,
    S: SecretProvider + 'static,
{
    let _guard = INIT_LOCK.lock();

    if ALLOCATOR_STORAGE.initialised.load(Ordering::Acquire) {
        return Err(AllocError::AlreadyInitialised);
    }

    // Validate configuration
    if config.heap_base == 0 {
        return Err(AllocError::InvalidConfig);
    }
    if config.heap_size < config::PAGE_SIZE {
        return Err(AllocError::InvalidConfig);
    }

    // Check that the allocator fits in storage
    let allocator_size = core::mem::size_of::<Allocator<V, P, S>>();
    let allocator_align = core::mem::align_of::<Allocator<V, P, S>>();

    if allocator_size > ALLOCATOR_STORAGE_SIZE {
        return Err(AllocError::InvalidConfig);
    }

    // Create the allocator
    let allocator = Allocator::new(vm, pool, secret, config);

    // Store in global storage
    // SAFETY: We hold the init lock and haven't initialised yet
    unsafe {
        let storage_ptr = ALLOCATOR_STORAGE.storage.get();

        // Align the pointer
        let base = (*storage_ptr).as_mut_ptr() as usize;
        let aligned = (base + allocator_align - 1) & !(allocator_align - 1);
        let offset = aligned - base;

        if offset + allocator_size > ALLOCATOR_STORAGE_SIZE {
            return Err(AllocError::InvalidConfig);
        }

        let allocator_location = aligned as *mut Allocator<V, P, S>;

        // Write the allocator
        ptr::write(allocator_location, allocator);

        // Store function pointers for type-erased access
        *ALLOCATOR_STORAGE.alloc_fn.get() = Some(alloc_impl::<V, P, S>);
        *ALLOCATOR_STORAGE.dealloc_fn.get() = Some(dealloc_impl::<V, P, S>);
        *ALLOCATOR_STORAGE.allocator_ptr.get() = allocator_location as *const ();
    }

    // Mark as initialised
    ALLOCATOR_STORAGE.initialised.store(true, Ordering::Release);

    Ok(())
}

/// Type-erased allocation implementation
unsafe fn alloc_impl<V, P, S>(allocator_ptr: *const (), layout: Layout) -> *mut u8
where
    V: VmProvider,
    P: PagePool,
    S: SecretProvider,
{
    let allocator = unsafe { &*(allocator_ptr as *const Allocator<V, P, S>) };
    allocator.alloc(layout)
}

/// Type-erased deallocation implementation
unsafe fn dealloc_impl<V, P, S>(allocator_ptr: *const (), ptr: *mut u8, layout: Layout)
where
    V: VmProvider,
    P: PagePool,
    S: SecretProvider,
{
    let allocator = unsafe { &*(allocator_ptr as *const Allocator<V, P, S>) };
    // SAFETY: Caller guarantees ptr was allocated with this allocator
    unsafe {
        allocator.dealloc(ptr, layout);
    }
}

/// Global allocator wrapper
///
/// Use this as the `#[global_allocator]` for your program.
///
/// # Example
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: m6_alloc::M6GlobalAlloc = m6_alloc::M6GlobalAlloc;
/// ```
pub struct M6GlobalAlloc;

unsafe impl GlobalAlloc for M6GlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !ALLOCATOR_STORAGE.initialised.load(Ordering::Acquire) {
            return ptr::null_mut();
        }

        // Handle zero-size allocations per GlobalAlloc spec
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }

        // SAFETY: We checked initialised is true
        unsafe {
            let alloc_fn = (*ALLOCATOR_STORAGE.alloc_fn.get()).unwrap_unchecked();
            let allocator_ptr = *ALLOCATOR_STORAGE.allocator_ptr.get();
            alloc_fn(allocator_ptr, layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ALLOCATOR_STORAGE.initialised.load(Ordering::Acquire) {
            return;
        }

        // Handle zero-size deallocations
        if ptr.is_null() || layout.size() == 0 {
            return;
        }

        // SAFETY: We checked initialised is true
        unsafe {
            let dealloc_fn = (*ALLOCATOR_STORAGE.dealloc_fn.get()).unwrap_unchecked();
            let allocator_ptr = *ALLOCATOR_STORAGE.allocator_ptr.get();
            dealloc_fn(allocator_ptr, ptr, layout)
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Simple implementation: alloc new, copy, free old
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l) => l,
            Err(_) => return ptr::null_mut(),
        };

        // SAFETY: Caller guarantees ptr is valid
        let new_ptr = unsafe { self.alloc(new_layout) };
        if new_ptr.is_null() {
            return ptr::null_mut();
        }

        // Copy old data
        let copy_size = layout.size().min(new_size);
        // SAFETY: Both pointers are valid for copy_size bytes
        unsafe {
            ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }

        new_ptr
    }
}

/// Check if the allocator is initialised
pub fn is_initialised() -> bool {
    ALLOCATOR_STORAGE.initialised.load(Ordering::Acquire)
}

#[cfg(feature = "stats")]
/// Get allocator statistics
///
/// Returns None if the allocator is not initialised.
pub fn get_stats() -> Option<stats::AllocatorStats> {
    if !is_initialised() {
        return None;
    }

    // Note: This requires storing the stats accessor during init
    // For now, return None as a placeholder
    None
}
