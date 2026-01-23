//! DMA HAL implementation for m6 userspace
//!
//! Implements the `dma_api::Osal` trait for the m6 microkernel userspace.
//! This handles:
//! - DMA memory allocation via syscalls
//! - Virtual to physical address translation (via IOVA mapping)
//! - Cache maintenance operations for non-coherent platforms (RK3588)

use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use dma_api::{Direction, Osal};
use m6_syscall::invoke;

use crate::io;

/// Page size constant
const PAGE_SIZE: usize = 4096;

/// DMA region tracking
///
/// On m6, we pre-allocate DMA buffer frames from device-mgr and map them
/// into both the driver's VSpace and IOSpace. The IOVA serves as the
/// "physical" address from the device's perspective.
///
/// This HAL maintains a simple mapping between virtual addresses (in the
/// driver's address space) and IOVAs (device-visible addresses).
pub struct M6DmaHal {
    /// Base virtual address of DMA region
    vaddr_base: u64,
    /// Base IOVA (device-visible address)
    iova_base: u64,
    /// Size of the DMA region in bytes
    region_size: usize,
    /// Next allocation offset
    alloc_offset: AtomicU64,
}

impl M6DmaHal {
    /// Create a new DMA HAL instance.
    ///
    /// # Arguments
    ///
    /// * `vaddr_base` - Base virtual address of pre-mapped DMA region
    /// * `iova_base` - Base IOVA of the region
    /// * `region_size` - Total size of the DMA region
    pub const fn new(vaddr_base: u64, iova_base: u64, region_size: usize) -> Self {
        Self {
            vaddr_base,
            iova_base,
            region_size,
            alloc_offset: AtomicU64::new(0),
        }
    }

    /// Convert virtual address to IOVA.
    #[inline]
    fn vaddr_to_iova(&self, vaddr: u64) -> Option<u64> {
        if vaddr >= self.vaddr_base && vaddr < self.vaddr_base + self.region_size as u64 {
            Some(self.iova_base + (vaddr - self.vaddr_base))
        } else {
            None
        }
    }

    /// Convert IOVA to virtual address.
    #[inline]
    fn iova_to_vaddr(&self, iova: u64) -> Option<u64> {
        if iova >= self.iova_base && iova < self.iova_base + self.region_size as u64 {
            Some(self.vaddr_base + (iova - self.iova_base))
        } else {
            None
        }
    }

    /// Allocate from the DMA region.
    ///
    /// Returns (virtual_address, iova) if successful.
    fn allocate(&self, size: usize, align: usize) -> Option<(u64, u64)> {
        let align = align.max(8); // Minimum 8-byte alignment

        loop {
            let current = self.alloc_offset.load(Ordering::Acquire);
            let aligned_offset = (current as usize + align - 1) & !(align - 1);
            let new_offset = aligned_offset + size;

            if new_offset > self.region_size {
                return None;
            }

            if self
                .alloc_offset
                .compare_exchange_weak(
                    current,
                    new_offset as u64,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let vaddr = self.vaddr_base + aligned_offset as u64;
                let iova = self.iova_base + aligned_offset as u64;
                return Some((vaddr, iova));
            }
        }
    }

    /// Reset allocator (for reuse after driver restart).
    pub fn reset(&self) {
        self.alloc_offset.store(0, Ordering::Release);
    }
}

// -- Global HAL instance

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;

/// Global DMA HAL wrapper with interior mutability.
struct DmaHalCell {
    inner: UnsafeCell<Option<M6DmaHal>>,
    init: AtomicBool,
}

// SAFETY: Single-threaded initialization, then read-only access
unsafe impl Sync for DmaHalCell {}

impl DmaHalCell {
    const fn new() -> Self {
        Self {
            inner: UnsafeCell::new(None),
            init: AtomicBool::new(false),
        }
    }

    /// Initialise the HAL.
    ///
    /// # Safety
    ///
    /// Must only be called once, before any other access.
    unsafe fn init(&self, hal: M6DmaHal) {
        // SAFETY: Single-threaded init, no concurrent access
        unsafe {
            *self.inner.get() = Some(hal);
        }
        self.init.store(true, Ordering::Release);
    }

    fn get(&self) -> &M6DmaHal {
        if !self.init.load(Ordering::Acquire) {
            panic!("DMA HAL not initialised");
        }
        // SAFETY: Initialised and immutable after init
        unsafe { (*self.inner.get()).as_ref().expect("DMA HAL is None") }
    }
}

/// Global DMA HAL instance.
static DMA_HAL: DmaHalCell = DmaHalCell::new();

/// Initialise the global DMA HAL.
///
/// # Safety
///
/// Must be called exactly once during driver initialisation, before any
/// DMA operations.
pub unsafe fn init_dma_hal(vaddr_base: u64, iova_base: u64, region_size: usize) {
    // SAFETY: Called once during single-threaded init
    unsafe {
        DMA_HAL.init(M6DmaHal::new(vaddr_base, iova_base, region_size));
    }
}

/// Get reference to global DMA HAL.
fn get_hal() -> &'static M6DmaHal {
    DMA_HAL.get()
}

// -- dma_api::Osal implementation

/// M6 userspace OSAL for dma-api.
pub struct M6Osal;

impl Osal for M6Osal {
    fn map(&self, addr: NonNull<u8>, _size: usize, _direction: Direction) -> u64 {
        let vaddr = addr.as_ptr() as u64;
        let hal = get_hal();

        // First try the DMA pool region
        if let Some(iova) = hal.vaddr_to_iova(vaddr) {
            return iova;
        }

        // Fall back to heap region lookup
        if let Some(phys) = crate::rt::get_heap_phys_addr(vaddr) {
            return phys;
        }

        io::puts("[usb] ERROR: vaddr_to_iova failed for ");
        io::put_hex(vaddr);
        io::newline();
        0
    }

    fn unmap(&self, _addr: NonNull<u8>, _size: usize) {
        // No-op: we use static mappings
    }

    fn flush(&self, addr: NonNull<u8>, size: usize) {
        // Clean (write back) cache before DMA to device
        let _ = invoke::cache_clean(addr.as_ptr() as u64, size);
    }

    fn invalidate(&self, addr: NonNull<u8>, size: usize) {
        // Invalidate cache after DMA from device
        let _ = invoke::cache_invalidate(addr.as_ptr() as u64, size);
    }

    unsafe fn alloc(&self, _dma_mask: u64, layout: Layout) -> *mut u8 {
        let hal = get_hal();
        let size = layout.size().max(layout.align());

        if let Some((vaddr, _iova)) = hal.allocate(size, layout.align()) {
            // Zero the memory
            // SAFETY: vaddr is valid and properly aligned
            unsafe {
                core::ptr::write_bytes(vaddr as *mut u8, 0, size);
            }
            vaddr as *mut u8
        } else {
            io::puts("[usb] ERROR: DMA alloc failed, size=");
            io::put_u64(size as u64);
            io::newline();
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op: we use a bump allocator that doesn't support deallocation
        // The entire region is reset when the driver restarts
    }
}

/// Global OSAL instance for dma-api.
pub static M6_OSAL: M6Osal = M6Osal;

/// Register the m6 OSAL with dma-api.
///
/// # Safety
///
/// Must be called once after `init_dma_hal()` and before any dma-api usage.
pub unsafe fn register_osal() {
    // SAFETY: Called once during init
    dma_api::init(&M6_OSAL);
}
