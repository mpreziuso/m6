//! Runtime support for m6-system binaries
//!
//! Provides panic handler and global allocator for system components.

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use m6_cap::ObjectType;
use m6_syscall::invoke::{debug_putc, sched_yield};

// -- Panic handler

/// Panic handler for m6-system programs.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Print "PANIC: " prefix
    for c in b"PANIC: " {
        debug_putc(*c);
    }

    // Print location if available
    if let Some(location) = info.location() {
        for c in location.file().bytes() {
            debug_putc(c);
        }
        debug_putc(b':');
        print_u32(location.line());
        debug_putc(b' ');
    }

    // Print the message if available
    if let Some(message) = info.message().as_str() {
        for c in message.bytes() {
            debug_putc(c);
        }
    } else {
        for c in b"<no message>" {
            debug_putc(*c);
        }
    }

    debug_putc(b'\n');

    loop {
        sched_yield();
    }
}

fn print_u32(mut n: u32) {
    if n == 0 {
        debug_putc(b'0');
        return;
    }

    let mut digits = [0u8; 10];
    let mut i = 0;

    while n > 0 {
        digits[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        debug_putc(digits[i]);
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        debug_putc(b'0');
        return;
    }

    let mut digits = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        digits[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        debug_putc(digits[i]);
    }
}

fn print_error(e: m6_syscall::error::SyscallError) {
    // Print the error name
    for c in e.name().bytes() {
        debug_putc(c);
    }
    debug_putc(b'(');
    // Print numeric value
    let val = e as i64;
    if val < 0 {
        debug_putc(b'-');
        print_u64((-val) as u64);
    } else {
        print_u64(val as u64);
    }
    debug_putc(b')');
}

// -- Global allocator

use m6_alloc::{
    AllocatedPages, AllocatorConfig, M6GlobalAlloc, PagePool, SecretProvider, VmProvider, VmRights,
};

/// CNode radix for capability slots.
#[allow(dead_code)]
const CNODE_RADIX: u8 = 10;

/// Root CNode slot.
#[allow(dead_code)]
const ROOT_CNODE: u64 = 0;

/// Root VSpace slot.
#[allow(dead_code)]
const ROOT_VSPACE: u64 = 2;

/// Untyped memory slot (matches slots::driver::RAM_UNTYPED).
#[allow(dead_code)]
const UNTYPED_SLOT: u64 = 17;

/// First slot for heap frame allocations.
#[allow(dead_code)]
static NEXT_FRAME_SLOT: AtomicU64 = AtomicU64::new(136);

/// Free slot recycling pool. Freed slots are pushed here and popped
/// before bumping NEXT_FRAME_SLOT, preventing CNode exhaustion.
#[allow(dead_code)]
const MAX_FREE_SLOTS: usize = 256;
#[allow(dead_code)]
static FREE_SLOT_POOL: [AtomicU64; MAX_FREE_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_FREE_SLOTS]
};
/// Number of slots in the free pool.
#[allow(dead_code)]
static FREE_SLOT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Try to reclaim a freed slot, or allocate a new one.
#[allow(dead_code)]
fn alloc_slot_range(count: usize) -> u64 {
    // For single-page allocations, try the free pool first
    if count == 1 {
        let idx = FREE_SLOT_COUNT.load(Ordering::Acquire);
        if idx > 0 {
            // Try to pop from the free pool
            let new_idx = idx - 1;
            if FREE_SLOT_COUNT.compare_exchange(idx, new_idx, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                let slot = FREE_SLOT_POOL[new_idx as usize].load(Ordering::Acquire);
                return slot;
            }
        }
    }
    // Fall back to bump allocator
    NEXT_FRAME_SLOT.fetch_add(count as u64, Ordering::SeqCst)
}

/// Return a freed slot to the recycle pool.
#[allow(dead_code)]
fn free_slot(slot: u64) {
    let idx = FREE_SLOT_COUNT.load(Ordering::Acquire);
    if (idx as usize) < MAX_FREE_SLOTS {
        FREE_SLOT_POOL[idx as usize].store(slot, Ordering::Release);
        FREE_SLOT_COUNT.store(idx + 1, Ordering::Release);
    }
    // If pool is full, slot is leaked (acceptable — pool is large enough for normal use)
}

// -- Page tracking for DMA address translation

/// Maximum number of heap pages we can track (256MB of heap / 4KB pages)
const MAX_HEAP_PAGES: usize = 65536;

/// Table mapping (vaddr_page - HEAP_BASE_PAGE) index to slot number.
/// 0 means unmapped. Uses AtomicU16 for safe concurrent access — the
/// allocator may map pages during runtime (not just init).
static PAGE_SLOT_TABLE: [AtomicU16; MAX_HEAP_PAGES] = {
    const ZERO: AtomicU16 = AtomicU16::new(0);
    [ZERO; MAX_HEAP_PAGES]
};

/// Heap base address (must match HEAP_BASE in init_allocator)
const HEAP_BASE_FOR_TRACKING: u64 = 0x4000_0000;

/// Track a page mapping for later physical address lookup.
#[allow(dead_code)]
fn track_page_mapping(vaddr: u64, slot: u64) {
    let page_index = ((vaddr - HEAP_BASE_FOR_TRACKING) / 4096) as usize;
    if page_index < MAX_HEAP_PAGES && slot < 65536 {
        PAGE_SLOT_TABLE[page_index].store(slot as u16, Ordering::Release);
    }
}

/// Get the physical address for a virtual address in the heap region.
///
/// Returns None if the address is not in the tracked heap region or not mapped.
#[allow(dead_code)]
pub fn get_heap_phys_addr(vaddr: u64) -> Option<u64> {
    if vaddr < HEAP_BASE_FOR_TRACKING {
        return None;
    }

    let page_index = ((vaddr - HEAP_BASE_FOR_TRACKING) / 4096) as usize;
    if page_index >= MAX_HEAP_PAGES {
        return None;
    }

    let slot = PAGE_SLOT_TABLE[page_index].load(Ordering::Acquire);
    if slot == 0 {
        return None;
    }

    let frame_cptr = slot_to_cptr(slot as u64);
    match m6_syscall::invoke::frame_get_phys(frame_cptr) {
        Ok(phys) => {
            let page_offset = vaddr & 0xFFF;
            Some(phys as u64 + page_offset)
        }
        Err(_) => None,
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct M6VmError;

#[allow(dead_code)]
struct M6VmProvider;

/// Convert slot number to CPtr for a CNode with CNODE_RADIX bits.
#[inline]
const fn slot_to_cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

impl VmProvider for M6VmProvider {
    type Error = M6VmError;

    fn map_frame(
        &self,
        vaddr: usize,
        frame_cptr: u64,
        _rights: VmRights,
    ) -> Result<(), Self::Error> {
        let vspace_cptr = slot_to_cptr(ROOT_VSPACE);

        // Map with RW permissions, normal memory attributes
        let result = m6_syscall::invoke::map_frame(vspace_cptr, frame_cptr, vaddr as u64, 0b11, 0);

        if result.is_ok() {
            // Track the mapping for physical address lookup (used by DMA HAL)
            // Extract slot from cptr (reverse of slot_to_cptr)
            let slot = frame_cptr >> (64 - CNODE_RADIX);
            track_page_mapping(vaddr as u64, slot);
            Ok(())
        } else {
            // Only log on error
            for c in b"[rt] ERROR: map_frame failed vaddr=" {
                debug_putc(*c);
            }
            print_u64(vaddr as u64);
            for c in b" error=" {
                debug_putc(*c);
            }
            if let Err(e) = result {
                print_error(e);
            }
            debug_putc(b'\n');
            Err(M6VmError)
        }
    }

    fn unmap_frame(&self, _vaddr: usize) -> Result<(), Self::Error> {
        // Note: unmap_frame takes the frame cptr, not vaddr
        // For now, we don't track frame->vaddr mapping, so this is a no-op
        // TODO: Implement proper unmapping
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct M6PoolError;

#[allow(dead_code)]
struct M6PagePool;

impl PagePool for M6PagePool {
    type Error = M6PoolError;

    fn alloc_pages(&self, count: usize) -> Result<AllocatedPages, Self::Error> {
        let cnode_cptr = slot_to_cptr(ROOT_CNODE);
        let untyped_cptr = slot_to_cptr(UNTYPED_SLOT);

        // Allocate a slot for the frame (tries free pool first)
        let slot = alloc_slot_range(count);
        let frame_cptr = slot_to_cptr(slot);

        // Retype untyped into frames at the given slot
        let result = m6_syscall::invoke::retype(
            untyped_cptr,
            ObjectType::Frame as u64,
            12, // size_bits: 4KB
            cnode_cptr,
            slot,
            count as u64,
        );

        if result.is_ok() {
            Ok(AllocatedPages { frame_cptr, count })
        } else {
            // Only log on error
            for c in b"[rt] ERROR: alloc_pages failed slot=" {
                debug_putc(*c);
            }
            print_u64(slot);
            for c in b" count=" {
                debug_putc(*c);
            }
            print_u64(count as u64);
            for c in b" error=" {
                debug_putc(*c);
            }
            if let Err(e) = result {
                print_error(e);
            }
            debug_putc(b'\n');
            Err(M6PoolError)
        }
    }

    fn free_pages(&self, pages: AllocatedPages) -> Result<(), Self::Error> {
        let cnode_cptr = slot_to_cptr(ROOT_CNODE);
        // Extract slot from cptr (reverse of slot_to_cptr)
        let slot = pages.frame_cptr >> (64 - CNODE_RADIX);

        let result = m6_syscall::invoke::cap_delete(cnode_cptr, slot, CNODE_RADIX as u64);
        if result.is_ok() {
            // Recycle freed slot(s) so they can be reused by future allocations
            for i in 0..pages.count as u64 {
                free_slot(slot + i);
            }
            Ok(())
        } else {
            Err(M6PoolError)
        }
    }
}

#[allow(dead_code)]
struct M6SecretProvider {
    secret: u64,
}

impl M6SecretProvider {
    #[allow(dead_code)]
    fn new() -> Self {
        let mut buf = [0u8; 8];
        let _ = m6_syscall::invoke::get_random(&mut buf);
        Self {
            secret: u64::from_ne_bytes(buf),
        }
    }
}

impl SecretProvider for M6SecretProvider {
    fn get_secret(&self) -> u64 {
        self.secret
    }
}

#[global_allocator]
static ALLOCATOR: M6GlobalAlloc = M6GlobalAlloc;

/// Initialise the allocator. Call this early in _start before any heap allocations.
#[allow(dead_code)]
pub fn init_allocator() {
    const HEAP_BASE: usize = 0x4000_0000;
    const HEAP_SIZE: usize = 128 * 1024 * 1024;

    // SAFETY: Called once at program start
    unsafe {
        if let Err(e) = m6_alloc::init(
            M6VmProvider,
            M6PagePool,
            M6SecretProvider::new(),
            AllocatorConfig {
                heap_base: HEAP_BASE,
                heap_size: HEAP_SIZE,
            },
        ) {
            // Only log on error
            for c in b"[rt] ERROR: Allocator init failed: " {
                debug_putc(*c);
            }
            match e {
                m6_alloc::AllocError::OutOfMemory => {
                    for c in b"OutOfMemory\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::MapFailed => {
                    for c in b"MapFailed\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::UnmapFailed => {
                    for c in b"UnmapFailed\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::SideTableFull => {
                    for c in b"SideTableFull\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::NoFreeSpans => {
                    for c in b"NoFreeSpans\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::NotInitialised => {
                    for c in b"NotInitialised\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::AlreadyInitialised => {
                    for c in b"AlreadyInitialised\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::InvalidConfig => {
                    for c in b"InvalidConfig\n" { debug_putc(*c); }
                }
                m6_alloc::AllocError::Poisoned => {
                    for c in b"Poisoned\n" { debug_putc(*c); }
                }
            }
        }
    }
}

