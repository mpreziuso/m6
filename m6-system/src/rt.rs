//! Runtime support for m6-system binaries
//!
//! Provides panic handler and global allocator for system components.

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Untyped memory slot.
#[allow(dead_code)]
const UNTYPED_SLOT: u64 = 15;

/// First slot for heap frame allocations.
#[allow(dead_code)]
static NEXT_FRAME_SLOT: AtomicU64 = AtomicU64::new(128);

#[derive(Debug)]
#[allow(dead_code)]
struct M6VmError;

#[allow(dead_code)]
struct M6VmProvider;

impl VmProvider for M6VmProvider {
    type Error = M6VmError;

    fn map_frame(
        &self,
        vaddr: usize,
        frame_cptr: u64,
        _rights: VmRights,
    ) -> Result<(), Self::Error> {
        let vspace_cptr = ROOT_VSPACE << (CNODE_RADIX as u64 * 6);

        // Map with RW permissions, normal memory attributes
        let result = m6_syscall::invoke::map_frame(vspace_cptr, frame_cptr, vaddr as u64, 0b11, 0);
        if result.is_ok() {
            Ok(())
        } else {
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
        let cnode_cptr = ROOT_CNODE << (CNODE_RADIX as u64 * 6);
        let untyped_cptr = UNTYPED_SLOT << (CNODE_RADIX as u64 * 6);

        // Allocate a slot for the frame
        let slot = NEXT_FRAME_SLOT.fetch_add(count as u64, Ordering::SeqCst);
        let frame_cptr = slot << (CNODE_RADIX as u64 * 6);

        // Retype untyped into frames at the given slot
        // ObjectType::Frame = 1, size = 12 (4KB)
        let result = m6_syscall::invoke::retype(
            cnode_cptr,
            untyped_cptr,
            1,  // Frame type
            12, // 4KB size
            slot,
            count as u64,
        );

        if result.is_ok() {
            Ok(AllocatedPages { frame_cptr, count })
        } else {
            Err(M6PoolError)
        }
    }

    fn free_pages(&self, pages: AllocatedPages) -> Result<(), Self::Error> {
        let cnode_cptr = ROOT_CNODE << (CNODE_RADIX as u64 * 6);
        // Extract slot from cptr
        let slot = pages.frame_cptr >> (CNODE_RADIX as u64 * 6);

        let result = m6_syscall::invoke::cap_delete(cnode_cptr, slot, CNODE_RADIX as u64);
        if result.is_ok() {
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
        let _ = m6_alloc::init(
            M6VmProvider,
            M6PagePool,
            M6SecretProvider::new(),
            AllocatorConfig {
                heap_base: HEAP_BASE,
                heap_size: HEAP_SIZE,
            },
        );
    }
}
