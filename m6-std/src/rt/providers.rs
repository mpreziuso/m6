//! M6-alloc trait provider implementations
//!
//! Implements the VmProvider, PagePool, and SecretProvider traits for
//! integrating m6-alloc with the M6 microkernel syscall interface.

use core::sync::atomic::{AtomicU64, Ordering};

use m6_alloc::AllocatorConfig;
use m6_alloc::traits::{AllocatedPages, PagePool, SecretProvider, VmProvider, VmRights};
use m6_cap::ObjectType;
use m6_syscall::error::SyscallError;
use m6_syscall::invoke::{get_random, map_frame, retype};

use super::{DEFAULT_HEAP_BASE, DEFAULT_HEAP_SIZE};

/// Virtual memory provider for M6.
///
/// Wraps the MapFrame/UnmapFrame syscalls.
pub struct M6VmProvider {
    /// VSpace capability pointer.
    vspace_cptr: u64,
}

impl M6VmProvider {
    /// Create a new VM provider.
    pub const fn new(vspace_cptr: u64) -> Self {
        Self { vspace_cptr }
    }
}

impl VmProvider for M6VmProvider {
    type Error = SyscallError;

    fn map_frame(
        &self,
        vaddr: usize,
        frame_cptr: u64,
        rights: VmRights,
    ) -> Result<(), Self::Error> {
        // Convert VmRights to M6 rights bits
        let mut rights_bits = 0u64;
        if rights.read {
            rights_bits |= 1; // R
        }
        if rights.write {
            rights_bits |= 2; // W
        }
        // Note: execute permission is inverted (XN bit)
        let attr = if rights.execute { 0 } else { 1 };

        map_frame(
            self.vspace_cptr,
            frame_cptr,
            vaddr as u64,
            rights_bits,
            attr,
        )?;
        Ok(())
    }

    fn unmap_frame(&self, _vaddr: usize) -> Result<(), Self::Error> {
        // Note: UnmapFrame takes the frame cptr, not vaddr
        // For now, we don't track the mapping, so we can't unmap properly
        // This is a limitation that could be addressed with a mapping registry
        // For heap usage, we typically don't unmap individual pages
        Ok(())
    }
}

/// Page pool for M6.
///
/// Allocates Frame capabilities from Untyped memory using Retype syscall.
pub struct M6PagePool {
    /// Untyped capability pointer for allocating frames.
    untyped_cptr: u64,
    /// CNode capability pointer for placing new capabilities.
    cnode_cptr: u64,
    /// CNode radix (number of bits for slot addressing).
    cnode_radix: u8,
    /// Next available slot index.
    next_slot: AtomicU64,
}

impl M6PagePool {
    /// Create a new page pool.
    pub const fn new(untyped_cptr: u64, cnode_cptr: u64, cnode_radix: u8, start_slot: u64) -> Self {
        Self {
            untyped_cptr,
            cnode_cptr,
            cnode_radix,
            next_slot: AtomicU64::new(start_slot),
        }
    }

    /// Convert a slot index to a CPtr.
    fn slot_to_cptr(&self, slot: u64) -> u64 {
        // CPtr format: slot index in lower bits, guard in upper bits
        // For a simple root CNode, the CPtr is just the slot shifted by guard bits
        slot << (64 - self.cnode_radix as u64)
    }
}

impl PagePool for M6PagePool {
    type Error = SyscallError;

    fn alloc_pages(&self, count: usize) -> Result<AllocatedPages, Self::Error> {
        let slot = self.next_slot.fetch_add(count as u64, Ordering::Relaxed);
        let frame_cptr = self.slot_to_cptr(slot);

        // Retype untyped memory into Frame objects
        retype(
            self.untyped_cptr,
            ObjectType::Frame as u64,
            12, // 4KB pages (2^12)
            self.cnode_cptr,
            slot,
            count as u64,
        )?;

        Ok(AllocatedPages { frame_cptr, count })
    }

    fn free_pages(&self, _pages: AllocatedPages) -> Result<(), Self::Error> {
        // Note: In a full implementation, we would delete the frame capability
        // and potentially return memory to the untyped region.
        // For now, pages are not returned (bump allocator style).
        Ok(())
    }
}

/// Secret provider for M6.
///
/// Uses the GetRandom syscall to obtain cryptographic randomness.
pub struct M6SecretProvider {
    /// Cached secret value.
    secret: u64,
}

impl M6SecretProvider {
    /// Create a new secret provider.
    ///
    /// Fetches random bytes from the kernel.
    pub fn new() -> Result<Self, SyscallError> {
        let mut buf = [0u8; 8];
        get_random(&mut buf)?;
        Ok(Self {
            secret: u64::from_le_bytes(buf),
        })
    }
}

impl SecretProvider for M6SecretProvider {
    fn get_secret(&self) -> u64 {
        self.secret
    }
}

/// Initialise the global allocator.
///
/// This function sets up the m6-alloc allocator with providers that use
/// M6 syscalls for memory management.
///
/// # Arguments
///
/// * `boot_info_ptr` - Pointer to boot info (unused for now, will be used
///   to discover untyped memory regions)
///
/// # Safety
///
/// Must be called exactly once before any allocations.
///
/// # Note
///
/// If the process doesn't have the required capabilities (untyped memory),
/// the allocator won't be initialised and heap allocations will panic.
/// This is acceptable for simple processes that don't need heap allocation.
#[cfg(feature = "alloc")]
pub fn init_allocator(_boot_info_ptr: usize) -> Result<(), &'static str> {
    // For now, use fixed capability slots that the init process is expected to have
    // In a full implementation, these would be discovered from boot info

    // TODO: These values should come from boot info or be passed to child processes
    // For now, use reasonable defaults that match the kernel's init setup
    const ROOT_CNODE_CPTR: u64 = 0; // Self-reference at slot 0
    const ROOT_VSPACE_CPTR: u64 = 2 << 52; // Slot 2 with radix 12
    const UNTYPED_CPTR: u64 = 15 << 52; // First untyped at slot 15 with radix 12
    const CNODE_RADIX: u8 = 12; // 4096 slots (matches spawn_process)
    const HEAP_SLOTS_START: u64 = 128; // Start allocating heap frames at slot 128

    // Try to get random - if this fails, we likely don't have proper capabilities
    // In that case, skip allocator init (process can't use heap but can still run)
    let secret_provider = match M6SecretProvider::new() {
        Ok(sp) => sp,
        Err(_) => {
            // No capabilities available - skip allocator init
            // Process can still run but heap allocations will panic
            return Ok(());
        }
    };

    let vm_provider = M6VmProvider::new(ROOT_VSPACE_CPTR);
    let page_pool = M6PagePool::new(UNTYPED_CPTR, ROOT_CNODE_CPTR, CNODE_RADIX, HEAP_SLOTS_START);

    // SAFETY: We ensure this is called exactly once during runtime init
    unsafe {
        m6_alloc::init(
            vm_provider,
            page_pool,
            secret_provider,
            AllocatorConfig {
                heap_base: DEFAULT_HEAP_BASE,
                heap_size: DEFAULT_HEAP_SIZE,
            },
        )
        .map_err(|_| "Failed to initialise allocator")
    }
}
