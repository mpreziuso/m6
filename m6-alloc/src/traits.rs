//! Trait definitions for runtime-provided backends
//!
//! The allocator is designed to be agnostic to the underlying memory management
//! system. These traits abstract the capability-based VM operations used by M6.

use core::fmt::Debug;

/// Access rights for mapped memory
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmRights {
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Execute permission
    pub execute: bool,
}

impl VmRights {
    /// Read-only access
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-write access
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read-execute access
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// Represents pages allocated from the pool
#[derive(Debug, Clone, Copy)]
pub struct AllocatedPages {
    /// Frame capability pointer for MapFrame syscall
    pub frame_cptr: u64,
    /// Number of pages allocated
    pub count: usize,
}

/// Virtual memory provider trait
///
/// This trait abstracts the VM operations needed by the allocator.
/// In M6, this is implemented using MapFrame/UnmapFrame syscalls
/// with frame capabilities.
pub trait VmProvider {
    /// Error type for VM operations
    type Error: Debug;

    /// Map a frame at the given virtual address
    ///
    /// # Arguments
    /// * `vaddr` - Virtual address to map at (must be page-aligned)
    /// * `frame_cptr` - Frame capability pointer
    /// * `rights` - Access rights for the mapping
    ///
    /// # Returns
    /// Ok(()) on success, Err on failure
    fn map_frame(&self, vaddr: usize, frame_cptr: u64, rights: VmRights)
    -> Result<(), Self::Error>;

    /// Unmap a frame from the given virtual address
    ///
    /// # Arguments
    /// * `vaddr` - Virtual address to unmap (must be page-aligned)
    ///
    /// # Returns
    /// Ok(()) on success, Err on failure
    fn unmap_frame(&self, vaddr: usize) -> Result<(), Self::Error>;
}

/// Page pool trait
///
/// This trait provides access to physical memory pages.
/// In M6, this is implemented using Retype syscall to create
/// Frame capabilities from Untyped memory.
pub trait PagePool {
    /// Error type for pool operations
    type Error: Debug;

    /// Allocate pages from the pool
    ///
    /// # Arguments
    /// * `count` - Number of contiguous pages to allocate
    ///
    /// # Returns
    /// AllocatedPages on success containing the frame capability
    fn alloc_pages(&self, count: usize) -> Result<AllocatedPages, Self::Error>;

    /// Free previously allocated pages
    ///
    /// # Arguments
    /// * `pages` - The allocated pages to free
    ///
    /// # Returns
    /// Ok(()) on success
    fn free_pages(&self, pages: AllocatedPages) -> Result<(), Self::Error>;

    /// Get the page size (typically 4096)
    fn page_size(&self) -> usize {
        crate::config::PAGE_SIZE
    }
}

/// Secret provider trait
///
/// Provides the per-process secret used for freelist pointer encoding.
/// This should be obtained via the GetRandom syscall at init time.
pub trait SecretProvider {
    /// Get the encoding secret
    ///
    /// This value is used to XOR freelist pointers for hardening.
    /// It should be unique per process and obtained from a secure
    /// random source.
    fn get_secret(&self) -> u64;
}
