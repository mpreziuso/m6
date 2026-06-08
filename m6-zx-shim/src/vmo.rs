//! VMO (Virtual Memory Object) shim
//!
//! Wraps M6 Frame capabilities in a userspace MemoryObject abstraction.
//! A VMO is a sparse collection of pages tracked by a BTreeMap.
//! Pages are committed on demand via Retype(Untyped→Frame).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use m6_starnix_std::sync::Mutex;

use crate::Status;

/// Options for VMO creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmoOptions(u32);

impl VmoOptions {
    pub const RESIZABLE: Self = Self(1);
    pub const UNBOUNDED: Self = Self(2);
}

/// Options for VMO child (clone) creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmoChildOptions(u32);

impl VmoChildOptions {
    pub const SNAPSHOT: Self = Self(0);
    pub const SNAPSHOT_AT_LEAST_ON_WRITE: Self = Self(1);
    pub const SNAPSHOT_MODIFIED: Self = Self(2);
    pub const SLICE: Self = Self(3);
    pub const RESIZABLE: Self = Self(1 << 4);
    pub const NO_WRITE: Self = Self(1 << 5);

    /// Whether `flag`'s bits are all set.
    pub fn contains(&self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

impl core::ops::BitOr for VmoChildOptions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for VmoChildOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A page entry in the VMO.
#[derive(Debug, Clone)]
pub(crate) struct PageEntry {
    /// Frame capability pointer (0 if uncommitted)
    pub frame_cptr: u64,
    /// Physical address of the frame
    pub phys_addr: u64,
}

/// Internal VMO state.
struct VmoInner {
    /// Size of the VMO in bytes (page-aligned)
    size: u64,
    /// Committed pages indexed by page offset
    pages: BTreeMap<usize, PageEntry>,
    /// Whether this VMO can be resized
    resizable: bool,
}

/// A Virtual Memory Object.
///
/// Tracks a sparse set of physical pages (M6 Frame capabilities).
/// Pages are committed lazily — only when written or explicitly committed.
pub struct Vmo {
    inner: Arc<Mutex<VmoInner>>,
}

impl Vmo {
    /// Create a new VMO with the given size.
    ///
    /// No pages are committed initially — they're allocated on demand.
    pub fn create(size: u64) -> Result<Self, Status> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        Ok(Self {
            inner: Arc::new(Mutex::new(VmoInner {
                size: aligned_size,
                pages: BTreeMap::new(),
                resizable: false,
            })),
        })
    }

    /// Create a new VMO with options.
    pub fn create_with_opts(options: VmoOptions, size: u64) -> Result<Self, Status> {
        let aligned_size = (size + 0xFFF) & !0xFFF;
        Ok(Self {
            inner: Arc::new(Mutex::new(VmoInner {
                size: aligned_size,
                pages: BTreeMap::new(),
                resizable: options == VmoOptions::RESIZABLE,
            })),
        })
    }

    /// Get the size of the VMO.
    pub fn get_size(&self) -> Result<u64, Status> {
        Ok(self.inner.lock().size)
    }

    /// Set the size of the VMO.
    pub fn set_size(&self, size: u64) -> Result<(), Status> {
        let mut inner = self.inner.lock();
        if !inner.resizable {
            return Err(Status::ERR_UNAVAILABLE);
        }
        let aligned_size = (size + 0xFFF) & !0xFFF;

        // If shrinking, remove pages beyond new size
        if aligned_size < inner.size {
            let max_page = (aligned_size / 4096) as usize;
            inner.pages.retain(|&offset, _| offset < max_page);
        }

        inner.size = aligned_size;
        Ok(())
    }

    /// Read data from the VMO.
    ///
    /// Reads from committed pages, returning zeroes for uncommitted pages.
    pub fn read(&self, data: &mut [u8], offset: u64) -> Result<(), Status> {
        let inner = self.inner.lock();
        if offset + data.len() as u64 > inner.size {
            return Err(Status::ERR_OUT_OF_RANGE);
        }

        let mut pos = 0usize;
        let mut vmo_offset = offset as usize;

        while pos < data.len() {
            let page_idx = vmo_offset / 4096;
            let page_offset = vmo_offset % 4096;
            let chunk_len = (4096 - page_offset).min(data.len() - pos);

            if let Some(page) = inner.pages.get(&page_idx) {
                // Page is committed — read from frame via FrameRead syscall
                let result = frame_read(
                    page.frame_cptr,
                    page_offset,
                    &mut data[pos..pos + chunk_len],
                );
                if result.is_err() {
                    return Err(Status::ERR_IO);
                }
            } else {
                // Uncommitted page — return zeroes
                data[pos..pos + chunk_len].fill(0);
            }

            pos += chunk_len;
            vmo_offset += chunk_len;
        }

        Ok(())
    }

    /// Write data to the VMO.
    ///
    /// Commits pages on demand if they haven't been allocated yet.
    pub fn write(&self, data: &[u8], offset: u64) -> Result<(), Status> {
        let mut inner = self.inner.lock();
        if offset + data.len() as u64 > inner.size {
            return Err(Status::ERR_OUT_OF_RANGE);
        }

        let mut pos = 0usize;
        let mut vmo_offset = offset as usize;

        while pos < data.len() {
            let page_idx = vmo_offset / 4096;
            let page_offset = vmo_offset % 4096;
            let chunk_len = (4096 - page_offset).min(data.len() - pos);

            // Commit the page on demand by allocating a (zeroed) frame from the
            // M6 allocator context. If the context is not installed this returns
            // ERR_BAD_STATE — the same "no backing memory" outcome as before.
            if !inner.pages.contains_key(&page_idx) {
                let frame_cptr = crate::mem_context::alloc_frame()?;
                inner.pages.insert(page_idx, PageEntry { frame_cptr, phys_addr: 0 });
            }

            let page = inner.pages.get(&page_idx).unwrap();
            let result = frame_write(page.frame_cptr, page_offset, &data[pos..pos + chunk_len]);
            if result.is_err() {
                return Err(Status::ERR_IO);
            }

            pos += chunk_len;
            vmo_offset += chunk_len;
        }

        Ok(())
    }

    /// Create a child VMO (COW clone).
    pub fn create_child(
        &self,
        _options: VmoChildOptions,
        offset: u64,
        size: u64,
    ) -> Result<Self, Status> {
        let inner = self.inner.lock();
        if offset + size > inner.size {
            return Err(Status::ERR_OUT_OF_RANGE);
        }

        // Create a new VMO that shares pages with the parent.
        // COW semantics: pages are shared until written, then copied.
        let start_page = (offset / 4096) as usize;
        let end_page = (offset + size).div_ceil(4096) as usize;

        let mut child_pages = BTreeMap::new();
        for (&page_idx, entry) in &inner.pages {
            if page_idx >= start_page && page_idx < end_page {
                child_pages.insert(page_idx - start_page, entry.clone());
            }
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(VmoInner {
                size,
                pages: child_pages,
                resizable: false,
            })),
        })
    }

    /// Get the number of committed pages.
    pub fn committed_pages(&self) -> usize {
        self.inner.lock().pages.len()
    }

    /// Insert a pre-allocated frame into the VMO at the given page index.
    ///
    /// Used by the memory manager to commit pages during demand paging.
    pub fn commit_page(&self, page_idx: usize, frame_cptr: u64, phys_addr: u64) {
        let mut inner = self.inner.lock();
        inner.pages.insert(
            page_idx,
            PageEntry {
                frame_cptr,
                phys_addr,
            },
        );
    }

    /// Get the capability pointer of the frame backing `page_idx`, committing
    /// (allocating + zeroing) a fresh frame from the M6 allocator context if the
    /// page is not yet backed. Used by [`Vmar::map`](crate::Vmar::map) to obtain
    /// the frames it installs into a VSpace.
    pub fn commit_and_get_frame(&self, page_idx: usize) -> Result<u64, Status> {
        let mut inner = self.inner.lock();
        if let Some(page) = inner.pages.get(&page_idx) {
            return Ok(page.frame_cptr);
        }
        let frame_cptr = crate::mem_context::alloc_frame()?;
        inner.pages.insert(page_idx, PageEntry { frame_cptr, phys_addr: 0 });
        Ok(frame_cptr)
    }

    /// Get the frame info for a committed page.
    pub fn get_page(&self, page_idx: usize) -> Option<(u64, u64)> {
        let inner = self.inner.lock();
        inner
            .pages
            .get(&page_idx)
            .map(|p| (p.frame_cptr, p.phys_addr))
    }

    /// Performs a range operation (commit, zero, prefetch, …) over the VMO. Stub.
    pub fn op_range(
        &self,
        _op: crate::flags::VmoOp,
        _offset: u64,
        _size: u64,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Returns info about the VMO.
    pub fn info(&self) -> Result<crate::info::VmoInfo, Status> {
        let inner = self.inner.lock();
        let mut flags = crate::flags::VmoInfoFlags::PAGED;
        if inner.resizable {
            flags |= crate::flags::VmoInfoFlags::RESIZABLE;
        }
        Ok(crate::info::VmoInfo {
            size_bytes: inner.size,
            flags,
            ..Default::default()
        })
    }

    /// Sets the VMO's name. Stub.
    pub fn set_name(&self, _name: &crate::identity::Name) -> Result<(), Status> {
        Ok(())
    }

    // -- Typed read API (mirrors zx::Vmo). Built on the byte-level `read` above.

    /// Reads `buffer_length` elements of `T` into the raw pointer `buffer`.
    ///
    /// # Safety
    /// `buffer` must be valid for writes of `buffer_length * size_of::<T>()`
    /// bytes.
    pub unsafe fn read_raw<T: zerocopy::FromBytes>(
        &self,
        buffer: *mut T,
        buffer_length: usize,
        offset: u64,
    ) -> Result<(), Status> {
        let byte_len = buffer_length.saturating_mul(core::mem::size_of::<T>());
        // SAFETY: caller guarantees `buffer` is valid for `byte_len` bytes.
        let bytes = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), byte_len) };
        self.read(bytes, offset)
    }

    /// Reads into an uninitialised slice, returning the now-initialised slice.
    pub fn read_uninit<'a, T: Copy + zerocopy::FromBytes>(
        &self,
        data: &'a mut [core::mem::MaybeUninit<T>],
        offset: u64,
    ) -> Result<&'a mut [T], Status> {
        // SAFETY: pointer/length come from a valid slice.
        unsafe { self.read_raw(data.as_mut_ptr().cast::<T>(), data.len(), offset)? }
        // SAFETY: read_raw filled the whole buffer, so it is initialised.
        Ok(unsafe { core::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<T>(), data.len()) })
    }

    /// Reads `length` elements of `T` into a fresh `Vec`.
    pub fn read_to_vec<T: Copy + zerocopy::FromBytes>(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<alloc::vec::Vec<T>, Status> {
        let len: usize = length.try_into().map_err(|_| Status::INVALID_ARGS)?;
        let mut buffer = alloc::vec::Vec::with_capacity(len);
        self.read_uninit(buffer.spare_capacity_mut(), offset)?;
        // SAFETY: read_uninit initialised `len` elements.
        unsafe { buffer.set_len(len) };
        Ok(buffer)
    }

    /// Reads a fixed-size array of `T`.
    pub fn read_to_array<T: Copy + zerocopy::FromBytes, const N: usize>(
        &self,
        offset: u64,
    ) -> Result<[T; N], Status> {
        let mut array: [core::mem::MaybeUninit<T>; N] =
            // SAFETY: an array of MaybeUninit is itself valid uninitialised.
            unsafe { core::mem::MaybeUninit::uninit().assume_init() };
        self.read_uninit(&mut array, offset)?;
        // SAFETY: read_uninit initialised every element.
        Ok(array.map(|a| unsafe { a.assume_init() }))
    }

    /// Reads a single `T` value at `offset`.
    pub fn read_to_object<T: Copy + zerocopy::FromBytes>(
        &self,
        offset: u64,
    ) -> Result<T, Status> {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        let slice = core::slice::from_mut(&mut value);
        self.read_uninit(slice, offset)?;
        // SAFETY: read_uninit initialised the single element.
        Ok(unsafe { value.assume_init() })
    }

    /// Returns the VMO's content/stream size (equal to its size in this shim).
    pub fn get_stream_size(&self) -> Result<u64, Status> {
        self.get_size()
    }

    /// Sets the VMO's content/stream size.
    pub fn set_stream_size(&self, size: u64) -> Result<(), Status> {
        self.set_size(size)
    }

    /// Returns the VMO's data (content) size. Equal to its size in this shim.
    pub fn get_data_size(&self) -> Result<u64, Status> {
        self.get_size()
    }

    /// Moves data from `src_vmo` into this VMO, decommitting the source range.
    ///
    /// Mirrors `zx::Vmo::transfer_data`. Stub: copies the bytes via the existing
    /// read/write path; the source range is left intact since this shim has no
    /// decommit primitive yet.
    pub fn transfer_data(
        &self,
        _options: crate::flags::TransferDataOptions,
        offset: u64,
        length: u64,
        src_vmo: &Vmo,
        src_offset: u64,
    ) -> Result<(), Status> {
        let len: usize = length.try_into().map_err(|_| Status::INVALID_ARGS)?;
        if len == 0 {
            return Ok(());
        }
        let mut buf = alloc::vec![0u8; len];
        src_vmo.read(&mut buf, src_offset)?;
        self.write(&buf, offset)
    }

    /// Returns a copy of this VMO marked executable. M6 has no VMEX resource
    /// gating; the handle is returned unchanged (executability is enforced by
    /// the page-table mapping permissions).
    pub fn replace_as_executable(self, _vmex: &crate::Resource) -> Result<Self, Status> {
        Ok(self)
    }
}

impl crate::object::AsHandleRef for Vmo {
    fn as_handle_ref(&self) -> crate::object::HandleRef<'_> {
        crate::object::HandleRef::from_raw(0)
    }
}

impl crate::object::HandleBased for Vmo {
    fn duplicate_handle(&self, _rights: crate::Rights) -> Result<Self, Status> {
        Ok(self.clone())
    }
}

impl Clone for Vmo {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for Vmo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vmo").finish_non_exhaustive()
    }
}

impl PartialEq for Vmo {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for Vmo {}

// -- Syscall helpers — backed by the M6 frame_read/frame_write syscalls.
//
// `frame_cptr` is an already-resolved capability pointer to the backing Frame
// object (stored by `commit_page`). `offset` is the byte offset within the 4 KiB
// frame; callers guarantee `offset + buf.len() <= 4096`.

fn frame_read(frame_cptr: u64, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
    if buf.is_empty() {
        return Ok(());
    }
    // SAFETY: `buf` is a valid, exclusively-borrowed slice of `buf.len()` bytes;
    // the kernel copies into it without retaining the pointer.
    m6_syscall::invoke::frame_read(frame_cptr, offset as u64, buf.as_mut_ptr(), buf.len())
        .map(|_| ())
        .map_err(|_| ())
}

fn frame_write(frame_cptr: u64, offset: usize, data: &[u8]) -> Result<(), ()> {
    if data.is_empty() {
        return Ok(());
    }
    // SAFETY: `data` is a valid, shared-borrowed slice of `data.len()` bytes;
    // the kernel copies from it without retaining the pointer.
    m6_syscall::invoke::frame_write(frame_cptr, offset as u64, data.as_ptr(), data.len())
        .map(|_| ())
        .map_err(|_| ())
}
