//! VMAR (Virtual Memory Address Region) shim
//!
//! Maps Zircon VMAR operations to M6 VSpace syscalls.
//! A VMAR represents a region of the virtual address space.

use core::sync::atomic::{AtomicU64, Ordering};

use bitflags::bitflags;

use crate::Status;

bitflags! {
    /// VMAR mapping flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VmarFlags: u32 {
        const PERM_READ = 1 << 0;
        const PERM_WRITE = 1 << 1;
        const PERM_EXECUTE = 1 << 2;
        const COMPACT = 1 << 3;
        const SPECIFIC = 1 << 4;
        const SPECIFIC_OVERWRITE = 1 << 5;
        const CAN_MAP_SPECIFIC = 1 << 6;
        const CAN_MAP_READ = 1 << 7;
        const CAN_MAP_WRITE = 1 << 8;
        const CAN_MAP_EXECUTE = 1 << 9;
        const MAP_RANGE = 1 << 10;
        const REQUIRE_NON_RESIZABLE = 1 << 11;
        const ALLOW_FAULTS = 1 << 12;
        const OFFSET_IS_UPPER_LIMIT = 1 << 13;
        const PERM_READ_IF_XOM_UNSUPPORTED = 1 << 14;
        const FAULT_BEYOND_STREAM_SIZE = 1 << 15;
    }
}

/// A Virtual Memory Address Region.
///
/// In M6, this wraps a VSpace capability and tracks a region within it.
/// All mapping operations delegate to the M6 MapFrame/UnmapFrame syscalls.
pub struct Vmar {
    /// Opaque VMAR handle.
    handle: crate::object::NullableHandle,
    /// VSpace capability pointer
    pub(crate) vspace_cptr: u64,
    /// Base address of this VMAR region
    pub(crate) base: u64,
    /// Size of this VMAR region
    pub(crate) size: u64,
    /// Next free address for sequential allocation (interior-mutable: `map`
    /// takes `&self` to mirror the upstream `zx::Vmar::map` signature).
    next_free: AtomicU64,
}

impl Vmar {
    /// Create a VMAR representing the root of a VSpace.
    pub fn new_root(vspace_cptr: u64) -> Self {
        // Must match Starnix's restricted address space exactly: the forked
        // `MemoryManager::new` asserts the root VMAR covers
        // `[RESTRICTED_ASPACE_BASE, RESTRICTED_ASPACE_HIGHEST_ADDRESS)`
        // (aarch64: `[0x20_0000, 1 << 47)`). These are within M6's 48-bit TTBR0
        // user range.
        // M6 bring-up: 2 GiB top — see the matching note in starnix_uapi
        // `restricted_aspace.rs` (keeps the Linux stack at L1 index 1, the
        // native-proven range). Must equal RESTRICTED_ASPACE_HIGHEST_ADDRESS so
        // MemoryManager::new's assert holds.
        const RESTRICTED_ASPACE_BASE: u64 = 0x0000_0000_0020_0000; // 2 MiB
        const RESTRICTED_ASPACE_TOP: u64 = 1 << 31;
        Self {
            handle: crate::object::NullableHandle::invalid(),
            vspace_cptr,
            base: RESTRICTED_ASPACE_BASE,
            size: RESTRICTED_ASPACE_TOP - RESTRICTED_ASPACE_BASE,
            next_free: AtomicU64::new(RESTRICTED_ASPACE_BASE),
        }
    }

    /// Create a sub-region VMAR.
    pub fn new_sub(vspace_cptr: u64, base: u64, size: u64) -> Self {
        Self {
            handle: crate::object::NullableHandle::invalid(),
            vspace_cptr,
            base,
            size,
            next_free: AtomicU64::new(base),
        }
    }

    /// Map a VMO into this VMAR region.
    ///
    /// Signature mirrors upstream `zx::Vmar::map` (offsets/length in `usize`,
    /// returns the virtual address where the mapping was placed).
    pub fn map(
        &self,
        vmar_offset: usize,
        vmo: &crate::Vmo,
        vmo_offset: u64,
        len: usize,
        flags: VmarFlags,
    ) -> Result<usize, Status> {
        let _ = (vmo, vmo_offset); // Will be used when connected to real syscalls
        let len = len as u64;

        let vaddr = if flags.contains(VmarFlags::SPECIFIC)
            || flags.contains(VmarFlags::SPECIFIC_OVERWRITE)
        {
            let addr = self.base + vmar_offset as u64;
            if addr + len > self.base + self.size {
                return Err(Status::ERR_OUT_OF_RANGE);
            }
            addr
        } else {
            // Sequential allocation
            let aligned = (self.next_free.load(Ordering::Relaxed) + 0xFFF) & !0xFFF;
            if aligned + len > self.base + self.size {
                return Err(Status::ERR_NO_MEMORY);
            }
            self.next_free.store(aligned + len, Ordering::Relaxed);
            aligned
        };

        // Convert VmarFlags to M6 rights bitmap
        let rights = vmar_flags_to_rights(flags);

        // Place the mapping. Only attempted once the M6 allocator context is
        // installed; otherwise the mapping is left address-reserved (the previous
        // behaviour) so the native bring-up path — which never installs the
        // context — is unaffected.
        //
        // Two regimes:
        //   * Eager — commit every page now and install it in this VSpace,
        //     creating intermediate page tables on demand. Used when the caller
        //     asked to populate (`MAP_RANGE`) or placed the mapping at a fixed
        //     address (`SPECIFIC`/`SPECIFIC_OVERWRITE` — ELF segments, the vDSO
        //     block, anything the service may read before the guest faults it).
        //   * Lazy (demand paging) — register the mapping and commit nothing;
        //     `mem_context::commit_fault_page` faults pages in on first access.
        //     This is the non-fixed, non-populated case = anonymous `mmap`.
        if crate::mem_context::is_initialised() {
            let specific = flags.contains(VmarFlags::SPECIFIC)
                || flags.contains(VmarFlags::SPECIFIC_OVERWRITE);
            let eager = flags.contains(VmarFlags::MAP_RANGE) || specific;
            if eager {
                let overwrite = flags.contains(VmarFlags::SPECIFIC_OVERWRITE);
                let n_pages = (len as usize).div_ceil(4096);
                let base_page = (vmo_offset / 4096) as usize;
                for i in 0..n_pages {
                    let frame_cptr = vmo.commit_and_get_frame(base_page + i)?;
                    let page_vaddr = vaddr + (i as u64) * 4096;
                    crate::mem_context::map_frame_into(
                        self.vspace_cptr,
                        frame_cptr,
                        page_vaddr,
                        rights,
                        0,
                        overwrite,
                    )?;
                }
            } else {
                crate::mem_context::register_lazy_mapping(
                    self.vspace_cptr,
                    vaddr,
                    vmo,
                    vmo_offset,
                    len,
                    rights,
                );
            }
        }

        Ok(vaddr as usize)
    }

    /// Unmap a region from this VMAR.
    ///
    /// # Safety
    /// The caller must ensure no live references point into `[addr, addr+len)`.
    pub unsafe fn unmap(&self, addr: usize, len: usize) -> Result<(), Status> {
        let (addr, len) = (addr as u64, len as u64);
        if addr < self.base || addr + len > self.base + self.size {
            return Err(Status::ERR_OUT_OF_RANGE);
        }

        // TODO: Call UnmapFrame for each page in the range
        Ok(())
    }

    /// Change protections on a mapped region.
    ///
    /// # Safety
    /// The caller must ensure the new protection is sound for all live
    /// references into `[addr, addr+len)`.
    pub unsafe fn protect(&self, addr: usize, len: usize, flags: VmarFlags) -> Result<(), Status> {
        let (addr, len) = (addr as u64, len as u64);
        if addr < self.base || addr + len > self.base + self.size {
            return Err(Status::ERR_OUT_OF_RANGE);
        }

        // TODO: Unmap + remap with new rights (BBM sequence)
        let _ = flags;

        Ok(())
    }

    /// Get the base address of this VMAR.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Get the size of this VMAR.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the VSpace capability pointer.
    pub fn vspace_cptr(&self) -> u64 {
        self.vspace_cptr
    }

    /// Returns info about this VMAR (base and length).
    pub fn info(&self) -> Result<crate::info::VmarInfo, Status> {
        Ok(crate::info::VmarInfo {
            base: self.base as usize,
            len: self.size as usize,
        })
    }

    /// Allocates a sub-VMAR. Returns the sub-VMAR and its base address.
    pub fn allocate(
        &self,
        offset: usize,
        size: usize,
        _flags: VmarFlags,
    ) -> Result<(Vmar, usize), Status> {
        let base = self.base + offset as u64;
        if base + size as u64 > self.base + self.size {
            return Err(Status::OUT_OF_RANGE);
        }
        Ok((Vmar::new_sub(self.vspace_cptr, base, size as u64), base as usize))
    }

    /// Destroys this VMAR. Stub.
    pub fn destroy(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Performs a range operation over part of this VMAR. Stub.
    pub fn op_range(
        &self,
        _op: crate::flags::VmarOp,
        _addr: usize,
        _len: usize,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Returns whether the backing handle is invalid.
    pub fn is_invalid(&self) -> bool {
        self.handle.is_invalid()
    }

    /// Wraps the `ZX_INFO_VMAR_MAPS` topic of `zx_object_get_info`.
    ///
    /// Returns an initialised slice of [`MapInfo`]s, any uninitialised trailing
    /// entries, and the total number of infos the kernel had available.
    ///
    /// Stub: M6 does not yet expose address-space map enumeration, so no entries
    /// are produced — the whole buffer is returned as the uninitialised tail and
    /// the available count is zero.
    #[allow(clippy::type_complexity)]
    pub fn maps<'a>(
        &self,
        buf: &'a mut [core::mem::MaybeUninit<crate::info::MapInfo>],
    ) -> Result<
        (
            &'a mut [crate::info::MapInfo],
            &'a mut [core::mem::MaybeUninit<crate::info::MapInfo>],
            usize,
        ),
        Status,
    > {
        Ok((&mut [], buf, 0))
    }

    /// Wraps the `ZX_INFO_VMAR_MAPS` topic of `zx_object_get_info`, returning a
    /// freshly allocated `Vec`.
    ///
    /// Stub: returns an empty `Vec` until map enumeration is wired.
    pub fn maps_vec(&self) -> Result<alloc::vec::Vec<crate::info::MapInfo>, Status> {
        Ok(alloc::vec::Vec::new())
    }
}

impl PartialEq for Vmar {
    fn eq(&self, other: &Self) -> bool {
        // Upstream `zx::Vmar` is a `repr(transparent)` wrapper over a handle and
        // compares by handle identity. Mirror that, also checking the M6 native
        // region descriptors so distinct sub-VMARs over the same VSpace differ.
        self.handle == other.handle
            && self.vspace_cptr == other.vspace_cptr
            && self.base == other.base
            && self.size == other.size
    }
}
impl Eq for Vmar {}

impl From<crate::object::NullableHandle> for Vmar {
    fn from(handle: crate::object::NullableHandle) -> Self {
        Self {
            handle,
            vspace_cptr: 0,
            base: 0,
            size: 0,
            next_free: AtomicU64::new(0),
        }
    }
}

impl crate::object::AsHandleRef for Vmar {
    fn as_handle_ref(&self) -> crate::object::HandleRef<'_> {
        self.handle.as_handle_ref()
    }
    fn raw_handle(&self) -> crate::sys::zx_handle_t {
        self.handle.raw()
    }
}
impl crate::object::HandleBased for Vmar {
    /// A VMAR wraps an M6 VSpace capability pointer plus the region bounds;
    /// "duplicating the handle" yields another reference to the SAME VSpace and
    /// region (used by `MemoryManager::exec`). The default `HandleBased` impl
    /// returns `NOT_SUPPORTED`, which is wrong for the shim's value-type VMAR.
    fn duplicate_handle(&self, _rights: crate::Rights) -> Result<Self, Status> {
        Ok(Self {
            handle: crate::object::NullableHandle::invalid(),
            vspace_cptr: self.vspace_cptr,
            base: self.base,
            size: self.size,
            next_free: AtomicU64::new(self.next_free.load(Ordering::Relaxed)),
        })
    }
}

/// Convert VMAR flags to M6 rights bitmap (R=1, W=2, X=4, COW=8).
fn vmar_flags_to_rights(flags: VmarFlags) -> u64 {
    let mut rights = 1u64; // Always readable
    if flags.contains(VmarFlags::PERM_WRITE) {
        rights |= 2;
    }
    if flags.contains(VmarFlags::PERM_EXECUTE) {
        rights |= 4;
    }
    rights
}
