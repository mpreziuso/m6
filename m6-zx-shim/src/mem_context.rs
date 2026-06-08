//! M6 memory allocator context for the VMO/VMAR shim.
//!
//! Zircon VMOs are standalone, page-bearing kernel objects whose pages the
//! kernel allocates on demand. M6 has no such ambient allocator: frames are
//! minted from an *untyped* capability via `retype` into CNode slots, and
//! mapped into a VSpace with `map_frame` (plus `map_page_table` for the
//! intermediate levels). Zircon's `Vmo::create`/`Vmar::map` take no allocator
//! argument, so to back them on M6 the bring-up entry point (`svc_starnix`)
//! installs a process-global context ONCE at startup; the shim then draws frames
//! and CNode slots from it.
//!
//! If the context is not installed (e.g. the native `run_linux_binary` bring-up
//! path, which manages memory itself and never touches the forked `Vmo`/`Vmar`),
//! [`alloc_frame`] returns [`Status::ERR_BAD_STATE`] — exactly the
//! "no backing memory" behaviour the previous stub had, so there is no
//! regression for that path.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use m6_cap::ObjectType;
use m6_starnix_std::sync::Mutex;
use m6_syscall::cptr::slot_to_cptr;
use m6_syscall::invoke;

use crate::Status;

// ARMv8 page-table coverage per level (4 KiB granule).
const L1_SIZE: u64 = 512 * 1024 * 1024 * 1024; // 512 GiB
const L2_SIZE: u64 = 1024 * 1024 * 1024; // 1 GiB
const L3_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB

/// The M6 capability environment the VMO/VMAR shim allocates from.
struct M6MemContext {
    /// CNode slot holding the untyped capability frames are retyped from.
    untyped_slot: u64,
    /// CNode slot of the destination CNode for `retype` (usually the root, 0).
    root_cnode_slot: u64,
    /// CNode slot of the ASID pool (to assign ASIDs to fresh VSpaces).
    asid_pool_slot: u64,
    /// CNode radix used to turn a slot index into a capability pointer.
    cnode_radix: u8,
    /// Next free CNode slot. Grows downward from the top of the CNode so it
    /// does not collide with the m6-std heap pool, which grows upward.
    next_slot: AtomicU64,
    /// Lowest slot this allocator may hand out (below are the caller's fixed
    /// caps and the upward-growing heap pool).
    floor_slot: u64,
}

impl M6MemContext {
    /// Hand out the next CNode slot, descending from the top. Returns
    /// `ERR_NO_MEMORY` once the reserved floor is reached.
    fn alloc_slot(&self) -> Result<u64, Status> {
        let slot = self.next_slot.fetch_sub(1, Ordering::Relaxed);
        if slot < self.floor_slot {
            return Err(Status::ERR_NO_MEMORY);
        }
        Ok(slot)
    }
}

static MEM_CTX: Mutex<Option<M6MemContext>> = Mutex::new(None);

/// Install the process-global allocator context. Call once, before any forked
/// `Vmo`/`Vmar`/process use. `first_free_slot` must not overlap slots the caller
/// still uses for its own capabilities.
pub fn init(
    untyped_slot: u64,
    root_cnode_slot: u64,
    asid_pool_slot: u64,
    cnode_radix: u8,
    first_free_slot: u64,
) {
    // Grow downward from the top slot of the CNode (radix → 1<<radix slots).
    let top_slot = (1u64 << cnode_radix) - 1;
    let mut ctx = MEM_CTX.lock();
    *ctx = Some(M6MemContext {
        untyped_slot,
        root_cnode_slot,
        asid_pool_slot,
        cnode_radix,
        next_slot: AtomicU64::new(top_slot),
        floor_slot: first_free_slot,
    });
}

/// Whether the allocator context has been installed.
pub fn is_initialised() -> bool {
    MEM_CTX.lock().is_some()
}

/// The capability pointer of the destination/root CNode (for `zx::Process`).
pub fn root_cnode_cptr() -> Result<u64, Status> {
    let ctx = MEM_CTX.lock();
    let ctx = ctx.as_ref().ok_or(Status::ERR_BAD_STATE)?;
    Ok(slot_to_cptr(ctx.root_cnode_slot, ctx.cnode_radix))
}

/// Create a fresh VSpace (address space) and assign it an ASID. Returns the
/// VSpace capability pointer — wrap it in `zx::Vmar::new_root` / `zx::Process`.
pub fn create_vspace() -> Result<u64, Status> {
    let ctx = MEM_CTX.lock();
    let ctx = ctx.as_ref().ok_or(Status::ERR_BAD_STATE)?;

    let slot = ctx.alloc_slot()?;
    let untyped_cptr = slot_to_cptr(ctx.untyped_slot, ctx.cnode_radix);
    let dest_cnode_cptr = slot_to_cptr(ctx.root_cnode_slot, ctx.cnode_radix);

    if invoke::retype(untyped_cptr, ObjectType::VSpace as u64, 0, dest_cnode_cptr, slot, 1).is_err()
    {
        return Err(Status::ERR_NO_MEMORY);
    }

    let vspace_cptr = slot_to_cptr(slot, ctx.cnode_radix);
    let asid_pool_cptr = slot_to_cptr(ctx.asid_pool_slot, ctx.cnode_radix);
    if invoke::asid_pool_assign(asid_pool_cptr, vspace_cptr).is_err() {
        return Err(Status::ERR_NO_MEMORY);
    }

    Ok(vspace_cptr)
}

/// Allocate a fresh 4 KiB frame from the untyped pool.
///
/// Returns the frame's capability pointer. The kernel zeroes Frame objects at
/// retype, so uncommitted regions of a committed VMO page read back as zero.
pub fn alloc_frame() -> Result<u64, Status> {
    let ctx = MEM_CTX.lock();
    let ctx = ctx.as_ref().ok_or(Status::ERR_BAD_STATE)?;

    let slot = ctx.alloc_slot()?;
    let untyped_cptr = slot_to_cptr(ctx.untyped_slot, ctx.cnode_radix);
    let dest_cnode_cptr = slot_to_cptr(ctx.root_cnode_slot, ctx.cnode_radix);

    if invoke::retype(
        untyped_cptr,
        ObjectType::Frame as u64,
        12, // 4 KiB
        dest_cnode_cptr,
        slot,
        1,
    )
    .is_err()
    {
        return Err(Status::ERR_NO_MEMORY);
    }

    Ok(slot_to_cptr(slot, ctx.cnode_radix))
}

/// Allocate a fresh page-table object (for `map_page_table`). Returns its cptr.
pub fn alloc_page_table(level: u8) -> Result<u64, Status> {
    let ctx = MEM_CTX.lock();
    let ctx = ctx.as_ref().ok_or(Status::ERR_BAD_STATE)?;

    let obj_type = match level {
        1 => ObjectType::PageTableL1,
        2 => ObjectType::PageTableL2,
        3 => ObjectType::PageTableL3,
        _ => return Err(Status::ERR_INVALID_ARGS),
    };

    let slot = ctx.alloc_slot()?;
    let untyped_cptr = slot_to_cptr(ctx.untyped_slot, ctx.cnode_radix);
    let dest_cnode_cptr = slot_to_cptr(ctx.root_cnode_slot, ctx.cnode_radix);

    if invoke::retype(untyped_cptr, obj_type as u64, 0, dest_cnode_cptr, slot, 1).is_err() {
        return Err(Status::ERR_NO_MEMORY);
    }

    Ok(slot_to_cptr(slot, ctx.cnode_radix))
}

// -- Page-table tracking, keyed by VSpace.
//
// `map_page_table` must be called exactly once per (vspace, level-region); a
// second call for the same region fails. Intermediate page tables are shared by
// every mapping under them and by all VMARs over the same VSpace, so the
// installed set is tracked per VSpace here (not per VMAR).

#[derive(Default)]
struct VspaceTables {
    l1: BTreeSet<u64>,
    l2: BTreeSet<u64>,
    l3: BTreeSet<u64>,
}

static PT_REGISTRY: Mutex<BTreeMap<u64, VspaceTables>> = Mutex::new(BTreeMap::new());

/// Ensure the L1/L2/L3 page tables covering `vaddr` are installed in `vspace_cptr`,
/// allocating and mapping any that are missing. Idempotent per region.
pub fn ensure_page_tables(vspace_cptr: u64, vaddr: u64) -> Result<(), Status> {
    let l1_base = vaddr & !(L1_SIZE - 1);
    let l2_base = vaddr & !(L2_SIZE - 1);
    let l3_base = vaddr & !(L3_SIZE - 1);

    let mut reg = PT_REGISTRY.lock();
    let tables = reg.entry(vspace_cptr).or_default();

    for (base, level) in [(l1_base, 1u8), (l2_base, 2), (l3_base, 3)] {
        let installed = match level {
            1 => &mut tables.l1,
            2 => &mut tables.l2,
            _ => &mut tables.l3,
        };
        if installed.contains(&base) {
            continue;
        }
        let pt_cptr = alloc_page_table(level)?;
        if invoke::map_page_table(vspace_cptr, pt_cptr, base, level as u64).is_err() {
            return Err(Status::ERR_NO_MEMORY);
        }
        installed.insert(base);
    }
    Ok(())
}

/// Map a frame at `vaddr` in `vspace_cptr`, installing intermediate page tables
/// as needed. `rights` is the M6 rights bitmap (R=1, W=2, X=4); `attr` is 0 for
/// normal cacheable memory.
///
/// `overwrite` mirrors Zircon's `SPECIFIC_OVERWRITE`: the page may already carry
/// a translation (e.g. the vvar/vDSO block is first mapped whole via a single
/// `Any` mapping, then partially re-mapped with `FixedOverwrite`). M6's
/// `map_frame` rejects an occupied page with `AlreadyMapped`, so drop any
/// existing leaf translation first.
pub fn map_frame_into(
    vspace_cptr: u64,
    frame_cptr: u64,
    vaddr: u64,
    rights: u64,
    attr: u64,
    overwrite: bool,
) -> Result<(), Status> {
    ensure_page_tables(vspace_cptr, vaddr)?;
    if overwrite {
        // The intermediate page tables stay installed; only the leaf frame is
        // replaced. Ignore the result — the page may legitimately be unmapped.
        let _ = invoke::unmap_frame(vspace_cptr, vaddr);
    }
    if invoke::map_frame(vspace_cptr, frame_cptr, vaddr, rights, attr).is_err() {
        return Err(Status::ERR_NO_MEMORY);
    }
    Ok(())
}

// -- Demand-paging fault registry, keyed by VSpace.
//
// A mapping created *without* `VmarFlags::MAP_RANGE` (the forked core's
// non-populated case — Fuchsia relies on its kernel to fault those pages in) is
// recorded here by [`Vmar::map`](crate::Vmar::map) instead of being committed at
// map time. On a not-present fault, [`commit_fault_page`] looks up the mapping
// covering the faulting address, commits the one backing VMO page and installs
// it into the VSpace. Each entry holds an `Arc` clone of the backing VMO, so the
// pages stay reachable while the mapping is registered.

struct LazyMapping {
    /// Backing VMO (shares pages with the original via its inner `Arc`).
    vmo: crate::Vmo,
    /// Base virtual address of the mapping (page-aligned).
    base: u64,
    /// Byte offset into the VMO corresponding to `base`.
    vmo_offset: u64,
    /// Length of the mapping in bytes (page-aligned).
    len: u64,
    /// M6 rights bitmap (R=1, W=2, X=4) to install the page with.
    rights: u64,
}

// vspace_cptr → (base vaddr → mapping). The inner map is keyed by base so the
// covering mapping for an address is the greatest base ≤ that address.
static LAZY_REGISTRY: Mutex<BTreeMap<u64, BTreeMap<u64, LazyMapping>>> =
    Mutex::new(BTreeMap::new());

/// Register a lazily-mapped region. Pages are committed on first fault by
/// [`commit_fault_page`]; nothing is mapped into the VSpace yet.
pub fn register_lazy_mapping(
    vspace_cptr: u64,
    base: u64,
    vmo: &crate::Vmo,
    vmo_offset: u64,
    len: u64,
    rights: u64,
) {
    let mut reg = LAZY_REGISTRY.lock();
    reg.entry(vspace_cptr).or_default().insert(
        base,
        LazyMapping { vmo: vmo.clone(), base, vmo_offset, len, rights },
    );
}

/// Commit the page covering `fault_vaddr` if it belongs to a registered lazy
/// mapping in `vspace_cptr`.
///
/// Returns `Ok(true)` if the page was committed and installed (the faulting
/// instruction should be retried), `Ok(false)` if no lazy mapping covers the
/// address (the caller should treat it as a genuine fault → SIGSEGV).
pub fn commit_fault_page(vspace_cptr: u64, fault_vaddr: u64) -> Result<bool, Status> {
    let page_vaddr = fault_vaddr & !0xFFF;

    // Resolve the covering mapping and clone out what we need, then drop the
    // registry lock before issuing the commit/map syscalls.
    let (vmo, vmo_page_idx, rights) = {
        let reg = LAZY_REGISTRY.lock();
        let Some(vmaps) = reg.get(&vspace_cptr) else {
            return Ok(false);
        };
        let Some((_, m)) = vmaps.range(..=page_vaddr).next_back() else {
            return Ok(false);
        };
        if page_vaddr >= m.base + m.len {
            return Ok(false);
        }
        let page_in_mapping = (page_vaddr - m.base) / 4096;
        let vmo_page_idx = (m.vmo_offset / 4096 + page_in_mapping) as usize;
        (m.vmo.clone(), vmo_page_idx, m.rights)
    };

    let frame_cptr = vmo.commit_and_get_frame(vmo_page_idx)?;
    map_frame_into(vspace_cptr, frame_cptr, page_vaddr, rights, 0, false)?;
    Ok(true)
}

/// Page-align `len` bytes starting at `addr` to the covering `[start, end)`.
fn page_range(addr: u64, len: u64) -> (u64, u64) {
    (addr & !0xFFF, (addr + len).div_ceil(4096) * 4096)
}

/// Collect the registered mapping bases in `vspace_cptr` whose extent overlaps
/// `[start, end)`.
fn overlapping_bases(vmaps: &BTreeMap<u64, LazyMapping>, start: u64, end: u64) -> Vec<u64> {
    vmaps
        .range(..end)
        .filter(|(_, m)| m.base + m.len > start)
        .map(|(&b, _)| b)
        .collect()
}

/// Drop any lazy mappings overlapping `[addr, addr+len)` from the registry
/// (trimming/splitting partial overlaps) and unmap any pages already faulted in
/// over that range from the VSpace, so a later mapping at the same address faults
/// afresh instead of reusing stale pages. Called from [`Vmar::unmap`](crate::Vmar::unmap).
pub fn unregister_lazy_range(vspace_cptr: u64, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    let (start, end) = page_range(addr, len);

    {
        let mut reg = LAZY_REGISTRY.lock();
        if let Some(vmaps) = reg.get_mut(&vspace_cptr) {
            for base in overlapping_bases(vmaps, start, end) {
                let m = vmaps.remove(&base).expect("base came from this map");
                let m_end = m.base + m.len;
                // Surviving head [m.base, start).
                if m.base < start {
                    vmaps.insert(
                        m.base,
                        LazyMapping {
                            vmo: m.vmo.clone(),
                            base: m.base,
                            vmo_offset: m.vmo_offset,
                            len: start - m.base,
                            rights: m.rights,
                        },
                    );
                }
                // Surviving tail [end, m_end).
                if m_end > end {
                    vmaps.insert(
                        end,
                        LazyMapping {
                            vmo: m.vmo.clone(),
                            base: end,
                            vmo_offset: m.vmo_offset + (end - m.base),
                            len: m_end - end,
                            rights: m.rights,
                        },
                    );
                }
            }
            if vmaps.is_empty() {
                reg.remove(&vspace_cptr);
            }
        }
    }

    // Tear down committed leaf translations in the range. Unmapped pages (the
    // common case — never faulted in) simply error and are ignored.
    let mut page = start;
    while page < end {
        let _ = invoke::unmap_frame(vspace_cptr, page);
        page += 4096;
    }
}

/// Apply `rights` to the part of any lazy mapping(s) overlapping
/// `[addr, addr+len)`: update the registry so future faults install the new
/// permissions (splitting partial overlaps), and re-map pages already faulted in
/// with the new rights. Eager mappings are not tracked here, so protecting one
/// remains a no-op — unchanged from the previous stub. Called from
/// [`Vmar::protect`](crate::Vmar::protect).
pub fn update_lazy_rights(vspace_cptr: u64, addr: u64, len: u64, rights: u64) {
    if len == 0 {
        return;
    }
    let (start, end) = page_range(addr, len);

    let mut to_remap: Vec<(u64, u64)> = Vec::new();
    {
        let mut reg = LAZY_REGISTRY.lock();
        let Some(vmaps) = reg.get_mut(&vspace_cptr) else {
            return;
        };
        for base in overlapping_bases(vmaps, start, end) {
            let m = vmaps.remove(&base).expect("base came from this map");
            let m_end = m.base + m.len;
            let ov_start = m.base.max(start);
            let ov_end = m_end.min(end);

            // Head outside the protected range keeps its old rights.
            if m.base < ov_start {
                vmaps.insert(
                    m.base,
                    LazyMapping {
                        vmo: m.vmo.clone(),
                        base: m.base,
                        vmo_offset: m.vmo_offset,
                        len: ov_start - m.base,
                        rights: m.rights,
                    },
                );
            }
            // Overlap takes the new rights; collect any committed pages to re-map.
            let ov_vmo_offset = m.vmo_offset + (ov_start - m.base);
            let mut p = ov_start;
            while p < ov_end {
                let idx = ((ov_vmo_offset + (p - ov_start)) / 4096) as usize;
                if let Some((frame_cptr, _)) = m.vmo.get_page(idx) {
                    to_remap.push((p, frame_cptr));
                }
                p += 4096;
            }
            vmaps.insert(
                ov_start,
                LazyMapping {
                    vmo: m.vmo.clone(),
                    base: ov_start,
                    vmo_offset: ov_vmo_offset,
                    len: ov_end - ov_start,
                    rights,
                },
            );
            // Tail outside the protected range keeps its old rights.
            if m_end > ov_end {
                vmaps.insert(
                    ov_end,
                    LazyMapping {
                        vmo: m.vmo.clone(),
                        base: ov_end,
                        vmo_offset: m.vmo_offset + (ov_end - m.base),
                        len: m_end - ov_end,
                        rights: m.rights,
                    },
                );
            }
        }
    }

    for (page_vaddr, frame_cptr) in to_remap {
        let _ = map_frame_into(vspace_cptr, frame_cptr, page_vaddr, rights, 0, true);
    }
}
