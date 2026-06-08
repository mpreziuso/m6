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
