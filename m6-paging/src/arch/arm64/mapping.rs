//! Greedy page table mapping algorithm
//!
//! Implements an efficient mapping algorithm that:
//! 1. Tries to use the largest possible block size (1GB at L1, 2MB at L2)
//! 2. Falls back to smaller sizes when alignment doesn't permit larger blocks
//! 3. Automatically allocates intermediate tables as needed
//!
//! This approach minimises TLB pressure and page table memory usage.

use super::descriptors::{
    BlockPageMapper, L1Descriptor, L2Descriptor, L3Descriptor, PageTableEntry, TableMapper,
};
use super::tables::{L0Table, L1Table, L2Table, L3Table, PgTable, zero_table};
use crate::address::{PA, TPA, VA};
use crate::region::{PhysMemoryRegion, VirtMemoryRegion};
use crate::traits::{MapAttributes, MapError, PageAllocator};

/// Map a memory region using the greedy algorithm
///
/// This function maps a contiguous physical region to a contiguous virtual
/// region, using the largest possible block sizes for efficiency.
///
/// # Arguments
/// * `l0` - The L0 (root) page table
/// * `attrs` - Mapping attributes (physical/virtual regions, permissions)
/// * `allocator` - Page table allocator for creating intermediate tables
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(MapError)` on failure
///
/// # Algorithm
/// For each page/block in the region:
/// 1. Try to map at L1 (1GB block) if aligned and large enough
/// 2. Otherwise try L2 (2MB block)
/// 3. Fall back to L3 (4KB page)
pub fn map_range<A: PageAllocator>(
    l0: &mut L0Table,
    attrs: MapAttributes,
    allocator: &mut A,
) -> Result<(), MapError> {
    // Validate inputs
    if attrs.phys.size() != attrs.virt.size() {
        return Err(MapError::SizeMismatch);
    }
    if attrs.phys.is_empty() {
        return Ok(()); // Nothing to map
    }
    if !attrs.phys.is_page_aligned() || !attrs.virt.is_page_aligned() {
        return Err(MapError::NotAligned);
    }

    let mut phys = attrs.phys;
    let mut virt = attrs.virt;

    while !virt.is_empty() {
        let va = virt.start();
        let pa = phys.start();

        // Get or create L1 table
        let mut l1 = get_or_create_l1(l0, va, allocator)?;

        // Try 1GB block at L1
        if L1Descriptor::can_map(phys, va) {
            let desc = L1Descriptor::new_mapping(pa, attrs.mem_type, attrs.perms);
            // SAFETY: We've verified alignment and the entry slot
            unsafe { l1.set_desc(va, desc) };

            let pages = 1 << (30 - 12); // 1GB in 4KB pages
            phys = phys.add_pages(pages);
            virt = virt.add_pages(pages);
            continue;
        }

        // Get or create L2 table
        let mut l2 = get_or_create_l2(&mut l1, va, allocator)?;

        // Try 2MB block at L2
        if L2Descriptor::can_map(phys, va) {
            let desc = L2Descriptor::new_mapping(pa, attrs.mem_type, attrs.perms);
            unsafe { l2.set_desc(va, desc) };

            let pages = 1 << (21 - 12); // 2MB in 4KB pages
            phys = phys.add_pages(pages);
            virt = virt.add_pages(pages);
            continue;
        }

        // Fall back to 4KB page at L3
        let mut l3 = get_or_create_l3(&mut l2, va, allocator)?;
        let desc = L3Descriptor::new_mapping(pa, attrs.mem_type, attrs.perms);
        unsafe { l3.set_desc(va, desc) };

        phys = phys.add_pages(1);
        virt = virt.add_pages(1);
    }

    Ok(())
}

/// Get or create an L1 table from L0
fn get_or_create_l1<A: PageAllocator>(
    l0: &mut L0Table,
    va: VA,
    allocator: &mut A,
) -> Result<L1Table, MapError> {
    let desc = l0.get_desc(va);

    // If already a table, return it
    if let Some(pa) = desc.next_table_address() {
        return Ok(unsafe { L1Table::from_pa(pa.cast()) });
    }

    // If valid but not a table, it's an error (L0 only supports tables)
    if desc.is_valid() {
        return Err(MapError::AlreadyMapped);
    }

    // Allocate new L1 table
    let new_pa: TPA<L1Table> = allocator
        .allocate_table()
        .ok_or(MapError::AllocationFailed)?;

    // Zero the new table
    unsafe { zero_table(new_pa.to_untyped().cast()) };

    // Install table descriptor
    let table_desc = <L0Table as PgTable>::Descriptor::new_table(new_pa.to_untyped());
    unsafe { l0.set_desc(va, table_desc) };

    Ok(unsafe { L1Table::from_pa(new_pa) })
}

/// Get or create an L2 table from L1
fn get_or_create_l2<A: PageAllocator>(
    l1: &mut L1Table,
    va: VA,
    allocator: &mut A,
) -> Result<L2Table, MapError> {
    let desc = l1.get_desc(va);

    // If already a table, return it
    if let Some(pa) = desc.next_table_address() {
        return Ok(unsafe { L2Table::from_pa(pa.cast()) });
    }

    // If valid but not a table (i.e., a block), error
    if desc.is_valid() {
        return Err(MapError::AlreadyMapped);
    }

    // Allocate new L2 table
    let new_pa: TPA<L2Table> = allocator
        .allocate_table()
        .ok_or(MapError::AllocationFailed)?;

    // Zero the new table
    unsafe { zero_table(new_pa.to_untyped().cast()) };

    // Install table descriptor
    let table_desc = <L1Table as PgTable>::Descriptor::new_table(new_pa.to_untyped());
    unsafe { l1.set_desc(va, table_desc) };

    Ok(unsafe { L2Table::from_pa(new_pa) })
}

/// Get or create an L3 table from L2
fn get_or_create_l3<A: PageAllocator>(
    l2: &mut L2Table,
    va: VA,
    allocator: &mut A,
) -> Result<L3Table, MapError> {
    let desc = l2.get_desc(va);

    // If already a table, return it
    if let Some(pa) = desc.next_table_address() {
        return Ok(unsafe { L3Table::from_pa(pa.cast()) });
    }

    // If valid but not a table (i.e., a block), error
    if desc.is_valid() {
        return Err(MapError::AlreadyMapped);
    }

    // Allocate new L3 table
    let new_pa: TPA<L3Table> = allocator
        .allocate_table()
        .ok_or(MapError::AllocationFailed)?;

    // Zero the new table
    unsafe { zero_table(new_pa.to_untyped().cast()) };

    // Install table descriptor
    let table_desc = <L2Table as PgTable>::Descriptor::new_table(new_pa.to_untyped());
    unsafe { l2.set_desc(va, table_desc) };

    Ok(unsafe { L3Table::from_pa(new_pa) })
}

/// Map a single 4KB page
///
/// Convenience function for mapping a single page when the full
/// greedy algorithm isn't needed.
pub fn map_page<A: PageAllocator>(
    l0: &mut L0Table,
    pa: PA,
    va: VA,
    attrs: &MapAttributes,
    allocator: &mut A,
) -> Result<(), MapError> {
    if !pa.is_page_aligned() || !va.is_page_aligned() {
        return Err(MapError::NotAligned);
    }

    let mut l1 = get_or_create_l1(l0, va, allocator)?;
    let mut l2 = get_or_create_l2(&mut l1, va, allocator)?;
    let mut l3 = get_or_create_l3(&mut l2, va, allocator)?;

    let desc = l3.get_desc(va);
    if desc.is_valid() {
        return Err(MapError::AlreadyMapped);
    }

    let new_desc = L3Descriptor::new_mapping(pa, attrs.mem_type, attrs.perms);
    unsafe { l3.set_desc(va, new_desc) };

    Ok(())
}

/// Map an identity region (VA = PA)
///
/// Convenience function for creating identity mappings during boot.
pub fn map_identity<A: PageAllocator>(
    l0: &mut L0Table,
    phys: PhysMemoryRegion,
    attrs: &MapAttributes,
    allocator: &mut A,
) -> Result<(), MapError> {
    let virt = VirtMemoryRegion::new(VA::new(phys.start().value()), phys.size());

    map_range(
        l0,
        MapAttributes {
            phys,
            virt,
            mem_type: attrs.mem_type,
            perms: attrs.perms,
        },
        allocator,
    )
}

/// Unmap a virtual address (set entry to invalid)
///
/// # Safety
/// Caller must ensure:
/// - The mapping exists and is not in use
/// - TLB is invalidated after this call
pub unsafe fn unmap_page(l0: &mut L0Table, va: VA) -> Result<(), MapError> {
    if !va.is_page_aligned() {
        return Err(MapError::NotAligned);
    }

    let desc_l0 = l0.get_desc(va);
    let Some(l1_pa) = desc_l0.next_table_address() else {
        return Err(MapError::InvalidAttributes); // Not mapped
    };

    // SAFETY: We just verified this is a valid table address
    let l1 = unsafe { L1Table::from_pa(l1_pa.cast()) };
    let desc_l1 = l1.get_desc(va);

    // Check if L1 is a block
    if desc_l1.is_valid() && !desc_l1.is_table() {
        return Err(MapError::InvalidAttributes); // Can't unmap a single page from a block
    }

    let Some(l2_pa) = desc_l1.next_table_address() else {
        return Err(MapError::InvalidAttributes);
    };

    // SAFETY: We just verified this is a valid table address
    let l2 = unsafe { L2Table::from_pa(l2_pa.cast()) };
    let desc_l2 = l2.get_desc(va);

    // Check if L2 is a block
    if desc_l2.is_valid() && !desc_l2.is_table() {
        return Err(MapError::InvalidAttributes);
    }

    let Some(l3_pa) = desc_l2.next_table_address() else {
        return Err(MapError::InvalidAttributes);
    };

    // SAFETY: We just verified this is a valid table address
    let mut l3 = unsafe { L3Table::from_pa(l3_pa.cast()) };
    let desc_l3 = l3.get_desc(va);

    if !desc_l3.is_valid() {
        return Err(MapError::InvalidAttributes);
    }

    // Clear the L3 entry
    // SAFETY: Caller guarantees the mapping is not in use
    unsafe { l3.set_desc(va, L3Descriptor::invalid()) };

    Ok(())
}
