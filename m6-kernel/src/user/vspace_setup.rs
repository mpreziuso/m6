//! VSpace setup for userspace tasks
//!
//! Provides utilities for creating and configuring user address spaces,
//! including loading ELF binaries and setting up initial mappings.

use core::sync::atomic::{AtomicU16, Ordering};

use m6_common::PhysAddr;
use m6_paging::{
    address::{PA, TPA, VA},
    arch::arm64::{mapping, tables::L0Table},
    arch::PgTable,
    permissions::{MemoryType, PtePermissions},
    region::{PhysMemoryRegion, VirtMemoryRegion},
    traits::{MapAttributes, MapError, PageAllocator},
};

use crate::initrd::elf_loader::{ElfLoadError, PagePerms};
use crate::memory::frame::alloc_frame_zeroed;
use crate::memory::translate::phys_to_virt;

use super::layout;

/// Next ASID to assign (0 is reserved for kernel).
static NEXT_ASID: AtomicU16 = AtomicU16::new(1);

/// Error during VSpace setup.
#[derive(Debug)]
pub enum VSpaceSetupError {
    /// Failed to allocate L0 page table.
    L0AllocationFailed,
    /// Failed to allocate page table.
    PageTableAllocationFailed,
    /// Failed to allocate frame for mapping.
    FrameAllocationFailed,
    /// Failed to create page mapping.
    MappingFailed(MapError),
    /// ELF loading failed.
    ElfLoadFailed(ElfLoadError),
    /// Address out of user space bounds.
    AddressOutOfBounds,
}

impl From<MapError> for VSpaceSetupError {
    fn from(e: MapError) -> Self {
        Self::MappingFailed(e)
    }
}

impl From<ElfLoadError> for VSpaceSetupError {
    fn from(e: ElfLoadError) -> Self {
        Self::ElfLoadFailed(e)
    }
}

/// Page allocator that uses the kernel's frame allocator.
pub struct KernelPageAllocator;

impl PageAllocator for KernelPageAllocator {
    fn allocate_table<T>(&mut self) -> Option<TPA<T>> {
        let phys = alloc_frame_zeroed()?;
        Some(TPA::new(phys))
    }
}

/// Create a new user VSpace (L0 page table and ASID).
///
/// Returns the physical address of the L0 table and the assigned ASID.
pub fn create_user_vspace() -> Result<(PhysAddr, u16), VSpaceSetupError> {
    // Allocate L0 table (zeroed)
    let l0_phys = alloc_frame_zeroed().ok_or(VSpaceSetupError::L0AllocationFailed)?;

    // Assign ASID (simple incrementing, wraps at 65535)
    // ASID 0 is reserved for kernel
    let asid = NEXT_ASID.fetch_add(1, Ordering::Relaxed);
    let asid = if asid == 0 {
        NEXT_ASID.fetch_add(1, Ordering::Relaxed)
    } else {
        asid
    };

    log::debug!("Created user VSpace: L0={:#x}, ASID={}", l0_phys, asid);

    Ok((PhysAddr::new(l0_phys), asid))
}

/// Get L0 table wrapper from physical address.
///
/// # Safety
///
/// The physical address must point to a valid L0 page table.
unsafe fn get_l0_table(l0_phys: PhysAddr) -> L0Table {
    // SAFETY: Caller guarantees this is a valid L0 table.
    // We use the paging crate's from_pa which properly constructs the L0Table
    // wrapper with the base pointer set to the virtual address of the table.
    unsafe { L0Table::from_pa(TPA::new(l0_phys.0)) }
}

/// Convert ELF permissions to PTE permissions.
fn elf_perms_to_pte(perms: PagePerms) -> PtePermissions {
    PtePermissions {
        read: perms.read,
        write: perms.write,
        execute: perms.execute,
        user: true,   // User-accessible
        cow: false,   // No copy-on-write
        global: false, // Per-ASID (not global)
    }
}

/// Map a single page into the user VSpace.
fn map_user_page(
    l0: &mut L0Table,
    allocator: &mut KernelPageAllocator,
    phys: u64,
    virt: u64,
    perms: PtePermissions,
) -> Result<(), VSpaceSetupError> {
    let phys_region = PhysMemoryRegion::new(PA::new(phys), 0x1000);
    let virt_region = VirtMemoryRegion::new(VA::new(virt), 0x1000);
    let attrs = MapAttributes::new(phys_region, virt_region, MemoryType::Normal, perms);

    mapping::map_range(l0, attrs, allocator)?;
    Ok(())
}

/// Load an ELF binary into a user VSpace.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
/// * `elf_data` - Raw bytes of the ELF file
///
/// # Returns
///
/// The entry point address on success.
pub fn load_elf_into_vspace(l0_phys: PhysAddr, elf_data: &[u8]) -> Result<u64, VSpaceSetupError> {
    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    let loaded = crate::initrd::elf_loader::load_elf(elf_data, |_phys_ignored, va, perms, data| {
        // Validate address is in user space
        if !layout::is_user_addr(va) {
            return Err(ElfLoadError::InvalidSegment);
        }

        // Allocate a frame for this page
        let frame_phys = alloc_frame_zeroed().ok_or(ElfLoadError::AllocationFailed)?;

        // Copy data into the frame if any
        if !data.is_empty() {
            let frame_virt = phys_to_virt(frame_phys);
            // SAFETY: We just allocated this frame and it's mapped in the direct map.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), frame_virt as *mut u8, data.len());
            }
        }

        // Convert permissions
        let pte_perms = elf_perms_to_pte(perms);

        // Map the page
        map_user_page(&mut l0, &mut allocator, frame_phys, va, pte_perms)
            .map_err(|_| ElfLoadError::MappingFailed)?;

        Ok(())
    })?;

    Ok(loaded.entry)
}

/// Set up the bootstrap stack for the root task.
///
/// Maps a stack region with a guard page below it.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
///
/// # Returns
///
/// The initial stack pointer (top of stack) on success.
pub fn setup_bootstrap_stack(l0_phys: PhysAddr) -> Result<u64, VSpaceSetupError> {
    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    // Note: Guard page at STACK_GUARD_ADDR is NOT mapped (will cause fault on access)

    // Map stack pages (RW, no execute)
    let stack_perms = PtePermissions::rw(true); // user=true

    for i in 0..layout::BOOTSTRAP_STACK_PAGES {
        let frame_phys = alloc_frame_zeroed().ok_or(VSpaceSetupError::FrameAllocationFailed)?;
        let va = layout::STACK_BASE + (i * 0x1000) as u64;

        map_user_page(&mut l0, &mut allocator, frame_phys, va, stack_perms)?;
    }

    log::debug!(
        "Mapped bootstrap stack: {:#x}..{:#x} ({} pages)",
        layout::STACK_BASE,
        layout::STACK_TOP,
        layout::BOOTSTRAP_STACK_PAGES
    );

    Ok(layout::STACK_TOP)
}

/// Map the UserBootInfo page into the user VSpace.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
/// * `boot_info_phys` - Physical address of the UserBootInfo page
///
/// # Returns
///
/// The virtual address of the UserBootInfo page.
pub fn map_user_boot_info(
    l0_phys: PhysAddr,
    boot_info_phys: PhysAddr,
) -> Result<u64, VSpaceSetupError> {
    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    // Map as read-only for user
    let perms = PtePermissions::ro(true); // user=true, read-only

    map_user_page(
        &mut l0,
        &mut allocator,
        boot_info_phys.0,
        layout::USER_BOOT_INFO_ADDR,
        perms,
    )?;

    log::debug!(
        "Mapped UserBootInfo: phys={:#x} -> virt={:#x}",
        boot_info_phys.0,
        layout::USER_BOOT_INFO_ADDR
    );

    Ok(layout::USER_BOOT_INFO_ADDR)
}

/// Set up the complete root task VSpace.
///
/// This is a convenience function that:
/// 1. Creates a new VSpace
/// 2. Loads the ELF binary
/// 3. Sets up the bootstrap stack
/// 4. Maps the UserBootInfo page
///
/// # Arguments
///
/// * `elf_data` - Raw bytes of the init ELF binary
/// * `boot_info_phys` - Physical address of the UserBootInfo page
///
/// # Returns
///
/// A tuple of (L0 physical address, ASID, entry point, stack pointer).
pub fn setup_root_vspace(
    elf_data: &[u8],
    boot_info_phys: PhysAddr,
) -> Result<(PhysAddr, u16, u64, u64), VSpaceSetupError> {
    // Create the VSpace
    let (l0_phys, asid) = create_user_vspace()?;

    // Load ELF
    let entry = load_elf_into_vspace(l0_phys, elf_data)?;

    // Set up stack
    let stack_top = setup_bootstrap_stack(l0_phys)?;

    // Map UserBootInfo
    map_user_boot_info(l0_phys, boot_info_phys)?;

    log::info!(
        "Root VSpace ready: L0={:#x} ASID={} entry={:#x} SP={:#x}",
        l0_phys.0,
        asid,
        entry,
        stack_top
    );

    Ok((l0_phys, asid, entry, stack_top))
}
