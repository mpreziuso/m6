//! VSpace setup for userspace tasks
//!
//! Provides utilities for creating and configuring user address spaces,
//! including loading ELF binaries and setting up initial mappings.

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
use crate::memory::asid::{allocate_asid, AllocatedAsid};
use crate::memory::frame::alloc_frame_zeroed;
use crate::memory::translate::phys_to_virt;

use super::layout;

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
/// Returns the physical address of the L0 table and the allocated ASID
/// (including generation information for TLB management).
pub fn create_user_vspace() -> Result<(PhysAddr, AllocatedAsid), VSpaceSetupError> {
    // Allocate L0 table (zeroed)
    let l0_phys = alloc_frame_zeroed().ok_or(VSpaceSetupError::L0AllocationFailed)?;

    // Allocate ASID from the global allocator (handles generation tracking)
    let asid = allocate_asid();

    log::debug!(
        "Created user VSpace: L0={:#x}, ASID={}, gen={}",
        l0_phys,
        asid.asid,
        asid.generation
    );

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

            // ARM64 cache maintenance: Clean D-cache for executable code
            // This ensures the written data is visible to instruction fetches
            if perms.execute {
                m6_arch::cache::cache_clean_range(frame_virt, data.len());
            }
        }

        // Convert permissions
        let pte_perms = elf_perms_to_pte(perms);

        // Map the page
        map_user_page(&mut l0, &mut allocator, frame_phys, va, pte_perms)
            .map_err(|_| ElfLoadError::MappingFailed)?;

        Ok(())
    })?;

    // ARM64 cache maintenance: Invalidate I-cache globally after loading executable code
    // This ensures all CPUs will fetch fresh instructions from memory, not stale cache lines.
    // CRITICAL for SMP systems to prevent instruction faults on first userspace entry.
    m6_arch::cache::icache_invalidate_all();

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

/// Map the IPC buffer for the root task.
///
/// Allocates a single 4KB frame for the IPC buffer and maps it RW.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
///
/// # Returns
///
/// Tuple of (virtual address, physical address) of the IPC buffer.
pub fn map_ipc_buffer(l0_phys: PhysAddr) -> Result<(u64, PhysAddr), VSpaceSetupError> {
    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    // Allocate a frame for the IPC buffer
    let ipc_buf_phys = alloc_frame_zeroed().ok_or(VSpaceSetupError::FrameAllocationFailed)?;

    // Map as read-write for user
    let perms = PtePermissions::rw(true); // user=true, read-write

    map_user_page(
        &mut l0,
        &mut allocator,
        ipc_buf_phys,
        layout::IPC_BUFFER_BASE,
        perms,
    )?;

    log::debug!(
        "Mapped IPC buffer: phys={:#x} -> virt={:#x}",
        ipc_buf_phys,
        layout::IPC_BUFFER_BASE
    );

    Ok((layout::IPC_BUFFER_BASE, PhysAddr::new(ipc_buf_phys)))
}

/// Map the DTB into the user VSpace (read-only).
///
/// Handles non-page-aligned physical addresses by mapping from the aligned
/// base and returning the virtual address with the correct offset.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
/// * `dtb_phys` - Physical address of the DTB (may not be page-aligned)
/// * `dtb_size` - Size of the DTB in bytes
///
/// # Returns
///
/// The virtual address (including offset) and size of the mapped DTB.
pub fn map_dtb(
    l0_phys: PhysAddr,
    dtb_phys: PhysAddr,
    dtb_size: u64,
) -> Result<(u64, u64), VSpaceSetupError> {
    if dtb_size == 0 || dtb_size > layout::DTB_MAX_SIZE {
        return Ok((0, 0)); // No DTB or too large
    }

    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    // Map as read-only for user
    let perms = PtePermissions::ro(true);

    // Handle non-page-aligned physical addresses
    let page_offset = dtb_phys.0 & 0xFFF;
    let aligned_phys = dtb_phys.0 & !0xFFF;

    // Calculate how many pages we need to cover the entire DTB
    // (accounting for the offset within the first page)
    let total_bytes = page_offset + dtb_size;
    let num_pages = total_bytes.div_ceil(0x1000) as usize;

    for i in 0..num_pages {
        let phys = aligned_phys + (i * 0x1000) as u64;
        let virt = layout::DTB_MAP_ADDR + (i * 0x1000) as u64;
        map_user_page(&mut l0, &mut allocator, phys, virt, perms)?;
    }

    // Return virtual address with offset so userspace can find the actual DTB
    let dtb_vaddr = layout::DTB_MAP_ADDR + page_offset;

    log::debug!(
        "Mapped DTB: phys={:#x} (aligned={:#x}, offset={:#x}) -> virt={:#x} ({} bytes, {} pages)",
        dtb_phys.0,
        aligned_phys,
        page_offset,
        dtb_vaddr,
        dtb_size,
        num_pages
    );

    Ok((dtb_vaddr, dtb_size))
}

/// Map the initrd into the user VSpace (read-only).
///
/// Handles non-page-aligned physical addresses by mapping from the aligned
/// base and returning the virtual address with the correct offset.
///
/// # Arguments
///
/// * `l0_phys` - Physical address of the L0 page table
/// * `initrd_phys` - Physical address of the initrd (may not be page-aligned)
/// * `initrd_size` - Size of the initrd in bytes
///
/// # Returns
///
/// The virtual address (including offset) and size of the mapped initrd.
pub fn map_initrd(
    l0_phys: PhysAddr,
    initrd_phys: PhysAddr,
    initrd_size: u64,
) -> Result<(u64, u64), VSpaceSetupError> {
    if initrd_size == 0 || initrd_size > layout::INITRD_MAX_SIZE {
        return Ok((0, 0)); // No initrd or too large
    }

    // SAFETY: l0_phys was allocated by create_user_vspace.
    let mut l0 = unsafe { get_l0_table(l0_phys) };
    let mut allocator = KernelPageAllocator;

    // Map as read-only for user
    let perms = PtePermissions::ro(true);

    // Handle non-page-aligned physical addresses
    let page_offset = initrd_phys.0 & 0xFFF;
    let aligned_phys = initrd_phys.0 & !0xFFF;

    // Calculate how many pages we need to cover the entire initrd
    // (accounting for the offset within the first page)
    let total_bytes = page_offset + initrd_size;
    let num_pages = total_bytes.div_ceil(0x1000) as usize;

    for i in 0..num_pages {
        let phys = aligned_phys + (i * 0x1000) as u64;
        let virt = layout::INITRD_MAP_ADDR + (i * 0x1000) as u64;
        map_user_page(&mut l0, &mut allocator, phys, virt, perms)?;
    }

    // Return virtual address with offset so userspace can find the actual initrd
    let initrd_vaddr = layout::INITRD_MAP_ADDR + page_offset;

    log::debug!(
        "Mapped initrd: phys={:#x} (aligned={:#x}, offset={:#x}) -> virt={:#x} ({} bytes, {} pages)",
        initrd_phys.0,
        aligned_phys,
        page_offset,
        initrd_vaddr,
        initrd_size,
        num_pages
    );

    Ok((initrd_vaddr, initrd_size))
}

/// Result of setting up the root VSpace.
pub struct RootVSpaceSetup {
    /// Physical address of the L0 page table.
    pub l0_phys: PhysAddr,
    /// Allocated ASID.
    pub asid: AllocatedAsid,
    /// Entry point address.
    pub entry: u64,
    /// Stack top address.
    pub stack_top: u64,
    /// DTB virtual address (0 if not mapped).
    pub dtb_vaddr: u64,
    /// DTB size in bytes.
    pub dtb_size: u64,
    /// Initrd virtual address (0 if not mapped).
    pub initrd_vaddr: u64,
    /// Initrd size in bytes.
    pub initrd_size: u64,
    /// IPC buffer virtual address.
    pub ipc_buffer_vaddr: u64,
    /// IPC buffer physical address.
    pub ipc_buffer_phys: PhysAddr,
}

/// Set up the complete root task VSpace.
///
/// This function:
/// 1. Creates a new VSpace
/// 2. Loads the ELF binary
/// 3. Sets up the bootstrap stack
/// 4. Maps the UserBootInfo page
/// 5. Maps DTB if available
/// 6. Maps initrd if available
///
/// # Arguments
///
/// * `elf_data` - Raw bytes of the init ELF binary
/// * `boot_info_phys` - Physical address of the UserBootInfo page
/// * `dtb_phys` - Physical address of DTB (or 0 if none)
/// * `dtb_size` - Size of DTB in bytes
/// * `initrd_phys` - Physical address of initrd (or 0 if none)
/// * `initrd_size` - Size of initrd in bytes
pub fn setup_root_vspace(
    elf_data: &[u8],
    boot_info_phys: PhysAddr,
    dtb_phys: PhysAddr,
    dtb_size: u64,
    initrd_phys: PhysAddr,
    initrd_size: u64,
) -> Result<RootVSpaceSetup, VSpaceSetupError> {
    // Create the VSpace
    let (l0_phys, asid) = create_user_vspace()?;

    // Load ELF
    let entry = load_elf_into_vspace(l0_phys, elf_data)?;

    // Set up stack
    let stack_top = setup_bootstrap_stack(l0_phys)?;

    // Map UserBootInfo
    map_user_boot_info(l0_phys, boot_info_phys)?;

    // Map DTB if available
    let (dtb_vaddr, dtb_mapped_size) = if dtb_phys.0 != 0 {
        map_dtb(l0_phys, dtb_phys, dtb_size)?
    } else {
        (0, 0)
    };

    // Map initrd if available
    let (initrd_vaddr, initrd_mapped_size) = if initrd_phys.0 != 0 {
        map_initrd(l0_phys, initrd_phys, initrd_size)?
    } else {
        (0, 0)
    };

    // Map IPC buffer for init
    let (ipc_buffer_vaddr, ipc_buffer_phys) = map_ipc_buffer(l0_phys)?;

    log::info!(
        "Root VSpace ready: L0={:#x} ASID={} gen={} entry={:#x} SP={:#x} IPC={:#x}",
        l0_phys.0,
        asid.asid,
        asid.generation,
        entry,
        stack_top,
        ipc_buffer_vaddr,
    );

    Ok(RootVSpaceSetup {
        l0_phys,
        asid,
        entry,
        stack_top,
        dtb_vaddr,
        dtb_size: dtb_mapped_size,
        initrd_vaddr,
        initrd_size: initrd_mapped_size,
        ipc_buffer_vaddr,
        ipc_buffer_phys,
    })
}
