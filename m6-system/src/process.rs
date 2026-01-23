//! Process spawning
//!
//! Capability-based process creation for userspace.
//! Uses VSpace, TCB, CSpace, and Frame capabilities to create isolated processes.

use m6_cap::ObjectType;
use m6_syscall::{error::SyscallError, invoke::*, slot_to_cptr};

use crate::elf::{Elf64, ElfError};

/// Error codes for process spawning
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// Invalid ELF binary
    InvalidElf(ElfError),
    /// Not enough untyped memory
    OutOfMemory,
    /// Failed to retype untyped memory
    RetypeFailed(SyscallError),
    /// Failed to assign ASID
    AsidAssignFailed(SyscallError),
    /// Failed to configure TCB
    TcbConfigureFailed(SyscallError),
    /// Failed to write TCB registers
    TcbWriteRegistersFailed(SyscallError),
    /// Failed to resume TCB
    TcbResumeFailed(SyscallError),
    /// Failed to map frame
    FrameMapFailed(SyscallError),
    /// Failed to map page table
    PageTableMapFailed(SyscallError),
    /// Failed to copy capability
    CapCopyFailed(SyscallError),
    /// Invalid address (not page aligned)
    InvalidAddress,
    /// No free capability slots
    NoSlots,
}

impl From<ElfError> for SpawnError {
    fn from(e: ElfError) -> Self {
        Self::InvalidElf(e)
    }
}

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Memory mapping rights
#[derive(Debug, Clone, Copy)]
pub struct MapRights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MapRights {
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// Convert to syscall rights bitmap (R=1, W=2, X=4)
    pub fn to_bits(self) -> u64 {
        let mut bits = 0u64;
        if self.read {
            bits |= 1;
        }
        if self.write {
            bits |= 2;
        }
        if self.execute {
            bits |= 4;
        }
        bits
    }
}

/// Initial capability to grant to spawned process
#[derive(Debug, Clone, Copy)]
pub struct InitialCap {
    /// Source capability slot
    pub src_slot: u64,
    /// Destination slot in child's CSpace
    pub dst_slot: u64,
}

/// Configuration for spawning a process
pub struct SpawnConfig<'a> {
    /// ELF binary data
    pub elf_data: &'a [u8],
    /// Root CNode capability slot
    pub root_cnode: u64,
    /// CNode radix (log2 of number of slots) - needed for CPtr formatting
    pub cnode_radix: u8,
    /// Untyped memory capability slot to use for allocations
    pub ram_untyped: u64,
    /// ASID pool capability slot
    pub asid_pool: u64,
    /// Next free slot in root CNode for allocating capabilities
    pub next_free_slot: u64,
    /// Initial capabilities to grant to child
    pub initial_caps: &'a [InitialCap],
    /// Initial value for x0 register (e.g., pointer to passed data)
    pub x0: u64,
    /// Whether to resume the TCB immediately (default: true)
    /// Set to false if you need to do additional setup before starting
    pub resume: bool,
}

/// Result of successful spawn
pub struct SpawnResult {
    /// Capability slot of the new process's TCB
    pub tcb_slot: u64,
    /// Capability slot of the new process's VSpace
    pub vspace_slot: u64,
    /// Capability slot of the new process's CSpace
    pub cspace_slot: u64,
    /// ASID assigned to the process
    pub asid: u64,
    /// Next free slot after allocation
    pub next_free_slot: u64,
}

/// VSpace manager for building page tables and mapping frames
struct VSpaceBuilder {
    vspace_slot: u64,
    root_cnode: u64,
    ram_untyped: u64,
    next_free_slot: u64,
    cnode_radix: u8,
    /// Track installed L1 region (512GB aligned base addresses, 0 = not used)
    l1_regions: [u64; 4],
    l1_count: usize,
    /// Track installed L2 regions (1GB aligned base addresses)
    l2_regions: [u64; 8],
    l2_count: usize,
    /// Track installed L3 regions (2MB aligned base addresses)
    l3_regions: [u64; 32],
    l3_count: usize,
}

impl VSpaceBuilder {
    fn new(
        vspace_slot: u64,
        root_cnode: u64,
        ram_untyped: u64,
        next_free_slot: u64,
        cnode_radix: u8,
    ) -> Self {
        Self {
            vspace_slot,
            root_cnode,
            ram_untyped,
            next_free_slot,
            cnode_radix,
            l1_regions: [u64::MAX; 4],
            l1_count: 0,
            l2_regions: [u64::MAX; 8],
            l2_count: 0,
            l3_regions: [u64::MAX; 32],
            l3_count: 0,
        }
    }

    /// Check if an L1 table exists for the given 512GB-aligned address
    fn has_l1(&self, addr: u64) -> bool {
        self.l1_regions[..self.l1_count].contains(&addr)
    }

    /// Check if an L2 table exists for the given 1GB-aligned address
    fn has_l2(&self, addr: u64) -> bool {
        self.l2_regions[..self.l2_count].contains(&addr)
    }

    /// Check if an L3 table exists for the given 2MB-aligned address
    fn has_l3(&self, addr: u64) -> bool {
        self.l3_regions[..self.l3_count].contains(&addr)
    }

    /// Record that an L1 table was installed
    fn add_l1(&mut self, addr: u64) {
        if self.l1_count < self.l1_regions.len() {
            self.l1_regions[self.l1_count] = addr;
            self.l1_count += 1;
        }
    }

    /// Record that an L2 table was installed
    fn add_l2(&mut self, addr: u64) {
        if self.l2_count < self.l2_regions.len() {
            self.l2_regions[self.l2_count] = addr;
            self.l2_count += 1;
        }
    }

    /// Record that an L3 table was installed
    fn add_l3(&mut self, addr: u64) {
        if self.l3_count < self.l3_regions.len() {
            self.l3_regions[self.l3_count] = addr;
            self.l3_count += 1;
        }
    }

    /// Convert a slot index to a CPtr
    #[inline]
    fn cptr(&self, slot: u64) -> u64 {
        slot_to_cptr(slot, self.cnode_radix)
    }

    /// Allocate and retype a page table
    fn alloc_page_table(&mut self, level: u64) -> Result<u64, SpawnError> {
        if self.next_free_slot >= 4096 {
            return Err(SpawnError::NoSlots);
        }

        let pt_slot = self.next_free_slot;
        self.next_free_slot += 1;

        // ObjectType for page tables: L1=5, L2=6, L3=7
        let obj_type = 4 + level; // L1=5, L2=6, L3=7

        retype(
            self.cptr(self.ram_untyped),
            obj_type,
            0, // Page tables don't need size_bits
            self.cptr(self.root_cnode),
            pt_slot,
            1,
        )
        .map_err(SpawnError::RetypeFailed)?;

        Ok(pt_slot)
    }

    /// Allocate a frame capability
    fn alloc_frame(&mut self) -> Result<u64, SpawnError> {
        if self.next_free_slot >= 4096 {
            return Err(SpawnError::NoSlots);
        }

        let frame_slot = self.next_free_slot;
        self.next_free_slot += 1;

        // Retype: create one 4KB frame (12 bits)
        retype(
            self.cptr(self.ram_untyped),
            ObjectType::Frame as u64,
            12, // 4KB
            self.cptr(self.root_cnode),
            frame_slot,
            1,
        )
        .map_err(SpawnError::RetypeFailed)?;

        Ok(frame_slot)
    }

    /// Map a frame at a virtual address
    fn map_frame(&self, frame_slot: u64, vaddr: u64, rights: MapRights) -> Result<(), SpawnError> {
        map_frame(
            self.cptr(self.vspace_slot),
            self.cptr(frame_slot),
            vaddr,
            rights.to_bits(),
            0,
        )
        .map_err(SpawnError::FrameMapFailed)?;
        Ok(())
    }

    /// Ensure page tables exist for a virtual address range
    fn ensure_page_tables(&mut self, vaddr_start: u64, vaddr_end: u64) -> Result<(), SpawnError> {
        // Process each page in the range
        let mut vaddr = vaddr_start & !(PAGE_SIZE as u64 - 1);
        while vaddr < vaddr_end {
            self.ensure_page_tables_for_addr(vaddr)?;
            vaddr += PAGE_SIZE as u64;
        }
        Ok(())
    }

    /// Ensure page tables exist for a single virtual address
    fn ensure_page_tables_for_addr(&mut self, vaddr: u64) -> Result<(), SpawnError> {
        // Calculate aligned base addresses for each level
        // L1: 512GB aligned (bits 47:39)
        // L2: 1GB aligned (bits 38:30)
        // L3: 2MB aligned (bits 29:21)
        const L1_SIZE: u64 = 512 * 1024 * 1024 * 1024; // 512GB
        const L2_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
        const L3_SIZE: u64 = 2 * 1024 * 1024; // 2MB

        let l1_base = vaddr & !(L1_SIZE - 1);
        let l2_base = vaddr & !(L2_SIZE - 1);
        let l3_base = vaddr & !(L3_SIZE - 1);

        // Ensure L1 table exists (covers 512GB region)
        if !self.has_l1(l1_base) {
            let l1_slot = self.alloc_page_table(1)?;
            map_page_table(
                self.cptr(self.vspace_slot),
                self.cptr(l1_slot),
                l1_base,
                1, // Level 1
            )
            .map_err(SpawnError::PageTableMapFailed)?;
            self.add_l1(l1_base);
        }

        // Ensure L2 table exists (covers 1GB region)
        if !self.has_l2(l2_base) {
            let l2_slot = self.alloc_page_table(2)?;
            map_page_table(
                self.cptr(self.vspace_slot),
                self.cptr(l2_slot),
                l2_base,
                2, // Level 2
            )
            .map_err(SpawnError::PageTableMapFailed)?;
            self.add_l2(l2_base);
        }

        // Ensure L3 table exists (covers 2MB region)
        if !self.has_l3(l3_base) {
            let l3_slot = self.alloc_page_table(3)?;
            map_page_table(
                self.cptr(self.vspace_slot),
                self.cptr(l3_slot),
                l3_base,
                3, // Level 3
            )
            .map_err(SpawnError::PageTableMapFailed)?;
            self.add_l3(l3_base);
        }

        Ok(())
    }

    /// Map an ELF segment
    fn map_segment(
        &mut self,
        vaddr: u64,
        size: u64,
        data: &[u8],
        rights: MapRights,
    ) -> Result<(), SpawnError> {
        // Align to page boundaries
        let vaddr_start = vaddr & !(PAGE_SIZE as u64 - 1);
        let vaddr_end = (vaddr + size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        let num_pages = ((vaddr_end - vaddr_start) / PAGE_SIZE as u64) as usize;

        // Ensure page tables exist
        self.ensure_page_tables(vaddr_start, vaddr_end)?;

        // Calculate offset from segment start (for data that doesn't start at page boundary)
        let data_offset_in_first_page = (vaddr - vaddr_start) as usize;

        for i in 0..num_pages {
            let page_vaddr = vaddr_start + (i * PAGE_SIZE) as u64;
            let frame_slot = self.alloc_frame()?;

            // Calculate how much data to copy for this page
            let page_data_start = if i == 0 {
                0
            } else {
                i * PAGE_SIZE - data_offset_in_first_page
            };

            let page_data_end = core::cmp::min(page_data_start + PAGE_SIZE, data.len());

            // Use frame_write syscall to copy data directly into the frame
            // without needing to map it into our address space
            if page_data_start < data.len() {
                if i == 0 {
                    // First page: copy starting at the offset within the page
                    let copy_len =
                        core::cmp::min(PAGE_SIZE - data_offset_in_first_page, data.len());
                    // Zero the page first (before the data)
                    if data_offset_in_first_page > 0 {
                        static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                        frame_write(
                            self.cptr(frame_slot),
                            0,
                            ZEROS.as_ptr(),
                            data_offset_in_first_page,
                        )
                        .map_err(SpawnError::FrameMapFailed)?;
                    }
                    // Write the actual data
                    frame_write(
                        self.cptr(frame_slot),
                        data_offset_in_first_page as u64,
                        data.as_ptr(),
                        copy_len,
                    )
                    .map_err(SpawnError::FrameMapFailed)?;
                    // Zero remainder if needed
                    let remainder_start = data_offset_in_first_page + copy_len;
                    if remainder_start < PAGE_SIZE {
                        static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                        frame_write(
                            self.cptr(frame_slot),
                            remainder_start as u64,
                            ZEROS.as_ptr(),
                            PAGE_SIZE - remainder_start,
                        )
                        .map_err(SpawnError::FrameMapFailed)?;
                    }
                } else if page_data_start < page_data_end {
                    // Subsequent pages: copy from calculated offset
                    let copy_len = page_data_end - page_data_start;
                    frame_write(
                        self.cptr(frame_slot),
                        0,
                        data[page_data_start..].as_ptr(),
                        copy_len,
                    )
                    .map_err(SpawnError::FrameMapFailed)?;
                    // Zero remainder if this is a partial page
                    if copy_len < PAGE_SIZE {
                        static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                        frame_write(
                            self.cptr(frame_slot),
                            copy_len as u64,
                            ZEROS.as_ptr(),
                            PAGE_SIZE - copy_len,
                        )
                        .map_err(SpawnError::FrameMapFailed)?;
                    }
                }
            } else {
                // No data for this page - just zero it
                static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                frame_write(self.cptr(frame_slot), 0, ZEROS.as_ptr(), PAGE_SIZE)
                    .map_err(SpawnError::FrameMapFailed)?;
            }

            // Map frame into child's VSpace with the correct permissions
            self.map_frame(frame_slot, page_vaddr, rights)?;
        }

        Ok(())
    }

    /// Create a stack for the process
    fn create_stack(&mut self, stack_pages: usize) -> Result<u64, SpawnError> {
        let stack_top = 0x0000_7FFF_F000u64; // Just below boot info page
        let stack_base = stack_top - (stack_pages * PAGE_SIZE) as u64;

        // Ensure page tables exist
        self.ensure_page_tables(stack_base, stack_top)?;

        // Allocate and map stack pages
        for i in 0..stack_pages {
            let page_vaddr = stack_base + (i * PAGE_SIZE) as u64;
            let frame_slot = self.alloc_frame()?;
            self.map_frame(frame_slot, page_vaddr, MapRights::RW)?;
        }

        Ok(stack_top)
    }
}

/// Map data into a child's VSpace.
///
/// This function allocates frames, copies data to them, and maps them into
/// the child's VSpace. Used for mapping DTB, initrd, boot info, etc.
///
/// Returns the virtual address where the data was mapped.
#[allow(clippy::too_many_arguments)]
pub fn map_data_to_child(
    root_cnode: u64,
    cnode_radix: u8,
    vspace_slot: u64,
    ram_untyped: u64,
    next_free_slot: &mut u64,
    vaddr: u64,
    data: &[u8],
    rights: MapRights,
) -> Result<(), SpawnError> {
    let cptr = |slot: u64| slot_to_cptr(slot, cnode_radix);

    // Calculate number of pages needed
    let num_pages = data.len().div_ceil(PAGE_SIZE);

    for i in 0..num_pages {
        let page_vaddr = vaddr + (i * PAGE_SIZE) as u64;
        let frame_slot = *next_free_slot;
        *next_free_slot += 1;

        // Allocate frame
        retype(
            cptr(ram_untyped),
            ObjectType::Frame as u64,
            12, // 4KB
            cptr(root_cnode),
            frame_slot,
            1,
        )
        .map_err(SpawnError::RetypeFailed)?;

        // Calculate data range for this page
        let data_start = i * PAGE_SIZE;
        let data_end = core::cmp::min(data_start + PAGE_SIZE, data.len());
        let copy_len = data_end - data_start;

        // Copy data to frame
        if copy_len > 0 {
            frame_write(cptr(frame_slot), 0, data[data_start..].as_ptr(), copy_len)
                .map_err(SpawnError::FrameMapFailed)?;

            // Zero remainder if partial page
            if copy_len < PAGE_SIZE {
                static ZEROS: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                frame_write(
                    cptr(frame_slot),
                    copy_len as u64,
                    ZEROS.as_ptr(),
                    PAGE_SIZE - copy_len,
                )
                .map_err(SpawnError::FrameMapFailed)?;
            }
        }

        // Map frame into child's VSpace
        map_frame(
            cptr(vspace_slot),
            cptr(frame_slot),
            page_vaddr,
            rights.to_bits(),
            0,
        )
        .map_err(SpawnError::FrameMapFailed)?;
    }

    Ok(())
}

/// Ensure page tables exist for an address range in a child's VSpace.
pub fn ensure_child_page_tables(
    root_cnode: u64,
    cnode_radix: u8,
    vspace_slot: u64,
    ram_untyped: u64,
    next_free_slot: &mut u64,
    vaddr_start: u64,
    vaddr_end: u64,
) -> Result<(), SpawnError> {
    // This is a simplified version - we create page tables for each level
    // In a real implementation, we'd track which tables already exist
    let cptr = |slot: u64| slot_to_cptr(slot, cnode_radix);

    const L1_SIZE: u64 = 512 * 1024 * 1024 * 1024; // 512GB
    const L2_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
    const L3_SIZE: u64 = 2 * 1024 * 1024; // 2MB

    let l1_base = vaddr_start & !(L1_SIZE - 1);
    let l2_base = vaddr_start & !(L2_SIZE - 1);
    let l3_base = vaddr_start & !(L3_SIZE - 1);

    // Create L1 table
    let l1_slot = *next_free_slot;
    *next_free_slot += 1;
    retype(cptr(ram_untyped), 5, 0, cptr(root_cnode), l1_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l1_slot), l1_base, 1);

    // Create L2 table
    let l2_slot = *next_free_slot;
    *next_free_slot += 1;
    retype(cptr(ram_untyped), 6, 0, cptr(root_cnode), l2_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l2_slot), l2_base, 2);

    // Create L3 table
    let l3_slot = *next_free_slot;
    *next_free_slot += 1;
    retype(cptr(ram_untyped), 7, 0, cptr(root_cnode), l3_slot, 1)
        .map_err(SpawnError::RetypeFailed)?;
    let _ = map_page_table(cptr(vspace_slot), cptr(l3_slot), l3_base, 3);

    // Handle case where end address is in a different L3 region
    let l3_end_base = (vaddr_end - 1) & !(L3_SIZE - 1);
    if l3_end_base != l3_base {
        let l3_slot2 = *next_free_slot;
        *next_free_slot += 1;
        retype(cptr(ram_untyped), 7, 0, cptr(root_cnode), l3_slot2, 1)
            .map_err(SpawnError::RetypeFailed)?;
        let _ = map_page_table(cptr(vspace_slot), cptr(l3_slot2), l3_end_base, 3);
    }

    Ok(())
}

/// Spawn a new process from an ELF binary
///
/// This function:
/// 1. Parses the ELF binary
/// 2. Creates a VSpace from untyped memory
/// 3. Assigns an ASID from the pool
/// 4. Creates frames and maps ELF segments
/// 5. Creates TCB and CSpace
/// 6. Configures TCB with VSpace/CSpace
/// 7. Grants initial capabilities
/// 8. Sets up entry point and resumes
///
/// # Arguments
///
/// * `config` - Spawn configuration
///
/// # Returns
///
/// `SpawnResult` on success with slots of created objects
pub fn spawn_process(config: &SpawnConfig) -> Result<SpawnResult, SpawnError> {
    let mut next_slot = config.next_free_slot;
    let radix = config.cnode_radix;

    // Helper to convert slot to CPtr
    let cptr = |slot: u64| slot_to_cptr(slot, radix);

    // Parse ELF
    let elf = Elf64::parse(config.elf_data)?;

    // Allocate capability slots
    let vspace_slot = next_slot;
    next_slot += 1;
    let cspace_slot = next_slot;
    next_slot += 1;
    let tcb_slot = next_slot;
    next_slot += 1;
    let ipc_buf_frame_slot = next_slot;
    next_slot += 1;

    // Create VSpace (L0 page table root)
    retype(
        cptr(config.ram_untyped),
        ObjectType::VSpace as u64,
        0,
        cptr(config.root_cnode),
        vspace_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Assign ASID to VSpace
    let asid = asid_pool_assign(cptr(config.asid_pool), cptr(vspace_slot))
        .map_err(SpawnError::AsidAssignFailed)? as u64;

    // Create CSpace for child (radix 12 = 4096 slots)
    retype(
        cptr(config.ram_untyped),
        ObjectType::CNode as u64,
        12, // radix
        cptr(config.root_cnode),
        cspace_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create TCB
    retype(
        cptr(config.ram_untyped),
        ObjectType::TCB as u64,
        0,
        cptr(config.root_cnode),
        tcb_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Create IPC buffer frame
    retype(
        cptr(config.ram_untyped),
        ObjectType::Frame as u64,
        12, // 4KB
        cptr(config.root_cnode),
        ipc_buf_frame_slot,
        1,
    )
    .map_err(SpawnError::RetypeFailed)?;

    // Initialize VSpace builder
    let mut vspace_builder = VSpaceBuilder::new(
        vspace_slot,
        config.root_cnode,
        config.ram_untyped,
        next_slot,
        radix,
    );

    // Map ELF segments
    // NOTE: This is simplified - proper implementation would copy data
    for segment in elf.segments() {
        let rights = if segment.executable {
            MapRights::RX
        } else if segment.writable {
            MapRights::RW
        } else {
            MapRights::R
        };

        if let Some(data) = elf.segment_data(&segment) {
            vspace_builder.map_segment(segment.vaddr, segment.mem_size, data, rights)?;
        }
    }

    // Create stack (32 pages = 128KB)
    // Rust programs need significant stack space for startup/runtime
    let stack_top = vspace_builder.create_stack(32)?;

    // Map IPC buffer at the standard address
    const IPC_BUFFER_ADDR: u64 = m6_syscall::IPC_BUFFER_ADDR;
    vspace_builder.ensure_page_tables(IPC_BUFFER_ADDR, IPC_BUFFER_ADDR + 0x1000)?;
    map_frame(
        cptr(vspace_slot),
        cptr(ipc_buf_frame_slot),
        IPC_BUFFER_ADDR,
        MapRights::RW.to_bits(),
        0,
    )
    .map_err(SpawnError::FrameMapFailed)?;

    crate::io::puts("[spawn] IPC buffer mapped\n");

    // Update next free slot
    next_slot = vspace_builder.next_free_slot;

    // Grant initial capabilities to child's CSpace
    crate::io::puts("[spawn] Copying initial caps...\n");

    // Set up standard slots 0, 1, 2 for the child's own capabilities.
    // These are critical for the child to be able to perform capability operations.

    // Slot 0: CSpace self-reference
    crate::io::puts("[spawn]   Setting up CNode self-reference at slot 0...");
    let result = cap_copy(
        cptr(cspace_slot),       // dest cnode (child's CSpace)
        0,                       // dest index (slot 0)
        0,                       // dest depth (auto)
        cptr(config.root_cnode), // src cnode (parent's CNode)
        cspace_slot,             // src index (where child's CSpace cap is in parent)
        0,                       // src depth (auto)
    );
    match result {
        Ok(_) => crate::io::puts(" OK\n"),
        Err(e) => {
            crate::io::puts(" FAILED: ");
            crate::io::puts(e.name());
            crate::io::newline();
            return Err(SpawnError::CapCopyFailed(e));
        }
    }

    // Slot 1: TCB
    crate::io::puts("[spawn]   Setting up TCB at slot 1...");
    let result = cap_copy(
        cptr(cspace_slot),       // dest cnode (child's CSpace)
        1,                       // dest index (slot 1)
        0,                       // dest depth (auto)
        cptr(config.root_cnode), // src cnode (parent's CNode)
        tcb_slot,                // src index (where TCB cap is in parent)
        0,                       // src depth (auto)
    );
    match result {
        Ok(_) => crate::io::puts(" OK\n"),
        Err(e) => {
            crate::io::puts(" FAILED: ");
            crate::io::puts(e.name());
            crate::io::newline();
            return Err(SpawnError::CapCopyFailed(e));
        }
    }

    // Slot 2: VSpace
    crate::io::puts("[spawn]   Setting up VSpace at slot 2...");
    let result = cap_copy(
        cptr(cspace_slot),       // dest cnode (child's CSpace)
        2,                       // dest index (slot 2)
        0,                       // dest depth (auto)
        cptr(config.root_cnode), // src cnode (parent's CNode)
        vspace_slot,             // src index (where VSpace cap is in parent)
        0,                       // src depth (auto)
    );
    match result {
        Ok(_) => crate::io::puts(" OK\n"),
        Err(e) => {
            crate::io::puts(" FAILED: ");
            crate::io::puts(e.name());
            crate::io::newline();
            return Err(SpawnError::CapCopyFailed(e));
        }
    }

    // Copy user-specified initial capabilities
    for cap in config.initial_caps {
        let result = cap_copy(
            cptr(cspace_slot),       // dest cnode
            cap.dst_slot,            // dest index
            0,                       // dest depth (auto)
            cptr(config.root_cnode), // src cnode
            cap.src_slot,            // src index
            0,                       // src depth (auto)
        );
        match result {
            Ok(_) => (),
            Err(e) => {
                crate::io::puts(" FAILED: ");
                crate::io::puts(e.name());
                crate::io::newline();
                return Err(SpawnError::CapCopyFailed(e));
            }
        }
    }

    crate::io::puts("[spawn] Configuring TCB...\n");
    // Configure TCB
    tcb_configure(
        cptr(tcb_slot),
        0, // fault_ep (none for now)
        cptr(cspace_slot),
        cptr(vspace_slot),
        IPC_BUFFER_ADDR,
        cptr(ipc_buf_frame_slot),
    )
    .map_err(SpawnError::TcbConfigureFailed)?;

    crate::io::puts("[spawn] Writing registers: PC=0x");
    // Set up initial registers
    let entry = elf.entry();
    let sp = stack_top;
    crate::io::put_hex(entry);
    crate::io::puts(" SP=0x");
    crate::io::put_hex(sp);
    crate::io::newline();
    tcb_write_registers(cptr(tcb_slot), entry, sp, config.x0)
        .map_err(SpawnError::TcbWriteRegistersFailed)?;

    if config.resume {
        crate::io::puts("[spawn] Resuming TCB...\n");
        // Resume the task
        tcb_resume(cptr(tcb_slot)).map_err(SpawnError::TcbResumeFailed)?;
        crate::io::puts("[spawn] TCB resumed\n");
    } else {
        crate::io::puts("[spawn] TCB configured (not resumed)\n");
    }

    Ok(SpawnResult {
        tcb_slot,
        vspace_slot,
        cspace_slot,
        asid,
        next_free_slot: next_slot,
    })
}
