//! Process spawning
//!
//! Capability-based process creation for userspace.
//! Uses VSpace, TCB, CSpace, and Frame capabilities to create isolated processes.

use m6_cap::ObjectType;
use m6_syscall::{invoke::*, error::SyscallError};

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

/// Well-known capability slot indices
pub mod slots {
    pub const ROOT_CNODE: u64 = 0;
    pub const ROOT_TCB: u64 = 1;
    pub const ROOT_VSPACE: u64 = 2;
    pub const IRQ_CONTROL: u64 = 3;
    pub const ASID_CONTROL: u64 = 4;
    pub const SCHED_CONTROL: u64 = 5;
    pub const FIRST_UNTYPED: u64 = 6;
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
    pub const R: Self = Self { read: true, write: false, execute: false };
    pub const RW: Self = Self { read: true, write: true, execute: false };
    pub const RX: Self = Self { read: true, write: false, execute: true };
    pub const RWX: Self = Self { read: true, write: true, execute: true };

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
}

impl VSpaceBuilder {
    fn new(vspace_slot: u64, root_cnode: u64, ram_untyped: u64, next_free_slot: u64) -> Self {
        Self {
            vspace_slot,
            root_cnode,
            ram_untyped,
            next_free_slot,
        }
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
            self.ram_untyped,
            ObjectType::Frame as u64,
            12, // 4KB
            self.root_cnode,
            frame_slot,
            1,
        )
        .map_err(|e| SpawnError::RetypeFailed(e))?;

        Ok(frame_slot)
    }

    /// Map a frame at a virtual address
    fn map_frame(&self, frame_slot: u64, vaddr: u64, rights: MapRights) -> Result<(), SpawnError> {
        map_frame(self.vspace_slot, frame_slot, vaddr, rights.to_bits(), 0)
            .map_err(|e| SpawnError::FrameMapFailed(e))?;
        Ok(())
    }

    /// Ensure page tables exist for a virtual address range
    ///
    /// This is a simplified version - in a full implementation, you would
    /// walk the page table hierarchy and create tables as needed.
    fn ensure_page_tables(&mut self, _vaddr_start: u64, _vaddr_end: u64) -> Result<(), SpawnError> {
        // For now, we rely on the kernel having pre-mapped page tables
        // or we get page faults. A full implementation would:
        // 1. Calculate which L1/L2/L3 tables are needed
        // 2. Retype page table objects
        // 3. Map them into the VSpace hierarchy
        Ok(())
    }

    /// Map an ELF segment
    fn map_segment(&mut self, vaddr: u64, size: u64, data: &[u8], rights: MapRights) -> Result<(), SpawnError> {
        // Align to page boundaries
        let vaddr_start = vaddr & !(PAGE_SIZE as u64 - 1);
        let vaddr_end = (vaddr + size + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        let num_pages = ((vaddr_end - vaddr_start) / PAGE_SIZE as u64) as usize;

        // Ensure page tables exist
        self.ensure_page_tables(vaddr_start, vaddr_end)?;

        // Temporary address for mapping frames into our VSpace for copying data
        // We use a high address that's unlikely to conflict with normal mappings
        const TEMP_MAP_BASE: u64 = 0x1_0000_0000;

        // Calculate offset from segment start (for data that doesn't start at page boundary)
        let data_offset_in_first_page = (vaddr - vaddr_start) as usize;

        for i in 0..num_pages {
            let page_vaddr = vaddr_start + (i * PAGE_SIZE) as u64;
            let frame_slot = self.alloc_frame()?;

            // Map frame into our VSpace temporarily for data copying
            map_frame(
                slots::ROOT_VSPACE,
                frame_slot,
                TEMP_MAP_BASE,
                MapRights::RW.to_bits(),
                0,
            )
            .map_err(|e| SpawnError::FrameMapFailed(e))?;

            // Calculate how much data to copy for this page
            let page_data_start = if i == 0 {
                // First page: data starts at offset within page
                0
            } else {
                // Subsequent pages: account for offset in first page
                i * PAGE_SIZE - data_offset_in_first_page
            };

            let page_data_end = core::cmp::min(
                page_data_start + PAGE_SIZE,
                data.len(),
            );

            // Copy data from ELF into the mapped frame
            if page_data_start < data.len() {
                // SAFETY: We just mapped this frame at TEMP_MAP_BASE with RW rights
                unsafe {
                    let dest = core::slice::from_raw_parts_mut(
                        TEMP_MAP_BASE as *mut u8,
                        PAGE_SIZE,
                    );

                    // Zero the entire page first
                    dest.fill(0);

                    // Copy the relevant portion of data
                    if i == 0 {
                        // First page: copy starting at the offset
                        let copy_len = core::cmp::min(
                            PAGE_SIZE - data_offset_in_first_page,
                            data.len(),
                        );
                        dest[data_offset_in_first_page..data_offset_in_first_page + copy_len]
                            .copy_from_slice(&data[0..copy_len]);
                    } else if page_data_start < page_data_end {
                        // Subsequent pages: copy from calculated offset
                        let copy_len = page_data_end - page_data_start;
                        dest[..copy_len].copy_from_slice(&data[page_data_start..page_data_end]);
                    }
                }
            } else {
                // No data for this page - just zero it
                // SAFETY: We just mapped this frame at TEMP_MAP_BASE with RW rights
                unsafe {
                    let dest = core::slice::from_raw_parts_mut(
                        TEMP_MAP_BASE as *mut u8,
                        PAGE_SIZE,
                    );
                    dest.fill(0);
                }
            }

            // Unmap from our VSpace
            unmap_frame(frame_slot).map_err(|e| SpawnError::FrameMapFailed(e))?;

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
        config.ram_untyped,
        ObjectType::VSpace as u64,
        0,
        config.root_cnode,
        vspace_slot,
        1,
    )
    .map_err(|e| SpawnError::RetypeFailed(e))?;

    // Assign ASID to VSpace
    let asid = asid_pool_assign(config.asid_pool, vspace_slot)
        .map_err(|e| SpawnError::AsidAssignFailed(e))? as u64;

    // Create CSpace for child (radix 12 = 4096 slots)
    retype(
        config.ram_untyped,
        ObjectType::CNode as u64,
        12, // radix
        config.root_cnode,
        cspace_slot,
        1,
    )
    .map_err(|e| SpawnError::RetypeFailed(e))?;

    // Create TCB
    retype(
        config.ram_untyped,
        ObjectType::TCB as u64,
        0,
        config.root_cnode,
        tcb_slot,
        1,
    )
    .map_err(|e| SpawnError::RetypeFailed(e))?;

    // Create IPC buffer frame
    retype(
        config.ram_untyped,
        ObjectType::Frame as u64,
        12, // 4KB
        config.root_cnode,
        ipc_buf_frame_slot,
        1,
    )
    .map_err(|e| SpawnError::RetypeFailed(e))?;

    // Initialize VSpace builder
    let mut vspace_builder = VSpaceBuilder::new(
        vspace_slot,
        config.root_cnode,
        config.ram_untyped,
        next_slot,
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

    // Create stack (16 pages = 64KB)
    let stack_top = vspace_builder.create_stack(16)?;

    // Map IPC buffer
    const IPC_BUFFER_ADDR: u64 = 0x0000_7FFF_F000_0000;
    map_frame(vspace_slot, ipc_buf_frame_slot, IPC_BUFFER_ADDR, MapRights::RW.to_bits(), 0)
        .map_err(|e| SpawnError::FrameMapFailed(e))?;

    // Update next free slot
    next_slot = vspace_builder.next_free_slot;

    // Grant initial capabilities to child's CSpace
    for cap in config.initial_caps {
        cap_copy(
            cspace_slot,    // dest cnode
            cap.dst_slot,   // dest index
            0,              // dest depth (auto)
            config.root_cnode, // src cnode
            cap.src_slot,   // src index
            0,              // src depth (auto)
        )
        .map_err(|e| SpawnError::CapCopyFailed(e))?;
    }

    // Configure TCB
    tcb_configure(
        tcb_slot,
        0,                  // fault_ep (none for now)
        cspace_slot,
        vspace_slot,
        IPC_BUFFER_ADDR,
        ipc_buf_frame_slot,
    )
    .map_err(|e| SpawnError::TcbConfigureFailed(e))?;

    // Set up initial registers
    let entry = elf.entry();
    let sp = stack_top;
    tcb_write_registers(tcb_slot, entry, sp, config.x0)
        .map_err(|e| SpawnError::TcbWriteRegistersFailed(e))?;

    // Resume the task
    tcb_resume(tcb_slot)
        .map_err(|e| SpawnError::TcbResumeFailed(e))?;

    Ok(SpawnResult {
        tcb_slot,
        vspace_slot,
        cspace_slot,
        asid,
        next_free_slot: next_slot,
    })
}
