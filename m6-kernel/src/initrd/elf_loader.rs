//! ELF loader for userspace binaries
//!
//! Loads ELF64 binaries into a user VSpace, following proper security
//! practices for a capability-based microkernel.

use elf_rs::{Elf, ElfFile, ProgramHeaderFlags, ProgramType};

/// Information about a loaded ELF binary.
#[derive(Debug)]
pub struct LoadedElf {
    /// Entry point virtual address.
    pub entry: u64,
    /// Highest virtual address used (page-aligned, for placing stack/heap).
    pub brk: u64,
    /// Number of frames allocated for this binary.
    pub frame_count: usize,
}

/// Errors that can occur during ELF loading.
#[derive(Debug)]
pub enum ElfLoadError {
    /// Failed to parse ELF header.
    ParseError,
    /// Not a 64-bit ELF file.
    Not64Bit,
    /// ELF file has no loadable segments.
    NoLoadableSegments,
    /// Failed to allocate memory for a segment.
    AllocationFailed,
    /// Failed to map a page into the VSpace.
    MappingFailed,
    /// Segment extends beyond file data.
    SegmentOutOfBounds,
    /// Invalid segment address or size.
    InvalidSegment,
}

/// Page permissions for mapped memory.
#[derive(Clone, Copy, Debug)]
pub struct PagePerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl PagePerms {
    /// Read-only permissions.
    pub const fn ro() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    /// Read-write permissions.
    pub const fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// Read-execute permissions.
    pub const fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }
}

/// Convert ELF program header flags to page permissions.
fn elf_flags_to_perms(flags: ProgramHeaderFlags) -> PagePerms {
    PagePerms {
        read: flags.contains(ProgramHeaderFlags::READ),
        write: flags.contains(ProgramHeaderFlags::WRITE),
        execute: flags.contains(ProgramHeaderFlags::EXECUTE),
    }
}

/// Load an ELF binary into a VSpace.
///
/// This function parses the ELF file and maps each LOAD segment into the
/// address space using the provided callback. The callback is responsible
/// for allocating physical frames and creating the page table mappings.
///
/// # Arguments
///
/// * `elf_data` - The raw bytes of the ELF file
/// * `map_page` - Callback to map a page: (phys_addr, virt_addr, perms) -> Result
///
/// # Returns
///
/// Information about the loaded ELF, including entry point and highest address.
///
/// # Security
///
/// - All allocated pages are zeroed before use
/// - W^X (write xor execute) is enforced by the page mapper
/// - Segment contents are copied from the ELF file, not mapped directly
pub fn load_elf<F>(elf_data: &[u8], mut map_page: F) -> Result<LoadedElf, ElfLoadError>
where
    F: FnMut(u64, u64, PagePerms, &[u8]) -> Result<(), ElfLoadError>,
{
    // Parse the ELF file
    let elf = Elf::from_bytes(elf_data).map_err(|_| ElfLoadError::ParseError)?;

    let elf64 = match elf {
        Elf::Elf64(e) => e,
        Elf::Elf32(_) => return Err(ElfLoadError::Not64Bit),
    };

    let header = elf64.elf_header();
    let entry = header.entry_point();
    let mut brk = 0u64;
    let mut frame_count = 0usize;
    let mut has_loadable = false;

    // Process each program header
    for phdr in elf64.program_header_iter() {
        // Only process LOAD segments with non-zero memory size
        if phdr.ph_type() != ProgramType::LOAD || phdr.memsz() == 0 {
            continue;
        }

        has_loadable = true;

        let vaddr = phdr.vaddr();
        let memsz = phdr.memsz();
        let filesz = phdr.filesz();
        let offset = phdr.offset() as usize;
        let flags = phdr.flags();

        // Validate segment bounds within ELF file
        if filesz > 0 {
            let file_end = offset.saturating_add(filesz as usize);
            if file_end > elf_data.len() {
                log::error!(
                    "ELF segment at offset {:#x} extends beyond file (size {:#x}, file len {:#x})",
                    offset,
                    filesz,
                    elf_data.len()
                );
                return Err(ElfLoadError::SegmentOutOfBounds);
            }
        }

        // Validate virtual address (must be in user space)
        if vaddr >= 0x0001_0000_0000_0000 {
            log::error!("ELF segment vaddr {:#x} is in kernel space", vaddr);
            return Err(ElfLoadError::InvalidSegment);
        }

        // Update brk (highest address)
        let segment_end = vaddr.saturating_add(memsz);
        if segment_end > brk {
            brk = segment_end;
        }

        // Convert flags to permissions
        let perms = elf_flags_to_perms(flags);

        log::debug!(
            "Loading segment: vaddr={:#x} memsz={:#x} filesz={:#x} perms={}{}{}",
            vaddr,
            memsz,
            filesz,
            if perms.read { 'r' } else { '-' },
            if perms.write { 'w' } else { '-' },
            if perms.execute { 'x' } else { '-' },
        );

        // Map each page in the segment
        let page_size = 0x1000u64;
        let page_mask = page_size - 1;
        let aligned_start = vaddr & !page_mask;
        let aligned_end = (vaddr + memsz + page_mask) & !page_mask;

        let mut va = aligned_start;
        while va < aligned_end {
            // Calculate how much of this page contains file data
            let page_start_in_segment = va.saturating_sub(vaddr);

            // Determine the data to copy into this page
            let data: &[u8] = if page_start_in_segment >= filesz {
                // This page is entirely in the BSS region (zero-filled)
                &[]
            } else {
                // Calculate the portion of file data for this page
                let data_start = offset + page_start_in_segment as usize;
                let data_end = (offset + filesz as usize).min(data_start + page_size as usize);

                if data_start < elf_data.len() && data_end <= elf_data.len() {
                    &elf_data[data_start..data_end]
                } else {
                    &[]
                }
            };

            // Map the page (the callback allocates the frame and zeroes it)
            map_page(0, va, perms, data)?;
            frame_count += 1;

            va += page_size;
        }
    }

    if !has_loadable {
        return Err(ElfLoadError::NoLoadableSegments);
    }

    // Page-align brk
    let page_size = 0x1000u64;
    brk = (brk + page_size - 1) & !(page_size - 1);

    log::info!(
        "ELF loaded: entry={:#x} brk={:#x} frames={}",
        entry,
        brk,
        frame_count
    );

    Ok(LoadedElf {
        entry,
        brk,
        frame_count,
    })
}
