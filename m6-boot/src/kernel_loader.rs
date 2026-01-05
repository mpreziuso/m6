//! Kernel ELF Loader
//!
//! Loads the M6 kernel from the EFI system partition.

extern crate alloc;
use alloc::vec::Vec;

use crate::config::{KERNEL_PATH, KERNEL_STACK_SIZE, MAX_KERNEL_SIZE};
use crate::efi_file::read_efi_file;
use elf_rs::{Elf, ElfFile, ProgramType};
use uefi::boot::{self, AllocateType, MemoryType};

/// Maximum number of loadable segments we track
pub const MAX_SEGMENTS: usize = 8;

/// Information about a loadable kernel segment
#[derive(Clone, Copy, Default)]
pub struct KernelSegment {
    /// Virtual address offset from kernel base
    pub virt_offset: u64,
    /// Size of the segment in memory
    pub size: u64,
    /// Readable
    pub read: bool,
    /// Writable
    pub write: bool,
    /// Executable
    pub execute: bool,
}

/// Loaded kernel information
pub struct LoadedKernel {
    /// Physical address where kernel is loaded
    pub phys_base: u64,
    /// Entry point virtual address
    pub entry_virt: u64,
    /// Total size of loaded kernel
    pub size: u64,
    /// Physical address of kernel stack (top of stack)
    pub stack_phys: u64,
    /// Virtual address of kernel stack (top of stack)
    pub stack_virt: u64,
    /// Loadable segments with their permissions
    pub segments: [KernelSegment; MAX_SEGMENTS],
    /// Number of valid segments
    pub segment_count: usize,
    /// Base virtual address (min vaddr from ELF)
    pub virt_base: u64,
}

/// Load the kernel from the EFI filesystem
pub fn load_kernel() -> uefi::Result<LoadedKernel> {
    log::info!("Loading kernel from {}", KERNEL_PATH);
    let kernel_data: Vec<u8> = match read_efi_file(KERNEL_PATH) {
        Some(data) => data,
        None => {
            log::error!("Kernel not found at {}", KERNEL_PATH);
            return Err(uefi::Status::NOT_FOUND.into());
        }
    };
    if kernel_data.len() > MAX_KERNEL_SIZE {
        log::error!("Kernel too large: {} bytes", kernel_data.len());
        return Err(uefi::Status::BUFFER_TOO_SMALL.into());
    }

    // Parse ELF file
    let elf = Elf::from_bytes(&kernel_data).map_err(|e| {
        log::error!("Failed to parse ELF file: {:?}", e);
        uefi::Status::LOAD_ERROR
    })?;

    let elf64 = match elf {
        Elf::Elf64(e) => e,
        Elf::Elf32(_) => {
            log::error!("Expected 64-bit ELF, got 32-bit");
            return Err(uefi::Status::LOAD_ERROR.into());
        }
    };

    let header = elf64.elf_header();
    log::info!("ELF entry point: {:#x}", header.entry_point());

    // Calculate total memory needed and collect segment info by scanning program headers
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut segments = [KernelSegment::default(); MAX_SEGMENTS];
    let mut segment_count = 0usize;

    for phdr in elf64.program_header_iter() {
        if phdr.ph_type() == ProgramType::LOAD && phdr.memsz() > 0 {
            let vaddr = phdr.vaddr();
            let memsz = phdr.memsz();

            min_vaddr = min_vaddr.min(vaddr);
            max_vaddr = max_vaddr.max(vaddr + memsz);

            // Collect segment permission information
            if segment_count < MAX_SEGMENTS {
                let flags = phdr.flags();
                use elf_rs::ProgramHeaderFlags;
                segments[segment_count] = KernelSegment {
                    virt_offset: vaddr, // Will adjust after finding min_vaddr
                    size: memsz,
                    read: flags.contains(ProgramHeaderFlags::READ),
                    write: flags.contains(ProgramHeaderFlags::WRITE),
                    execute: flags.contains(ProgramHeaderFlags::EXECUTE),
                };
                segment_count += 1;
            }
        }
    }

    if min_vaddr == u64::MAX {
        log::error!("No loadable segments found");
        return Err(uefi::Status::LOAD_ERROR.into());
    }

    // Adjust segment offsets to be relative to min_vaddr
    for seg in segments.iter_mut().take(segment_count) {
        seg.virt_offset -= min_vaddr;
    }

    let total_size = max_vaddr - min_vaddr;
    log::info!(
        "Kernel virtual range: {:#x} - {:#x} ({} bytes)",
        min_vaddr,
        max_vaddr,
        total_size
    );

    // Allocate physical memory for the kernel
    let num_pages = (total_size as usize).div_ceil(4096);
    let kernel_phys =
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, num_pages)?;

    log::info!(
        "Allocated {} pages at physical {:#x}",
        num_pages,
        kernel_phys.as_ptr() as u64
    );

    // Zero the allocated memory
    // SAFETY: We just allocated this memory
    unsafe {
        core::ptr::write_bytes(kernel_phys.as_ptr(), 0, num_pages * 4096);
    }

    // Load segments
    for phdr in elf64.program_header_iter() {
        if phdr.ph_type() == ProgramType::LOAD && phdr.filesz() > 0 {
            let dest_offset = (phdr.vaddr() - min_vaddr) as usize;
            let src_offset = phdr.offset() as usize;
            let copy_size = phdr.filesz() as usize;

            log::debug!(
                "Loading segment: file offset {:#x}, size {:#x} -> vaddr {:#x}",
                src_offset,
                copy_size,
                phdr.vaddr()
            );

            // SAFETY: We've verified all offsets and sizes
            unsafe {
                let src = kernel_data.as_ptr().add(src_offset);
                let dst = kernel_phys.as_ptr().add(dest_offset);
                core::ptr::copy_nonoverlapping(src, dst, copy_size);
            }
        }
    }

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE.div_ceil(4096);
    let stack_phys =
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, stack_pages)?;

    log::info!(
        "Allocated kernel stack: {} pages at physical {:#x}",
        stack_pages,
        stack_phys.as_ptr() as u64
    );

    // Zero the stack memory
    // SAFETY: We just allocated this memory
    unsafe {
        core::ptr::write_bytes(stack_phys.as_ptr(), 0, stack_pages * 4096);
    }

    // Stack grows downward, so stack_top is at the end of the allocated region
    // Virtual address is placed right after the kernel in the high-half
    let stack_phys_top = stack_phys.as_ptr() as u64 + KERNEL_STACK_SIZE as u64;
    let stack_virt_top = min_vaddr + total_size + KERNEL_STACK_SIZE as u64;

    log::info!(
        "Kernel stack: phys {:#x}, virt {:#x}",
        stack_phys_top,
        stack_virt_top
    );

    // Log segment information for W^X
    for (i, seg) in segments.iter().enumerate().take(segment_count) {
        let perms = [
            if seg.read { 'R' } else { '-' },
            if seg.write { 'W' } else { '-' },
            if seg.execute { 'X' } else { '-' },
        ];
        log::info!(
            "Segment {}: offset {:#x}, size {:#x}, perms {}{}{}",
            i,
            seg.virt_offset,
            seg.size,
            perms[0],
            perms[1],
            perms[2]
        );
    }

    Ok(LoadedKernel {
        phys_base: kernel_phys.as_ptr() as u64,
        entry_virt: header.entry_point(),
        size: total_size,
        stack_phys: stack_phys_top,
        stack_virt: stack_virt_top,
        segments,
        segment_count,
        virt_base: min_vaddr,
    })
}
