//! Kernel ELF Loader
//!
//! Loads the M6 kernel from the EFI system partition.

extern crate alloc;
use alloc::vec::Vec;

use crate::config::{KERNEL_PATH, MAX_CPUS, MAX_KERNEL_SIZE, PER_CPU_STACK_SIZE};
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

/// Per-CPU stack information (matches PerCpuStackInfo layout)
#[derive(Clone, Copy, Default)]
pub struct PerCpuStack {
    /// Physical address of stack base (low address)
    pub phys_base: u64,
    /// Virtual address of stack top (high address, where SP starts)
    pub virt_top: u64,
}

/// Loaded kernel information
pub struct LoadedKernel {
    /// Physical address where kernel is loaded
    pub phys_base: u64,
    /// Entry point virtual address
    pub entry_virt: u64,
    /// Total size of loaded kernel
    pub size: u64,
    /// Physical address of kernel stack (top of stack) - CPU 0's stack
    pub stack_phys: u64,
    /// Virtual address of kernel stack (top of stack) - CPU 0's stack
    pub stack_virt: u64,
    /// Per-CPU stack information
    pub per_cpu_stacks: [PerCpuStack; MAX_CPUS],
    /// Number of CPUs for which stacks were allocated
    pub cpu_count: u32,
    /// Loadable segments with their permissions
    pub segments: [KernelSegment; MAX_SEGMENTS],
    /// Number of valid segments
    pub segment_count: usize,
    /// Base virtual address (min vaddr from ELF)
    pub virt_base: u64,
}

/// Load the kernel from the EFI filesystem
///
/// # Arguments
/// * `cpu_count` - Number of CPUs to allocate stacks for (from DTB parsing)
pub fn load_kernel(cpu_count: u32) -> uefi::Result<LoadedKernel> {
    let cpu_count = (cpu_count as usize).clamp(1, MAX_CPUS);
    log::info!("Loading kernel from {} (for {} CPUs)", KERNEL_PATH, cpu_count);
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

    // Allocate per-CPU kernel stacks (contiguous block for all CPUs)
    let stack_pages_per_cpu = PER_CPU_STACK_SIZE.div_ceil(4096);
    let total_stack_pages = stack_pages_per_cpu * cpu_count;
    let stacks_phys =
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, total_stack_pages)?;

    log::info!(
        "Allocated {} per-CPU stacks: {} pages at physical {:#x}",
        cpu_count,
        total_stack_pages,
        stacks_phys.as_ptr() as u64
    );

    // Zero all stack memory
    // SAFETY: We just allocated this memory
    unsafe {
        core::ptr::write_bytes(stacks_phys.as_ptr(), 0, total_stack_pages * 4096);
    }

    // Calculate per-CPU stack addresses
    // Virtual addresses are placed right after the kernel in the high-half
    let stacks_phys_base = stacks_phys.as_ptr() as u64;
    let stacks_virt_base = min_vaddr + total_size;

    let mut per_cpu_stacks = [PerCpuStack::default(); MAX_CPUS];
    for (cpu, stack) in per_cpu_stacks.iter_mut().enumerate().take(cpu_count) {
        let phys_base = stacks_phys_base + (cpu * PER_CPU_STACK_SIZE) as u64;
        let virt_base = stacks_virt_base + (cpu * PER_CPU_STACK_SIZE) as u64;
        // Stack top is at base + size (stack grows downward)
        let virt_top = virt_base + PER_CPU_STACK_SIZE as u64;

        *stack = PerCpuStack { phys_base, virt_top };
        log::debug!(
            "CPU {} stack: phys_base={:#x}, virt_top={:#x}",
            cpu, phys_base, virt_top
        );
    }

    // CPU 0's stack for backwards compatibility
    let stack_phys_top = per_cpu_stacks[0].phys_base + PER_CPU_STACK_SIZE as u64;
    let stack_virt_top = per_cpu_stacks[0].virt_top;

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
        per_cpu_stacks,
        cpu_count: cpu_count as u32,
        segments,
        segment_count,
        virt_base: min_vaddr,
    })
}
