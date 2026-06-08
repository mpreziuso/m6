//! Kernel ELF Loader
//!
//! Loads the M6 kernel from the EFI system partition.

extern crate alloc;
use alloc::vec::Vec;

use crate::config::{
    KERNEL_MMIO_BASE, KERNEL_PATH, KERNEL_VIRT_BASE, MAX_CPUS, MAX_KERNEL_SIZE, PER_CPU_STACK_SIZE,
};
use crate::efi_file::read_efi_file;
use elf_rs::{Elf, ElfFile, ProgramType};
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::proto::rng::Rng;

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
    /// KASLR virtual-address slide applied to this load (0 if disabled).
    pub kaslr_slide: u64,
}

// -- KASLR (Kernel Address Space Layout Randomisation)

/// `R_AARCH64_RELATIVE` dynamic relocation type.
const R_AARCH64_RELATIVE: u32 = 1027;
/// `SHT_RELA` section type.
const SHT_RELA: u32 = 4;

#[inline]
fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn read_u64_le(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Gather boot-time entropy for the KASLR slide.
///
/// Prefers the UEFI RNG protocol (true hardware entropy where available);
/// falls back to the architectural counter, which is weak but better than a
/// fixed layout.
fn boot_entropy() -> u64 {
    if let Ok(handle) = boot::get_handle_for_protocol::<Rng>()
        && let Ok(mut rng) = boot::open_protocol_exclusive::<Rng>(handle)
    {
        let mut buf = [0u8; 8];
        if rng.get_rng(None, &mut buf).is_ok() {
            return u64::from_le_bytes(buf);
        }
    }
    // Fallback: architectural generic-timer counter.
    let cnt: u64;
    // SAFETY: CNTVCT_EL0 is readable at the bootloader's exception level.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack));
    }
    cnt
}

/// Choose a random, 2 MiB-aligned virtual-address slide for the kernel image.
///
/// The kernel image + per-CPU stacks (< 1 MiB) live in the 1.75 GiB window
/// between [`KERNEL_VIRT_BASE`] and [`KERNEL_MMIO_BASE`]. The slide is bounded
/// well within that window so the image never collides with the kernel MMIO or
/// physmap regions. 2 MiB alignment keeps huge-page mappings possible and
/// preserves the page alignment the stack placement relies on.
fn choose_kaslr_slide() -> u64 {
    const ALIGN: u64 = 0x20_0000; // 2 MiB
    // Leave a generous 256 MiB margin below KERNEL_MMIO_BASE.
    let window = (KERNEL_MMIO_BASE - KERNEL_VIRT_BASE) - 0x1000_0000;
    let positions = window / ALIGN;
    if positions == 0 {
        return 0;
    }
    (boot_entropy() % positions) * ALIGN
}

/// Apply `R_AARCH64_RELATIVE` relocations to the freshly-loaded physical image.
///
/// The kernel is a position-independent executable; lld emits one RELATIVE
/// entry per absolute pointer baked into the image. Patching them here — before
/// the image is mapped with W^X permissions and before the cache is cleaned to
/// the point of coherency — lets the kernel run at `KERNEL_VIRT_BASE + slide`
/// with no in-kernel self-relocation and with read-only sections staying
/// read-only.
///
/// With `slide == 0` each slot receives its original link-time value, i.e. the
/// result is byte-identical to a non-PIE static link.
///
/// # Safety
///
/// `phys_base` must point to the loaded kernel image (identity-mapped by UEFI),
/// covering `[min_vaddr, min_vaddr + image_size)` in virtual terms.
unsafe fn apply_relocations(
    kernel_data: &[u8],
    phys_base: u64,
    min_vaddr: u64,
    image_size: u64,
    slide: u64,
) -> Result<usize, &'static str> {
    if kernel_data.len() < 0x40 {
        return Err("ELF too small");
    }
    let e_shoff = read_u64_le(kernel_data, 0x28) as usize;
    let e_shentsize = read_u16_le(kernel_data, 0x3a) as usize;
    let e_shnum = read_u16_le(kernel_data, 0x3c) as usize;
    if e_shoff == 0 || e_shentsize < 64 {
        return Err("no section headers");
    }

    let mut applied = 0usize;
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + 64 > kernel_data.len() {
            break;
        }
        if read_u32_le(kernel_data, sh + 4) != SHT_RELA {
            continue;
        }
        let sh_offset = read_u64_le(kernel_data, sh + 0x18) as usize;
        let sh_size = read_u64_le(kernel_data, sh + 0x20) as usize;
        let count = sh_size / 24; // sizeof(Elf64_Rela)
        for j in 0..count {
            let e = sh_offset + j * 24;
            if e + 24 > kernel_data.len() {
                return Err("relocation entry out of file bounds");
            }
            let r_offset = read_u64_le(kernel_data, e);
            let r_info = read_u64_le(kernel_data, e + 8);
            let r_addend = read_u64_le(kernel_data, e + 16);
            if (r_info & 0xffff_ffff) as u32 != R_AARCH64_RELATIVE {
                return Err("unexpected (non-RELATIVE) relocation type");
            }
            if r_offset < min_vaddr || r_offset + 8 > min_vaddr + image_size {
                return Err("relocation target outside the kernel image");
            }
            let target_phys = phys_base + (r_offset - min_vaddr);
            let value = r_addend.wrapping_add(slide);
            // SAFETY: target_phys lies within the identity-mapped, freshly
            // loaded kernel image; the 8-byte write is bounds-checked above.
            unsafe {
                core::ptr::write_unaligned(target_phys as *mut u64, value);
            }
            applied += 1;
        }
    }
    Ok(applied)
}

/// Load the kernel from the EFI filesystem
///
/// # Arguments
/// * `cpu_count` - Number of CPUs to allocate stacks for (from DTB parsing)
pub fn load_kernel(cpu_count: u32) -> uefi::Result<LoadedKernel> {
    let cpu_count = (cpu_count as usize).clamp(1, MAX_CPUS);
    log::info!(
        "Loading kernel from {} (for {} CPUs)",
        KERNEL_PATH,
        cpu_count
    );
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

    // KASLR: choose a random virtual-address slide and apply the kernel's
    // PIE relocations to the physical image so it can run at a random base.
    let kaslr_slide = choose_kaslr_slide();
    let phys_base = kernel_phys.as_ptr() as u64;
    // SAFETY: the kernel image was just loaded at `phys_base` (identity-mapped
    // by UEFI) and covers [min_vaddr, min_vaddr + total_size).
    match unsafe { apply_relocations(&kernel_data, phys_base, min_vaddr, total_size, kaslr_slide) } {
        Ok(n) => log::info!(
            "KASLR: slide {:#x}, applied {} relocations (kernel base {:#x})",
            kaslr_slide,
            n,
            KERNEL_VIRT_BASE + kaslr_slide
        ),
        Err(e) => {
            log::error!("KASLR relocation failed: {}", e);
            return Err(uefi::Status::LOAD_ERROR.into());
        }
    }

    // Allocate per-CPU kernel stacks (contiguous block for all CPUs)
    let stack_pages_per_cpu = PER_CPU_STACK_SIZE.div_ceil(4096);
    let total_stack_pages = stack_pages_per_cpu * cpu_count;
    let stacks_phys = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        total_stack_pages,
    )?;

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
    // Virtual addresses are placed right after the kernel in the high-half,
    // shifted by the KASLR slide so they track the relocated kernel image.
    let stacks_phys_base = stacks_phys.as_ptr() as u64;
    let stacks_virt_base = min_vaddr + total_size + kaslr_slide;

    let mut per_cpu_stacks = [PerCpuStack::default(); MAX_CPUS];
    for (cpu, stack) in per_cpu_stacks.iter_mut().enumerate().take(cpu_count) {
        let phys_base = stacks_phys_base + (cpu * PER_CPU_STACK_SIZE) as u64;
        let virt_base = stacks_virt_base + (cpu * PER_CPU_STACK_SIZE) as u64;
        // Stack top is at base + size (stack grows downward)
        let virt_top = virt_base + PER_CPU_STACK_SIZE as u64;

        *stack = PerCpuStack {
            phys_base,
            virt_top,
        };
        log::debug!(
            "CPU {} stack: phys_base={:#x}, virt_top={:#x}",
            cpu,
            phys_base,
            virt_top
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
        // Entry, stacks and segment mappings are all shifted by the slide so
        // they address the relocated image.
        entry_virt: header.entry_point() + kaslr_slide,
        size: total_size,
        stack_phys: stack_phys_top,
        stack_virt: stack_virt_top,
        per_cpu_stacks,
        cpu_count: cpu_count as u32,
        segments,
        segment_count,
        virt_base: min_vaddr,
        kaslr_slide,
    })
}
