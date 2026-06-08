//! ELF loader for Linux binaries
//!
//! Loads a static Linux ELF binary into a restricted VSpace using
//! the MemoryManager's frame allocation and write primitives.

extern crate alloc;
use alloc::vec::Vec;

use crate::mm::{MemoryManager, Vma, map_flags, prot};

// -- ELF constants

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const PAGE_SIZE: u64 = 4096;

// -- ELF structures

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

// -- Auxiliary vector entry types (AT_* from Linux)

pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_HWCAP2: u64 = 26;
}

/// Information about a loaded ELF binary.
pub struct LoadedElf {
    /// Entry point virtual address
    pub entry: u64,
    /// Program header table virtual address (for AT_PHDR)
    pub phdr_addr: u64,
    /// Size of each program header entry
    pub phdr_entry_size: u16,
    /// Number of program header entries
    pub phdr_count: u16,
    /// Top of the loaded segments (page-aligned, for brk base)
    pub brk_base: u64,
}

/// Load a static Linux ELF binary into the Linux VSpace.
///
/// Parses PT_LOAD segments from the ELF, allocates frames via the
/// MemoryManager, copies segment data using frame_write, and registers
/// VMAs for each segment.
pub fn load_elf(mm: &mut MemoryManager, elf_data: &[u8]) -> Result<LoadedElf, &'static str> {
    // -- Parse ELF header

    if elf_data.len() < core::mem::size_of::<Elf64Header>() {
        return Err("ELF too small");
    }

    // SAFETY: We verified the size above. The struct is repr(C) with
    // no alignment requirements beyond u8.
    let header = unsafe { &*(elf_data.as_ptr() as *const Elf64Header) };

    if header.e_ident[0..4] != ELFMAG {
        return Err("invalid ELF magic");
    }
    if header.e_ident[4] != ELFCLASS64 {
        return Err("not ELF64");
    }

    let phoff = header.e_phoff as usize;
    let phnum = header.e_phnum as usize;
    let phentsize = header.e_phentsize as usize;

    // -- Find PT_PHDR virtual address (for AT_PHDR auxv)

    let mut phdr_addr = 0u64;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + core::mem::size_of::<Elf64ProgramHeader>() > elf_data.len() {
            return Err("phdr out of bounds");
        }
        // SAFETY: Bounds checked above.
        let ph = unsafe { &*(elf_data.as_ptr().add(off) as *const Elf64ProgramHeader) };
        if ph.p_type == PT_PHDR {
            phdr_addr = ph.p_vaddr;
            break;
        }
    }

    // If no PT_PHDR, estimate: first LOAD segment base + e_phoff
    if phdr_addr == 0 {
        for i in 0..phnum {
            let off = phoff + i * phentsize;
            // SAFETY: Same as above, we checked bounds in the first loop.
            let ph = unsafe { &*(elf_data.as_ptr().add(off) as *const Elf64ProgramHeader) };
            if ph.p_type == PT_LOAD && ph.p_offset == 0 {
                phdr_addr = ph.p_vaddr + header.e_phoff;
                break;
            }
        }
    }

    // -- Load PT_LOAD segments

    let mut brk_base = 0u64;

    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + core::mem::size_of::<Elf64ProgramHeader>() > elf_data.len() {
            continue;
        }
        // SAFETY: Bounds checked above.
        let ph = unsafe { &*(elf_data.as_ptr().add(off) as *const Elf64ProgramHeader) };

        if ph.p_type != PT_LOAD {
            continue;
        }

        // Convert ELF flags to M6 rights
        let mut rights = 0u64;
        let mut linux_prot = 0u64;
        if ph.p_flags & PF_R != 0 {
            rights |= 1;
            linux_prot |= prot::PROT_READ;
        }
        if ph.p_flags & PF_W != 0 {
            rights |= 2;
            linux_prot |= prot::PROT_WRITE;
        }
        if ph.p_flags & PF_X != 0 {
            rights |= 4;
            linux_prot |= prot::PROT_EXEC;
        }

        // Get segment data from file
        let file_start = ph.p_offset as usize;
        let file_end = file_start + ph.p_filesz as usize;
        if file_end > elf_data.len() {
            return Err("segment data out of bounds");
        }

        let segment_data = &elf_data[file_start..file_end];

        // Write segment data into the Linux VSpace.
        // write_to_linux handles page-aligned allocation and partial pages.
        // For segments with memsz > filesz (BSS), we need to write zeros
        // for the remainder — write_to_linux already zeros whole frames
        // before writing data, so BSS pages within the file-backed region
        // are automatically zeroed. We just need to allocate extra pages
        // for the memsz - filesz tail.
        mm.write_to_linux(ph.p_vaddr, segment_data, rights)?;

        // Allocate zero pages for BSS (memsz > filesz)
        if ph.p_memsz > ph.p_filesz {
            let bss_start = ph.p_vaddr + ph.p_filesz;
            let bss_end = ph.p_vaddr + ph.p_memsz;
            let bss_page_start = (bss_start + PAGE_SIZE - 1) & !0xFFF;
            let mut page = bss_page_start;
            while page < bss_end {
                // Only allocate pages that weren't already allocated by write_to_linux
                if mm.find_frame(page).is_none() {
                    mm.alloc_and_map_page(page, rights)?;
                    // Frame is zeroed by the kernel on Retype
                }
                page += PAGE_SIZE;
            }
        }

        // Register VMA for this segment
        let vma_start = ph.p_vaddr & !0xFFF;
        let vma_end = (ph.p_vaddr + ph.p_memsz + PAGE_SIZE - 1) & !0xFFF;
        mm.add_vma(Vma {
            start: vma_start,
            end: vma_end,
            prot: linux_prot,
            flags: map_flags::MAP_PRIVATE,
            offset: 0,
        });

        // Track highest loaded address for brk base
        let seg_end = (ph.p_vaddr + ph.p_memsz + PAGE_SIZE - 1) & !0xFFF;
        if seg_end > brk_base {
            brk_base = seg_end;
        }
    }

    Ok(LoadedElf {
        entry: header.e_entry,
        phdr_addr,
        phdr_entry_size: header.e_phentsize,
        phdr_count: header.e_phnum,
        brk_base,
    })
}

// -- Linux user stack construction

/// Linux stack layout for initial process setup.
///
/// The stack is built top-down: strings first, then the structured
/// region with argc/argv/envp/auxv. The result is written into the
/// Linux VSpace via the MemoryManager.
///
/// Default Linux stack size (8 pages = 32KB).
const STACK_PAGES: u64 = 8;

/// Stack top address for the Linux process.
const LINUX_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;

/// Build and write the initial Linux user stack.
///
/// Returns the initial stack pointer (pointing at argc).
pub fn build_linux_stack(
    mm: &mut MemoryManager,
    args: &[&[u8]],
    env: &[&[u8]],
    loaded: &LoadedElf,
) -> Result<u64, &'static str> {
    let stack_base = LINUX_STACK_TOP - STACK_PAGES * PAGE_SIZE;

    // Register stack VMA
    mm.add_vma(Vma {
        start: stack_base,
        end: LINUX_STACK_TOP,
        prot: prot::PROT_READ | prot::PROT_WRITE,
        flags: map_flags::MAP_PRIVATE | map_flags::MAP_ANONYMOUS | map_flags::MAP_STACK,
        offset: 0,
    });

    // Allocate stack pages
    let rights = 1 | 2; // R+W
    let mut page = stack_base;
    while page < LINUX_STACK_TOP {
        mm.alloc_and_map_page(page, rights)?;
        page += PAGE_SIZE;
    }

    // Build the stack content in a local buffer, then write it all at once.
    // We build from the top down conceptually, but collect into a buffer.
    let stack_size = (STACK_PAGES * PAGE_SIZE) as usize;
    let mut stack_buf = alloc::vec![0u8; stack_size];
    let mut sp = LINUX_STACK_TOP;

    // Helper: write bytes at position (moves sp down, returns new sp)
    let write_bytes = |buf: &mut Vec<u8>, sp: &mut u64, data: &[u8]| {
        *sp -= data.len() as u64;
        let off = (*sp - stack_base) as usize;
        buf[off..off + data.len()].copy_from_slice(data);
    };

    // -- Phase 1: Write strings (top of stack)

    // AT_RANDOM: 16 random bytes
    sp -= 16;
    let random_addr = sp;
    // Use a simple seed — real randomness from get_random would be better
    let random_off = (random_addr - stack_base) as usize;
    for i in 0..16 {
        stack_buf[random_off + i] = (i as u8).wrapping_mul(0x6D).wrapping_add(0x37);
    }

    // Write argument strings (with null terminators)
    let mut argv_addrs = Vec::with_capacity(args.len());
    for arg in args {
        sp -= 1; // null terminator
        write_bytes(&mut stack_buf, &mut sp, arg);
        argv_addrs.push(sp);
    }

    // Write environment strings
    let mut envp_addrs = Vec::with_capacity(env.len());
    for e in env {
        sp -= 1; // null terminator
        write_bytes(&mut stack_buf, &mut sp, e);
        envp_addrs.push(sp);
    }

    // Align to 16 bytes
    sp &= !0xF;

    // -- Phase 2: Build structured region (argc/argv/envp/auxv)
    // We need to calculate the total size first, then write bottom-up.

    let auxv_entries: [(u64, u64); 13] = [
        (auxv::AT_PAGESZ, 4096),
        (auxv::AT_PHDR, loaded.phdr_addr),
        (auxv::AT_PHENT, loaded.phdr_entry_size as u64),
        (auxv::AT_PHNUM, loaded.phdr_count as u64),
        (auxv::AT_ENTRY, loaded.entry),
        (auxv::AT_UID, 0),
        (auxv::AT_EUID, 0),
        (auxv::AT_GID, 0),
        (auxv::AT_EGID, 0),
        (auxv::AT_SECURE, 0),
        (auxv::AT_RANDOM, random_addr),
        (auxv::AT_CLKTCK, 100),
        (auxv::AT_NULL, 0),
    ];

    // Total structured region size
    let auxv_size = auxv_entries.len() * 16;
    let envp_ptrs_size = (envp_addrs.len() + 1) * 8; // +1 for NULL
    let argv_ptrs_size = (argv_addrs.len() + 1) * 8; // +1 for NULL
    let argc_size = 8;
    let total = auxv_size + envp_ptrs_size + argv_ptrs_size + argc_size;

    sp -= total as u64;
    sp &= !0xF; // 16-byte alignment

    let final_sp = sp;
    let mut pos = sp;

    // Write argc
    let off = (pos - stack_base) as usize;
    stack_buf[off..off + 8].copy_from_slice(&(args.len() as u64).to_le_bytes());
    pos += 8;

    // Write argv pointers
    for addr in &argv_addrs {
        let off = (pos - stack_base) as usize;
        stack_buf[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        pos += 8;
    }
    // NULL terminator
    let off = (pos - stack_base) as usize;
    stack_buf[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    pos += 8;

    // Write envp pointers
    for addr in &envp_addrs {
        let off = (pos - stack_base) as usize;
        stack_buf[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        pos += 8;
    }
    // NULL terminator
    let off = (pos - stack_base) as usize;
    stack_buf[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    pos += 8;

    // Write auxiliary vector
    for (key, val) in &auxv_entries {
        let off = (pos - stack_base) as usize;
        stack_buf[off..off + 8].copy_from_slice(&key.to_le_bytes());
        pos += 8;
        let off = (pos - stack_base) as usize;
        stack_buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
        pos += 8;
    }

    // Write the entire stack buffer to the Linux VSpace.
    // Since we already allocated the frames above, we write directly
    // to the frame capabilities.
    let mut buf_off = 0usize;
    let mut page_addr = stack_base;
    while page_addr < LINUX_STACK_TOP {
        if let Some(frame_slot) = mm.find_frame(page_addr) {
            m6_syscall::invoke::frame_write(
                mm.frame_cptr(frame_slot),
                0,
                stack_buf[buf_off..].as_ptr(),
                PAGE_SIZE as usize,
            )
            .map_err(|_| "stack frame_write failed")?;
        }
        buf_off += PAGE_SIZE as usize;
        page_addr += PAGE_SIZE;
    }

    Ok(final_sp)
}
