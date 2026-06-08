//! Minimal `no_std` `process_builder::elf_load` shim for the M6 Starnix fork.
//!
//! Upstream `process_builder` is the Fuchsia ELF loader. The Starnix task loader
//! (`task/loader.rs`) uses just its `elf_load` surface — the `Mapper` trait plus
//! `loaded_elf_info`/`map_elf_segments` — to compute an ELF's load span and map
//! its PT_LOAD segments through a caller-supplied mapper (which, in Starnix,
//! drives the `MemoryManager`).
//!
//! This shim reimplements that surface against the M6 `elf_parse` + `zx` shims:
//! `loaded_elf_info` is a faithful low/high computation; `map_elf_segments` maps
//! each PT_LOAD segment via the `Mapper`. The .bss handling (segments where
//! `memsz > filesz`) maps the whole memsz span from the file VMO — correct
//! zero-fill of the trailing partial page + anonymous tail is an M4 refinement
//! once the M6 memory model (M3 VMO↔capability seam) is wired; noted inline.

#![no_std]

extern crate alloc;

pub mod elf_load {
    use elf_parse::{Elf64Headers, SegmentType};

    /// 4 KiB page size (aarch64 / M6).
    const PAGE_SIZE: usize = 4096;

    /// ELF program-flag bits.
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    const PF_R: u32 = 4;

    /// Error type for ELF loading.
    #[derive(Debug)]
    pub enum ElfLoadError {
        /// A segment could not be mapped (carries the underlying zx status).
        MapError(zx::Status),
        /// The ELF had no loadable segments.
        NothingToLoad,
    }

    /// The address span an ELF occupies once loaded (page-aligned).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct LoadedElfInfo {
        /// Lowest mapped virtual address.
        pub low: usize,
        /// One past the highest mapped virtual address.
        pub high: usize,
    }

    /// Maps VMO ranges into an address space. Implemented by the caller
    /// (`task/loader.rs`) on top of the Starnix `MemoryManager`.
    pub trait Mapper {
        /// Maps `length` bytes (the full memsz span, page-rounded) at
        /// `vmar_offset` with `vmar_flags`, returning the mapped address. Only
        /// the first `file_length` bytes are file-backed (from `vmo` at
        /// `vmo_offset`); the remaining `length - file_length` bytes are the
        /// `.bss` tail and MUST read back as zero.
        fn map(
            &self,
            vmar_offset: usize,
            vmo: &zx::Vmo,
            vmo_offset: u64,
            length: usize,
            file_length: usize,
            vmar_flags: zx::VmarFlags,
        ) -> Result<usize, zx::Status>;
    }

    fn page_down(v: usize) -> usize {
        v & !(PAGE_SIZE - 1)
    }

    fn page_up(v: usize) -> usize {
        (v + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }

    /// Computes the page-aligned `[low, high)` span covering all PT_LOAD
    /// segments of `headers`.
    pub fn loaded_elf_info(headers: &Elf64Headers) -> LoadedElfInfo {
        let mut low = usize::MAX;
        let mut high = 0usize;
        for ph in headers.program_headers() {
            if matches!(ph.segment_type(), Ok(SegmentType::Load)) {
                let start = page_down(ph.vaddr);
                let end = page_up(ph.vaddr.wrapping_add(ph.memsz as usize));
                if start < low {
                    low = start;
                }
                if end > high {
                    high = end;
                }
            }
        }
        if low == usize::MAX {
            low = 0;
        }
        LoadedElfInfo { low, high }
    }

    fn vmar_flags_for(flags: u32) -> zx::VmarFlags {
        let mut f = zx::VmarFlags::empty();
        if flags & PF_R != 0 {
            f |= zx::VmarFlags::PERM_READ;
        }
        if flags & PF_W != 0 {
            f |= zx::VmarFlags::PERM_WRITE;
        }
        if flags & PF_X != 0 {
            f |= zx::VmarFlags::PERM_EXECUTE;
        }
        f
    }

    /// Maps every PT_LOAD segment of `headers` from `vmo` through `mapper`.
    ///
    /// `vmar_offset_bias` is added to each segment's page-aligned vaddr to form
    /// the mapper offset (used for position-independent executables relocated by
    /// the caller). Returns the first map error encountered.
    pub fn map_elf_segments(
        vmo: &zx::Vmo,
        headers: &Elf64Headers,
        mapper: &dyn Mapper,
        vmar_base: usize,
        vmar_offset_bias: usize,
    ) -> Result<(), ElfLoadError> {
        let mut mapped_any = false;
        for ph in headers.program_headers() {
            if !matches!(ph.segment_type(), Ok(SegmentType::Load)) {
                continue;
            }
            if ph.memsz == 0 {
                continue;
            }
            let vaddr = ph.vaddr;
            let page_offset = vaddr - page_down(vaddr);
            // `vmar_offset` is relative to the VMAR base: the `Mapper` adds the
            // VMAR base (`mm.base_addr`) back when it maps, so we must subtract
            // `vmar_base` here or each segment lands `vmar_base` too high (a
            // translation fault at the absolute entry PC). `vmar_offset_bias`
            // carries the PIE/interpreter relocation.
            let vmar_offset =
                page_down(vaddr).wrapping_sub(vmar_base).wrapping_add(vmar_offset_bias);
            let vmo_offset = (ph.offset - page_offset) as u64;
            let length = page_up(page_offset + ph.memsz as usize);
            // File-backed bytes from the page-aligned start. Anything past this
            // (the `.bss` tail) must be zero, NOT read from the file — reading
            // further would pull in whatever follows the segment in the file
            // (e.g. `.shstrtab`), corrupting `.bss`.
            let file_length = page_offset + ph.filesz as usize;
            mapper
                .map(vmar_offset, vmo, vmo_offset, length, file_length, vmar_flags_for(ph.flags))
                .map_err(ElfLoadError::MapError)?;
            mapped_any = true;
        }
        if mapped_any { Ok(()) } else { Err(ElfLoadError::NothingToLoad) }
    }
}
