//! Minimal ELF64 parser for userspace
//!
//! This module provides just enough ELF parsing to load binaries
//! into address spaces. It does not perform full validation.

/// ELF64 file header
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Header {
    e_ident: [u8; 16],      // ELF identification
    e_type: u16,            // Object file type
    e_machine: u16,         // Architecture
    e_version: u32,         // Object file version
    e_entry: u64,           // Entry point virtual address
    e_phoff: u64,           // Program header table offset
    e_shoff: u64,           // Section header table offset
    e_flags: u32,           // Processor-specific flags
    e_ehsize: u16,          // ELF header size
    e_phentsize: u16,       // Program header table entry size
    e_phnum: u16,           // Program header table entry count
    e_shentsize: u16,       // Section header table entry size
    e_shnum: u16,           // Section header table entry count
    e_shstrndx: u16,        // Section header string table index
}

/// ELF64 program header
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64ProgramHeader {
    p_type: u32,            // Segment type
    p_flags: u32,           // Segment flags
    p_offset: u64,          // Segment file offset
    p_vaddr: u64,           // Segment virtual address
    p_paddr: u64,           // Segment physical address (unused)
    p_filesz: u64,          // Segment size in file
    p_memsz: u64,           // Segment size in memory
    p_align: u64,           // Segment alignment
}

// ELF constants
const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Error codes for ELF parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Invalid ELF magic number
    InvalidMagic,
    /// Not a 64-bit ELF
    Not64Bit,
    /// File too small
    TooSmall,
    /// Invalid program header
    InvalidProgramHeader,
}

/// Parsed ELF segment information
#[derive(Clone, Copy)]
pub struct ElfSegment {
    /// Virtual address where segment should be loaded
    pub vaddr: u64,
    /// Offset in file where segment data starts
    pub file_offset: u64,
    /// Size of segment in file
    pub file_size: u64,
    /// Size of segment in memory (may be larger due to BSS)
    pub mem_size: u64,
    /// Segment is readable
    pub readable: bool,
    /// Segment is writable
    pub writable: bool,
    /// Segment is executable
    pub executable: bool,
}

impl ElfSegment {
    /// Get access rights as a bitmap (R=1, W=2, X=4)
    #[expect(dead_code)]
    pub fn rights(&self) -> u64 {
        let mut rights = 0u64;
        if self.readable {
            rights |= 1;
        }
        if self.writable {
            rights |= 2;
        }
        if self.executable {
            rights |= 4;
        }
        rights
    }
}

/// Parsed ELF file
pub struct Elf64<'a> {
    data: &'a [u8],
    header: &'a Elf64Header,
}

impl<'a> Elf64<'a> {
    /// Parse an ELF64 binary
    ///
    /// # Arguments
    ///
    /// * `data` - Raw ELF file data
    ///
    /// # Returns
    ///
    /// Parsed ELF file or error
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        // Check minimum size
        if data.len() < core::mem::size_of::<Elf64Header>() {
            return Err(ElfError::TooSmall);
        }

        // Parse header
        // SAFETY: We verified the size above
        let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

        // Validate magic
        if header.e_ident[0..4] != ELFMAG {
            return Err(ElfError::InvalidMagic);
        }

        // Validate 64-bit
        if header.e_ident[4] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }

        Ok(Self { data, header })
    }

    /// Get entry point address
    pub fn entry(&self) -> u64 {
        self.header.e_entry
    }

    /// Get the highest virtual address used by the ELF
    ///
    /// This is useful for placing the heap after the program image.
    #[expect(dead_code)]
    pub fn brk(&self) -> u64 {
        let mut max_addr = 0u64;
        for segment in self.segments() {
            let end = segment.vaddr.saturating_add(segment.mem_size);
            if end > max_addr {
                max_addr = end;
            }
        }
        max_addr
    }

    /// Iterate over LOAD segments
    pub fn segments(&'a self) -> impl Iterator<Item = ElfSegment> + 'a {
        let phoff = self.header.e_phoff as usize;
        let phnum = self.header.e_phnum as usize;
        let phentsize = self.header.e_phentsize as usize;
        let data = self.data;

        (0..phnum).filter_map(move |i| {
            let offset = phoff + i * phentsize;
            if offset + core::mem::size_of::<Elf64ProgramHeader>() > data.len() {
                return None;
            }

            // SAFETY: We validated the offset above
            let ph = unsafe {
                &*(data.as_ptr().add(offset) as *const Elf64ProgramHeader)
            };

            // Only return LOAD segments
            if ph.p_type != PT_LOAD {
                return None;
            }

            Some(ElfSegment {
                vaddr: ph.p_vaddr,
                file_offset: ph.p_offset,
                file_size: ph.p_filesz,
                mem_size: ph.p_memsz,
                readable: ph.p_flags & PF_R != 0,
                writable: ph.p_flags & PF_W != 0,
                executable: ph.p_flags & PF_X != 0,
            })
        })
    }

    /// Get a slice of the segment data from the file
    pub fn segment_data(&self, segment: &ElfSegment) -> Option<&'a [u8]> {
        let start = segment.file_offset as usize;
        let end = start.checked_add(segment.file_size as usize)?;
        self.data.get(start..end)
    }
}
