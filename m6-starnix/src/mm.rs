//! Memory management for Linux processes
//!
//! Implements the virtual memory abstraction layer using M6 capabilities.
//! This module manages the Linux process address space including:
//! - VMA (Virtual Memory Area) tracking
//! - Demand paging via REASON_EXCEPTION fault handling
//! - COW (Copy-on-Write) via PTE bit 55
//! - mmap/munmap/mprotect/brk implementation

extern crate alloc;
use alloc::collections::BTreeMap;
use m6_cap::ObjectType;
use m6_syscall::invoke::*;
use m6_syscall::slot_to_cptr;

/// Protection flags (matching Linux mmap prot values).
pub mod prot {
    pub const PROT_NONE: u64 = 0;
    pub const PROT_READ: u64 = 1;
    pub const PROT_WRITE: u64 = 2;
    pub const PROT_EXEC: u64 = 4;
}

/// Map flags (matching Linux mmap flags).
pub mod map_flags {
    pub const MAP_SHARED: u64 = 0x01;
    pub const MAP_PRIVATE: u64 = 0x02;
    pub const MAP_FIXED: u64 = 0x10;
    pub const MAP_ANONYMOUS: u64 = 0x20;
    pub const MAP_GROWSDOWN: u64 = 0x100;
    pub const MAP_STACK: u64 = 0x20000;
}

const PAGE_SIZE: u64 = 4096;

/// A virtual memory area (VMA) in the Linux process.
#[derive(Debug, Clone)]
pub struct Vma {
    /// Start virtual address (page-aligned)
    pub start: u64,
    /// End virtual address (exclusive, page-aligned)
    pub end: u64,
    /// Protection flags
    pub prot: u64,
    /// Map flags
    pub flags: u64,
    /// File offset (0 for anonymous)
    pub offset: u64,
}

impl Vma {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Convert Linux prot flags to M6 rights bitmap (R=1, W=2, X=4).
    pub fn to_m6_rights(&self) -> u64 {
        let mut rights = 0u64;
        if self.prot & prot::PROT_READ != 0 {
            rights |= 1;
        }
        if self.prot & prot::PROT_WRITE != 0 {
            rights |= 2;
        }
        if self.prot & prot::PROT_EXEC != 0 {
            rights |= 4;
        }
        rights
    }
}

/// Page table level sizes for ARM64.
const L1_SIZE: u64 = 512 * 1024 * 1024 * 1024; // 512GB
const L2_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const L3_SIZE: u64 = 2 * 1024 * 1024; // 2MB

/// Memory manager for a single Linux process.
///
/// Tracks VMAs and manages the mapping between Linux virtual addresses
/// and M6 Frame capabilities. Also tracks which frame capability is
/// mapped at each page so we can read/write Linux user memory.
pub struct MemoryManager {
    /// VMAs sorted by start address
    vmas: BTreeMap<u64, Vma>,
    /// Mapping from page-aligned VA to frame capability slot
    page_frames: BTreeMap<u64, u64>,
    /// Current brk position
    brk: u64,
    /// VSpace capability pointer for this process
    vspace_cptr: u64,
    /// Root CNode capability pointer
    root_cnode: u64,
    /// Untyped memory capability pointer
    ram_untyped: u64,
    /// CNode radix for CPtr computation
    cnode_radix: u8,
    /// Next free capability slot
    next_free_slot: u64,
    /// Next free virtual address for mmap
    mmap_base: u64,
    /// Installed L1 page table regions
    l1_regions: [u64; 4],
    l1_count: usize,
    /// Installed L2 page table regions
    l2_regions: [u64; 16],
    l2_count: usize,
    /// Installed L3 page table regions
    l3_regions: [u64; 128],
    l3_count: usize,
}

impl MemoryManager {
    /// Create a new memory manager for a Linux process.
    pub fn new(
        vspace_cptr: u64,
        root_cnode: u64,
        ram_untyped: u64,
        cnode_radix: u8,
        next_free_slot: u64,
        initial_brk: u64,
    ) -> Self {
        Self {
            vmas: BTreeMap::new(),
            page_frames: BTreeMap::new(),
            brk: initial_brk,
            vspace_cptr,
            root_cnode,
            ram_untyped,
            cnode_radix,
            next_free_slot,
            mmap_base: 0x0000_7F00_0000_0000,
            l1_regions: [u64::MAX; 4],
            l1_count: 0,
            l2_regions: [u64::MAX; 16],
            l2_count: 0,
            l3_regions: [u64::MAX; 128],
            l3_count: 0,
        }
    }

    fn cptr(&self, slot: u64) -> u64 {
        slot_to_cptr(slot, self.cnode_radix)
    }

    /// Import page table state from the loader's initial setup.
    pub fn import_page_tables(&mut self, l1: &[u64], l2: &[u64], l3: &[u64]) {
        let l1_len = l1.len().min(self.l1_regions.len());
        self.l1_regions[..l1_len].copy_from_slice(&l1[..l1_len]);
        self.l1_count = l1_len;

        let l2_len = l2.len().min(self.l2_regions.len());
        self.l2_regions[..l2_len].copy_from_slice(&l2[..l2_len]);
        self.l2_count = l2_len;

        let l3_len = l3.len().min(self.l3_regions.len());
        self.l3_regions[..l3_len].copy_from_slice(&l3[..l3_len]);
        self.l3_count = l3_len;
    }

    /// Add a VMA (used by the ELF loader and mmap).
    pub fn add_vma(&mut self, vma: Vma) {
        self.vmas.insert(vma.start, vma);
    }

    /// Find the VMA containing a given address.
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .range(..=addr)
            .next_back()
            .map(|(_, vma)| vma)
            .filter(|vma| vma.contains(addr))
    }

    /// Ensure page tables exist for a virtual address in the Linux VSpace.
    pub fn ensure_page_tables(&mut self, vaddr: u64) -> Result<(), &'static str> {
        let l1_base = vaddr & !(L1_SIZE - 1);
        let l2_base = vaddr & !(L2_SIZE - 1);
        let l3_base = vaddr & !(L3_SIZE - 1);

        if !self.l1_regions[..self.l1_count].contains(&l1_base) {
            let slot = self.alloc_slot();
            retype(
                self.cptr(self.ram_untyped),
                5, // L1 page table
                0,
                self.cptr(self.root_cnode),
                slot,
                1,
            )
            .map_err(|_| "retype L1 failed")?;
            map_page_table(self.cptr(self.vspace_cptr), self.cptr(slot), l1_base, 1)
                .map_err(|_| "map L1 failed")?;
            if self.l1_count < self.l1_regions.len() {
                self.l1_regions[self.l1_count] = l1_base;
                self.l1_count += 1;
            }
        }

        if !self.l2_regions[..self.l2_count].contains(&l2_base) {
            let slot = self.alloc_slot();
            retype(
                self.cptr(self.ram_untyped),
                6, // L2 page table
                0,
                self.cptr(self.root_cnode),
                slot,
                1,
            )
            .map_err(|_| "retype L2 failed")?;
            map_page_table(self.cptr(self.vspace_cptr), self.cptr(slot), l2_base, 2)
                .map_err(|_| "map L2 failed")?;
            if self.l2_count < self.l2_regions.len() {
                self.l2_regions[self.l2_count] = l2_base;
                self.l2_count += 1;
            }
        }

        if !self.l3_regions[..self.l3_count].contains(&l3_base) {
            let slot = self.alloc_slot();
            retype(
                self.cptr(self.ram_untyped),
                7, // L3 page table
                0,
                self.cptr(self.root_cnode),
                slot,
                1,
            )
            .map_err(|_| "retype L3 failed")?;
            map_page_table(self.cptr(self.vspace_cptr), self.cptr(slot), l3_base, 3)
                .map_err(|_| "map L3 failed")?;
            if self.l3_count < self.l3_regions.len() {
                self.l3_regions[self.l3_count] = l3_base;
                self.l3_count += 1;
            }
        }

        Ok(())
    }

    /// Allocate a frame and map it at the given virtual address.
    pub fn alloc_and_map_page(&mut self, vaddr: u64, rights: u64) -> Result<u64, &'static str> {
        let page_vaddr = vaddr & !0xFFF;
        self.ensure_page_tables(page_vaddr)?;

        let frame_slot = self.alloc_slot();
        retype(
            self.cptr(self.ram_untyped),
            ObjectType::Frame as u64,
            12, // 4KB
            self.cptr(self.root_cnode),
            frame_slot,
            1,
        )
        .map_err(|_| "retype frame failed")?;

        map_frame(
            self.cptr(self.vspace_cptr),
            self.cptr(frame_slot),
            page_vaddr,
            rights,
            0,
        )
        .map_err(|_| "map frame failed")?;

        self.page_frames.insert(page_vaddr, frame_slot);

        Ok(frame_slot)
    }

    /// Read data from the Linux address space via frame_read.
    ///
    /// Uses the tracked frame capabilities to read user memory without
    /// mapping it into Starnix's own VSpace.
    pub fn read_from_linux(&self, vaddr: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut buf_pos = 0usize;
        let mut current_addr = vaddr;

        while buf_pos < buf.len() {
            let page_addr = current_addr & !0xFFF;
            let page_offset = (current_addr - page_addr) as usize;
            let remaining = buf.len() - buf_pos;
            let available = 4096 - page_offset;
            let copy_len = remaining.min(available);

            let frame_slot = self.page_frames.get(&page_addr).ok_or("page not mapped")?;

            frame_read(
                self.cptr(*frame_slot),
                page_offset as u64,
                buf[buf_pos..].as_mut_ptr(),
                copy_len,
            )
            .map_err(|_| "frame_read failed")?;

            buf_pos += copy_len;
            current_addr += copy_len as u64;
        }

        Ok(())
    }

    /// Write data to the Linux VSpace by allocating frames and using frame_write.
    pub fn write_to_linux(
        &mut self,
        vaddr: u64,
        data: &[u8],
        rights: u64,
    ) -> Result<(), &'static str> {
        if data.is_empty() {
            return Ok(());
        }

        let vaddr_start = vaddr & !0xFFF;
        let vaddr_end = (vaddr + data.len() as u64 + 0xFFF) & !0xFFF;
        let offset_in_first_page = (vaddr - vaddr_start) as usize;

        let mut data_pos = 0usize;
        let mut page_vaddr = vaddr_start;

        while page_vaddr < vaddr_end {
            let frame_slot = self.alloc_and_map_page(page_vaddr, rights)?;

            // Zero the frame first
            static ZEROS: [u8; 4096] = [0u8; 4096];
            let _ = frame_write(self.cptr(frame_slot), 0, ZEROS.as_ptr(), 4096);

            // Calculate what data goes on this page
            let page_offset = if page_vaddr == vaddr_start {
                offset_in_first_page
            } else {
                0
            };
            let remaining = data.len() - data_pos;
            let space_on_page = 4096 - page_offset;
            let copy_len = remaining.min(space_on_page);

            if copy_len > 0 {
                frame_write(
                    self.cptr(frame_slot),
                    page_offset as u64,
                    data[data_pos..].as_ptr(),
                    copy_len,
                )
                .map_err(|_| "frame_write failed")?;
                data_pos += copy_len;
            }

            page_vaddr += PAGE_SIZE;
        }

        Ok(())
    }

    fn alloc_slot(&mut self) -> u64 {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }

    /// Handle brk syscall.
    pub fn handle_brk(&mut self, addr: u64) -> u64 {
        if addr == 0 {
            return self.brk;
        }

        let aligned = (addr + 0xFFF) & !0xFFF;
        if aligned > self.brk {
            self.add_vma(Vma {
                start: self.brk,
                end: aligned,
                prot: prot::PROT_READ | prot::PROT_WRITE,
                flags: map_flags::MAP_PRIVATE | map_flags::MAP_ANONYMOUS,
                offset: 0,
            });
        }

        self.brk = aligned;
        self.brk
    }

    /// Handle mmap syscall.
    pub fn handle_mmap(
        &mut self,
        addr: u64,
        length: u64,
        protection: u64,
        flags: u64,
        _fd: u64,
        _offset: u64,
    ) -> i64 {
        if length == 0 {
            return -22; // EINVAL
        }

        let aligned_len = (length + 0xFFF) & !0xFFF;

        let vaddr = if flags & map_flags::MAP_FIXED != 0 {
            if addr & 0xFFF != 0 {
                return -22; // EINVAL
            }
            addr
        } else {
            let result = self.mmap_base;
            self.mmap_base += aligned_len;
            result
        };

        self.add_vma(Vma {
            start: vaddr,
            end: vaddr + aligned_len,
            prot: protection,
            flags,
            offset: 0,
        });

        vaddr as i64
    }

    /// Handle munmap syscall.
    pub fn handle_munmap(&mut self, addr: u64, length: u64) -> i64 {
        if addr & 0xFFF != 0 || length == 0 {
            return -22; // EINVAL
        }

        let end = addr + ((length + 0xFFF) & !0xFFF);
        self.vmas
            .retain(|_, vma| vma.end <= addr || vma.start >= end);

        // TODO: Actually unmap frames via UnmapFrame syscall
        0
    }

    /// Handle mprotect syscall.
    pub fn handle_mprotect(&mut self, addr: u64, length: u64, protection: u64) -> i64 {
        if addr & 0xFFF != 0 || length == 0 {
            return -22; // EINVAL
        }

        let end = addr + ((length + 0xFFF) & !0xFFF);
        for vma in self.vmas.values_mut() {
            if vma.start >= addr && vma.end <= end {
                vma.prot = protection;
            }
        }

        // TODO: Actually change page protections via UnmapFrame + MapFrame
        0
    }

    /// Handle a page fault at the given address.
    ///
    /// Returns true if the fault was handled (page was mapped).
    pub fn handle_page_fault(&mut self, fault_addr: u64, is_write: bool) -> bool {
        let page_addr = fault_addr & !0xFFF;

        let vma = match self.find_vma(page_addr) {
            Some(v) => v.clone(),
            None => return false,
        };

        // Check permissions
        if is_write && (vma.prot & prot::PROT_WRITE == 0) {
            return false;
        }

        // Demand paging: allocate a frame and map it
        let rights = vma.to_m6_rights();
        self.alloc_and_map_page(page_addr, rights).is_ok()
    }

    /// Look up the frame slot for a page-aligned virtual address.
    pub fn find_frame(&self, page_addr: u64) -> Option<u64> {
        self.page_frames.get(&page_addr).copied()
    }

    /// Convert a slot to a CPtr (public for loader access).
    pub fn frame_cptr(&self, slot: u64) -> u64 {
        self.cptr(slot)
    }

    /// Get the VSpace capability pointer.
    pub fn vspace_cptr(&self) -> u64 {
        self.vspace_cptr
    }

    /// Get the current brk.
    pub fn brk(&self) -> u64 {
        self.brk
    }

    /// Set the brk position (used after ELF loading to initialise the heap base).
    pub fn set_brk(&mut self, addr: u64) {
        self.brk = addr;
    }

    /// Get the next free slot (useful after setup for the syscall loop).
    pub fn next_free_slot(&self) -> u64 {
        self.next_free_slot
    }
}
