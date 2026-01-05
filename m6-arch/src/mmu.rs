//! MMU (Memory Management Unit) Support
//!
//! Provides page table management and virtual memory support for ARM64.
//! Uses 4KB pages with 4-level page tables (48-bit VA).

use crate::cpu::{dsb_sy, isb};
use aarch64_cpu::registers::*;
use core::arch::asm;
use m6_common::memory::page::SIZE_4K;
use spin::Mutex;

/// Number of entries per page table
pub const ENTRIES_PER_TABLE: usize = 512;

/// TCR_EL1 configuration constants
mod tcr_config {
    /// T0SZ: Virtual address size for TTBR0 (16 = 48-bit VA)
    pub const T0SZ: u64 = 16;
    /// T1SZ: Virtual address size for TTBR1 (16 = 48-bit VA)
    pub const T1SZ: u64 = 16;
    /// TG0: Granule size for TTBR0 (0b00 = 4KB)
    /// Reserved for explicit TTBR0 configuration when needed
    #[allow(dead_code)]
    pub const TG0_4KB: u64 = 0b00;
    /// TG1: Granule size for TTBR1 (0b10 = 4KB)
    pub const TG1_4KB: u64 = 0b10 << 30;
    /// IPS: Intermediate Physical Address Size (0b101 = 48-bit)
    pub const IPS_48BIT: u64 = 0b101 << 32;
    /// SH0: Shareability for TTBR0 (0b11 = Inner Shareable)
    pub const SH0_INNER: u64 = 0b11 << 12;
    /// SH1: Shareability for TTBR1 (0b11 = Inner Shareable)
    pub const SH1_INNER: u64 = 0b11 << 28;
    /// ORGN0: Outer cacheability for TTBR0 (0b01 = WB-RWA)
    pub const ORGN0_WBRWA: u64 = 0b01 << 10;
    /// ORGN1: Outer cacheability for TTBR1 (0b01 = WB-RWA)
    pub const ORGN1_WBRWA: u64 = 0b01 << 26;
    /// IRGN0: Inner cacheability for TTBR0 (0b01 = WB-RWA)
    pub const IRGN0_WBRWA: u64 = 0b01 << 8;
    /// IRGN1: Inner cacheability for TTBR1 (0b01 = WB-RWA)
    pub const IRGN1_WBRWA: u64 = 0b01 << 24;
}

/// Page table entry flags
pub mod flags {
    /// Entry is valid
    pub const VALID: u64 = 1 << 0;
    /// Table descriptor (points to next level table)
    pub const TABLE: u64 = 1 << 1;
    /// Page descriptor (for level 3)
    pub const PAGE: u64 = 1 << 1;
    /// Access flag (set by hardware or software)
    pub const AF: u64 = 1 << 10;
    /// Shareability: Non-shareable
    pub const SH_NONE: u64 = 0 << 8;
    /// Shareability: Outer Shareable
    pub const SH_OUTER: u64 = 2 << 8;
    /// Shareability: Inner Shareable
    pub const SH_INNER: u64 = 3 << 8;
    /// Access Permission: Read-only at EL1
    pub const AP_RO: u64 = 1 << 7;
    /// Access Permission: Accessible from EL0
    pub const AP_EL0: u64 = 1 << 6;
    /// Not global (ASID-specific)
    pub const NG: u64 = 1 << 11;
    /// Unprivileged Execute Never
    pub const UXN: u64 = 1 << 54;
    /// Privileged Execute Never
    pub const PXN: u64 = 1 << 53;
    /// Contiguous hint
    pub const CONTIGUOUS: u64 = 1 << 52;
    /// Dirty bit modifier
    pub const DBM: u64 = 1 << 51;

    /// Memory attribute index shift
    pub const ATTR_INDEX_SHIFT: u64 = 2;

    /// Normal memory (Write-Back, Read-Allocate, Write-Allocate)
    pub const ATTR_NORMAL: u64 = 0 << ATTR_INDEX_SHIFT;
    /// Device memory (nGnRnE)
    pub const ATTR_DEVICE: u64 = 1 << ATTR_INDEX_SHIFT;
    /// Non-cacheable normal memory
    pub const ATTR_NORMAL_NC: u64 = 2 << ATTR_INDEX_SHIFT;

    /// Kernel code (RX)
    pub const KERNEL_CODE: u64 = VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | UXN;
    /// Kernel data (RW, no execute)
    pub const KERNEL_DATA: u64 = VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | UXN | PXN;
    /// Kernel read-only data
    pub const KERNEL_RODATA: u64 = VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | UXN | PXN | AP_RO;
    /// User code (RX)
    pub const USER_CODE: u64 = VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | AP_EL0 | PXN | NG;
    /// User data (RW, no execute)
    pub const USER_DATA: u64 =
        VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | AP_EL0 | UXN | PXN | NG;
    /// User read-only data
    pub const USER_RODATA: u64 =
        VALID | PAGE | AF | SH_INNER | ATTR_NORMAL | AP_EL0 | UXN | PXN | AP_RO | NG;
    /// Device MMIO (for device registers)
    pub const DEVICE_MMIO: u64 = VALID | PAGE | AF | SH_NONE | ATTR_DEVICE | UXN | PXN;
    /// Table descriptor
    pub const TABLE_DESC: u64 = VALID | TABLE;
}

/// Physical address mask for page table entries
pub const PHYS_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// A single page table (512 entries, 4KB)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create an empty page table
    pub const fn empty() -> Self {
        Self {
            entries: [0; ENTRIES_PER_TABLE],
        }
    }

    /// Get an entry by index
    #[inline]
    pub fn get(&self, index: usize) -> u64 {
        self.entries[index]
    }

    /// Set an entry by index
    #[inline]
    pub fn set(&mut self, index: usize, value: u64) {
        self.entries[index] = value;
    }

    /// Check if an entry is valid
    #[inline]
    pub fn is_valid(&self, index: usize) -> bool {
        self.entries[index] & flags::VALID != 0
    }

    /// Check if an entry is a table descriptor
    #[inline]
    pub fn is_table(&self, index: usize) -> bool {
        let entry = self.entries[index];
        (entry & flags::VALID != 0) && (entry & flags::TABLE != 0)
    }

    /// Get the physical address from a table entry
    #[inline]
    pub fn table_address(&self, index: usize) -> u64 {
        self.entries[index] & PHYS_ADDR_MASK
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            *entry = 0;
        }
    }
}

/// Page table level indices from a virtual address
#[derive(Debug, Clone, Copy)]
pub struct VirtAddrParts {
    /// Level 0 index (PGD)
    pub l0: usize,
    /// Level 1 index (PUD)
    pub l1: usize,
    /// Level 2 index (PMD)
    pub l2: usize,
    /// Level 3 index (PTE)
    pub l3: usize,
    /// Page offset
    pub offset: usize,
}

impl VirtAddrParts {
    /// Extract page table indices from a virtual address
    #[inline]
    pub const fn from_vaddr(vaddr: u64) -> Self {
        Self {
            l0: ((vaddr >> 39) & 0x1FF) as usize,
            l1: ((vaddr >> 30) & 0x1FF) as usize,
            l2: ((vaddr >> 21) & 0x1FF) as usize,
            l3: ((vaddr >> 12) & 0x1FF) as usize,
            offset: (vaddr & 0xFFF) as usize,
        }
    }
}

/// MMU controller
pub struct Mmu {
    /// Whether the MMU is enabled
    enabled: bool,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    /// Create a new MMU controller
    pub const fn new() -> Self {
        Self { enabled: false }
    }

    /// Check if MMU is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled || (SCTLR_EL1.get() & 1) != 0
    }

    /// Initialize the MMU with the given page tables
    pub fn enable(&mut self, ttbr0: u64, ttbr1: u64) {
        // Set MAIR (Memory Attribute Indirection Register)
        // Index 0: Normal WB-RWA (0xFF)
        // Index 1: Device-nGnRE (0x04) - allows early write acknowledgement
        // Index 2: Normal Non-cacheable (0x44)
        let mair: u64 = 0x00_00_00_00_44_04_FF;
        MAIR_EL1.set(mair);

        // Set TCR (Translation Control Register)
        // Configure for 48-bit virtual addresses with 4KB pages
        let tcr: u64 = tcr_config::T0SZ
            | (tcr_config::T1SZ << 16)
            | tcr_config::TG1_4KB
            | tcr_config::IPS_48BIT
            | tcr_config::SH0_INNER
            | tcr_config::SH1_INNER
            | tcr_config::ORGN0_WBRWA
            | tcr_config::ORGN1_WBRWA
            | tcr_config::IRGN0_WBRWA
            | tcr_config::IRGN1_WBRWA;
        TCR_EL1.set(tcr);

        // Set translation table base registers
        TTBR0_EL1.set(ttbr0);
        TTBR1_EL1.set(ttbr1);

        // Ensure all writes complete
        isb();
        dsb_sy();

        // Invalidate TLB
        self.invalidate_tlb_all();

        // Enable MMU
        let mut sctlr = SCTLR_EL1.get();
        sctlr |= 1 << 0;  // M bit (MMU enable)
        sctlr |= 1 << 2;  // C bit (data cache enable)
        sctlr |= 1 << 12; // I bit (instruction cache enable)
        SCTLR_EL1.set(sctlr);

        isb();

        self.enabled = true;
    }

    /// Invalidate all TLB entries
    pub fn invalidate_tlb_all(&self) {
        // SAFETY: TLB invalidation is safe
        unsafe {
            asm!(
                "tlbi vmalle1",
                "dsb sy",
                "isb",
                options(nostack)
            );
        }
    }

    /// Invalidate TLB entry for a specific virtual address
    pub fn invalidate_tlb_vaddr(&self, vaddr: u64) {
        // SAFETY: TLB invalidation is safe
        unsafe {
            asm!(
                "tlbi vale1, {}",
                "dsb sy",
                "isb",
                in(reg) vaddr >> 12,
                options(nostack)
            );
        }
    }

    /// Threshold for switching to full TLB invalidation (in pages)
    /// For ranges larger than this, a full invalidation is more efficient
    const TLB_RANGE_THRESHOLD: usize = 16;

    /// Invalidate TLB entries for a range of virtual addresses
    ///
    /// Uses per-page invalidation for small ranges, or full TLB invalidation
    /// for large ranges (more than TLB_RANGE_THRESHOLD pages).
    pub fn invalidate_tlb_range(&self, start: u64, end: u64) {
        let start_aligned = start & !((SIZE_4K - 1) as u64);
        let pages = ((end.saturating_sub(start_aligned)) as usize).div_ceil(SIZE_4K);

        if pages > Self::TLB_RANGE_THRESHOLD {
            // Full TLB invalidation is more efficient for large ranges
            self.invalidate_tlb_all();
        } else {
            // Per-page invalidation for small ranges
            let mut vaddr = start_aligned;
            while vaddr < end {
                self.invalidate_tlb_vaddr(vaddr);
                vaddr += SIZE_4K as u64;
            }
        }
    }

    /// Set TTBR0 (user space page table)
    pub fn set_ttbr0(&self, ttbr0: u64) {
        TTBR0_EL1.set(ttbr0);
        isb();
    }

    /// Set TTBR1 (kernel space page table)
    pub fn set_ttbr1(&self, ttbr1: u64) {
        TTBR1_EL1.set(ttbr1);
        isb();
    }

    /// Get current TTBR0
    #[must_use]
    pub fn ttbr0(&self) -> u64 {
        TTBR0_EL1.get()
    }

    /// Get current TTBR1
    #[must_use]
    pub fn ttbr1(&self) -> u64 {
        TTBR1_EL1.get()
    }

    /// Set ASID (Address Space Identifier)
    pub fn set_asid(&self, asid: u16) {
        let ttbr0 = TTBR0_EL1.get();
        let new_ttbr0 = (ttbr0 & 0x0000_FFFF_FFFF_FFFF) | ((asid as u64) << 48);
        // SAFETY: We're only changing the ASID field
        TTBR0_EL1.set(new_ttbr0);
    }
}

/// Global MMU instance
static MMU: Mutex<Mmu> = Mutex::new(Mmu::new());

/// Get access to the global MMU
pub fn mmu() -> spin::MutexGuard<'static, Mmu> {
    MMU.lock()
}

/// Page table walker - walks page tables to translate virtual to physical
pub struct PageTableWalker {
    ttbr: u64,
}

impl PageTableWalker {
    /// Create a new walker for the given TTBR
    pub fn new(ttbr: u64) -> Self {
        Self {
            ttbr: ttbr & PHYS_ADDR_MASK,
        }
    }

    /// Walk the page tables to translate a virtual address
    ///
    /// Returns the physical address if the mapping exists, None otherwise.
    ///
    /// # Safety
    /// The page tables must be valid and accessible.
    pub unsafe fn translate(&self, vaddr: u64) -> Option<u64> {
        let parts = VirtAddrParts::from_vaddr(vaddr);

        // SAFETY: Caller guarantees page tables are accessible
        unsafe {
            // Level 0
            let l0_table = self.ttbr as *const PageTable;
            let l0_entry = (*l0_table).get(parts.l0);
            if l0_entry & flags::VALID == 0 {
                return None;
            }

            // Level 1
            let l1_table = (l0_entry & PHYS_ADDR_MASK) as *const PageTable;
            let l1_entry = (*l1_table).get(parts.l1);
            if l1_entry & flags::VALID == 0 {
                return None;
            }
            // Check for 1GB block
            if l1_entry & flags::TABLE == 0 {
                let block_addr = l1_entry & 0x0000_FFFF_C000_0000;
                return Some(block_addr | (vaddr & 0x3FFF_FFFF));
            }

            // Level 2
            let l2_table = (l1_entry & PHYS_ADDR_MASK) as *const PageTable;
            let l2_entry = (*l2_table).get(parts.l2);
            if l2_entry & flags::VALID == 0 {
                return None;
            }
            // Check for 2MB block
            if l2_entry & flags::TABLE == 0 {
                let block_addr = l2_entry & 0x0000_FFFF_FFE0_0000;
                return Some(block_addr | (vaddr & 0x001F_FFFF));
            }

            // Level 3 (4KB pages)
            let l3_table = (l2_entry & PHYS_ADDR_MASK) as *const PageTable;
            let l3_entry = (*l3_table).get(parts.l3);
            if l3_entry & flags::VALID == 0 {
                return None;
            }

            let page_addr = l3_entry & PHYS_ADDR_MASK;
            Some(page_addr | parts.offset as u64)
        }
    }
}
