//! ARM64 page table descriptor types
//!
//! Implements type-safe descriptors for each page table level:
//! - L0: Table descriptor only (points to L1)
//! - L1: Table or 1GB block descriptor
//! - L2: Table or 2MB block descriptor
//! - L3: 4KB page descriptor only
//!
//! Descriptor format (ARMv8-A):
//! ```text
//! +---+--------+-----+-----+---+------------------------+---+----+----+----+----+------+----+----+
//! | R |   SW   | UXN | PXN | R | Output address [47:12] | R | AF | SH | AP | NS | INDX | TB | VB |
//! +---+--------+-----+-----+---+------------------------+---+----+----+----+----+------+----+----+
//!  63  58    55 54    53    52  47                    12 11  10   9  8 7  6 5    4    2 1    0
//! ```

use tock_registers::{
    interfaces::{Readable, ReadWriteable},
    register_bitfields,
    registers::InMemoryRegister,
};

use crate::address::PA;
use crate::permissions::{MemoryType, PtePermissions};
use crate::region::PhysMemoryRegion;
use crate::VA;
use m6_common::memory::page::{SHIFT_4K, SHIFT_2M};

// Page size constants
const PAGE_SHIFT: usize = SHIFT_4K;

// Block size constants
const BLOCK_L2_SHIFT: usize = SHIFT_2M;
const BLOCK_L2_SIZE: u64 = 1 << BLOCK_L2_SHIFT;
const BLOCK_L2_MASK: u64 = BLOCK_L2_SIZE - 1;

const BLOCK_L1_SHIFT: usize = 30; // 1GB
const BLOCK_L1_SIZE: u64 = 1 << BLOCK_L1_SHIFT;
const BLOCK_L1_MASK: u64 = BLOCK_L1_SIZE - 1;

// Output address masks
const L3_OUTPUT_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]
const L2_BLOCK_OUTPUT_MASK: u64 = 0x0000_FFFF_FFE0_0000; // bits [47:21]
const L1_BLOCK_OUTPUT_MASK: u64 = 0x0000_FFFF_C000_0000; // bits [47:30]
const TABLE_OUTPUT_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]

register_bitfields![u64,
    /// Common descriptor fields for all levels
    pub DescriptorFields [
        /// Valid bit - entry is valid when set
        VALID OFFSET(0) NUMBITS(1) [],

        /// Type bit - 0=Block/Reserved, 1=Table/Page
        /// For L0-L2: 0=Block (L1/L2 only), 1=Table
        /// For L3: must be 1 for valid page
        TYPE OFFSET(1) NUMBITS(1) [
            Block = 0,
            TableOrPage = 1
        ],

        /// Memory attribute index into MAIR_EL1
        ATTR_INDEX OFFSET(2) NUMBITS(3) [
            /// Normal memory (index 0 in MAIR)
            Normal = 0,
            /// Device memory (index 1 in MAIR)
            Device = 1
        ],

        /// Non-secure bit
        NS OFFSET(5) NUMBITS(1) [],

        /// Access permissions
        AP OFFSET(6) NUMBITS(2) [
            /// Read/Write at EL1, no access at EL0
            RW_EL1 = 0b00,
            /// Read/Write at EL1 and EL0
            RW_EL0 = 0b01,
            /// Read-only at EL1, no access at EL0
            RO_EL1 = 0b10,
            /// Read-only at EL1 and EL0
            RO_EL0 = 0b11
        ],

        /// Shareability
        SH OFFSET(8) NUMBITS(2) [
            NonShareable = 0b00,
            OuterShareable = 0b10,
            InnerShareable = 0b11
        ],

        /// Access flag - set by hardware or software on first access
        AF OFFSET(10) NUMBITS(1) [],

        /// Privileged Execute Never
        PXN OFFSET(53) NUMBITS(1) [],

        /// Unprivileged Execute Never
        UXN OFFSET(54) NUMBITS(1) [],

        /// Software-defined: Copy-on-Write flag
        COW OFFSET(55) NUMBITS(1) []
    ]
];

/// Trait for page table entry operations
pub trait PageTableEntry: Sized + Copy + Clone {
    fn is_valid(self) -> bool;

    fn as_raw(self) -> u64;

    fn from_raw(value: u64) -> Self;

    fn invalid() -> Self;
}

/// Trait for table descriptors that point to next level
pub trait TableMapper: PageTableEntry {
    fn next_table_address(self) -> Option<PA>;

    fn new_table(pa: PA) -> Self;

    fn is_table(self) -> bool;
}

/// Trait for block/page descriptors that map physical memory
pub trait BlockPageMapper: PageTableEntry {
    /// Shift amount for this level (12 for 4KB, 21 for 2MB, 30 for 1GB)
    const SHIFT: usize;

    /// Size of memory mapped by one entry at this level
    const SIZE: u64 = 1 << Self::SHIFT;

    /// Alignment mask for this level
    const MASK: u64 = Self::SIZE - 1;

    /// Create a new block/page mapping
    fn new_mapping(pa: PA, mem_type: MemoryType, perms: PtePermissions) -> Self;

    /// Get the mapped physical address, if this is a block/page descriptor
    fn mapped_address(self) -> Option<PA>;

    /// Check if a region can be mapped at this level
    ///
    /// Returns true if both the physical and virtual addresses are aligned
    /// to this level's block/page size, and the region is at least as large.
    fn can_map(phys: PhysMemoryRegion, va: VA) -> bool {
        let pa_aligned = phys.start().value() & Self::MASK == 0;
        let va_aligned = va.value() & Self::MASK == 0;
        let size_ok = phys.size() >= Self::SIZE as usize;
        pa_aligned && va_aligned && size_ok
    }

    /// Get permissions from this descriptor
    fn permissions(self) -> Option<PtePermissions>;

    /// Get memory type from this descriptor
    fn memory_type(self) -> Option<MemoryType>;
}

// -- L0 Descriptor - Table only (points to L1)

/// L0 table descriptor (512GB per entry, table only)
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct L0Descriptor(u64);

impl L0Descriptor {
    /// Table descriptor bits: valid=1, type=1 (table)
    const TABLE_BITS: u64 = 0b11;
}

impl PageTableEntry for L0Descriptor {
    #[inline]
    fn is_valid(self) -> bool {
        self.0 & 0b1 != 0
    }

    #[inline]
    fn as_raw(self) -> u64 {
        self.0
    }

    #[inline]
    fn from_raw(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    fn invalid() -> Self {
        Self(0)
    }
}

impl TableMapper for L0Descriptor {
    #[inline]
    fn next_table_address(self) -> Option<PA> {
        if self.is_table() {
            Some(PA::new(self.0 & TABLE_OUTPUT_MASK))
        } else {
            None
        }
    }

    #[inline]
    fn new_table(pa: PA) -> Self {
        debug_assert!(pa.is_page_aligned());
        Self((pa.value() & TABLE_OUTPUT_MASK) | Self::TABLE_BITS)
    }

    #[inline]
    fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11
    }
}

impl core::fmt::Debug for L0Descriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_valid() {
            write!(f, "L0Desc::Table({:#x})", self.0 & TABLE_OUTPUT_MASK)
        } else {
            write!(f, "L0Desc::Invalid")
        }
    }
}

// -- L1 Descriptor - Table or 1GB Block

/// L1 descriptor (1GB per entry, table or block)
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct L1Descriptor(u64);

impl L1Descriptor {
    /// Table descriptor bits: valid=1, type=1 (table)
    const TABLE_BITS: u64 = 0b11;
    /// Block descriptor bits: valid=1, type=0 (block)
    const BLOCK_BITS: u64 = 0b01;

    /// Check if this is a block descriptor
    #[inline]
    pub fn is_block(self) -> bool {
        self.0 & 0b11 == Self::BLOCK_BITS
    }
}

impl PageTableEntry for L1Descriptor {
    #[inline]
    fn is_valid(self) -> bool {
        self.0 & 0b1 != 0
    }

    #[inline]
    fn as_raw(self) -> u64 {
        self.0
    }

    #[inline]
    fn from_raw(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    fn invalid() -> Self {
        Self(0)
    }
}

impl TableMapper for L1Descriptor {
    #[inline]
    fn next_table_address(self) -> Option<PA> {
        if self.is_table() {
            Some(PA::new(self.0 & TABLE_OUTPUT_MASK))
        } else {
            None
        }
    }

    #[inline]
    fn new_table(pa: PA) -> Self {
        debug_assert!(pa.is_page_aligned());
        Self((pa.value() & TABLE_OUTPUT_MASK) | Self::TABLE_BITS)
    }

    #[inline]
    fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11
    }
}

impl BlockPageMapper for L1Descriptor {
    const SHIFT: usize = BLOCK_L1_SHIFT;

    fn new_mapping(pa: PA, mem_type: MemoryType, perms: PtePermissions) -> Self {
        debug_assert!(pa.value() & BLOCK_L1_MASK == 0, "L1 block address must be 1GB aligned");

        let mut value = (pa.value() & L1_BLOCK_OUTPUT_MASK) | Self::BLOCK_BITS;

        // Set access flag (required)
        value |= 1 << 10;

        // Set memory attributes
        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(value);

        match mem_type {
            MemoryType::Normal => {
                reg.modify(
                    DescriptorFields::ATTR_INDEX::Normal + DescriptorFields::SH::InnerShareable,
                );
            }
            MemoryType::Device => {
                reg.modify(
                    DescriptorFields::ATTR_INDEX::Device + DescriptorFields::SH::NonShareable,
                );
            }
        }

        let mut value = reg.get();

        // Set permissions
        if perms.user {
            if perms.write {
                value |= 0b01 << 6; // AP = RW_EL0
            } else {
                value |= 0b11 << 6; // AP = RO_EL0
            }
        } else {
            if !perms.write {
                value |= 0b10 << 6; // AP = RO_EL1
            }
            // else AP = 0b00 = RW_EL1 (default)
        }

        // Set execute permissions
        if !perms.execute {
            value |= 1 << 54; // UXN
            value |= 1 << 53; // PXN
        } else if !perms.user {
            value |= 1 << 54; // UXN only (kernel can execute)
        }

        // Set COW flag if needed
        if perms.cow {
            value |= 1 << 55;
        }

        // Set nG (non-Global) bit for non-global mappings
        // nG=0 means global (ASID-independent), nG=1 means per-ASID
        if !perms.global {
            value |= 1 << 11; // nG bit
        }

        Self(value)
    }

    fn mapped_address(self) -> Option<PA> {
        if self.is_block() {
            Some(PA::new(self.0 & L1_BLOCK_OUTPUT_MASK))
        } else {
            None
        }
    }

    fn permissions(self) -> Option<PtePermissions> {
        if !self.is_block() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        let ap = reg.read(DescriptorFields::AP);

        let (write, user) = match ap {
            0b00 => (true, false),  // RW_EL1
            0b01 => (true, true),   // RW_EL0
            0b10 => (false, false), // RO_EL1
            0b11 => (false, true),  // RO_EL0
            _ => unreachable!(),
        };

        let pxn = reg.is_set(DescriptorFields::PXN);
        let cow = reg.is_set(DescriptorFields::COW);
        let ng = (self.0 >> 11) & 1 != 0; // nG bit at position 11

        Some(PtePermissions {
            read: true,
            write,
            execute: !pxn,
            user,
            cow,
            global: !ng, // global = !nG
        })
    }

    fn memory_type(self) -> Option<MemoryType> {
        if !self.is_block() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        match reg.read(DescriptorFields::ATTR_INDEX) {
            0 => Some(MemoryType::Normal),
            1 => Some(MemoryType::Device),
            _ => None,
        }
    }
}

impl core::fmt::Debug for L1Descriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_valid() {
            write!(f, "L1Desc::Invalid")
        } else if self.is_table() {
            write!(f, "L1Desc::Table({:#x})", self.0 & TABLE_OUTPUT_MASK)
        } else {
            write!(f, "L1Desc::Block({:#x})", self.0 & L1_BLOCK_OUTPUT_MASK)
        }
    }
}

// -- L2 Descriptor - Table or 2MB Block

/// L2 descriptor (2MB per entry, table or block)
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct L2Descriptor(u64);

impl L2Descriptor {
    const TABLE_BITS: u64 = 0b11;
    const BLOCK_BITS: u64 = 0b01;

    #[inline]
    pub fn is_block(self) -> bool {
        self.0 & 0b11 == Self::BLOCK_BITS
    }
}

impl PageTableEntry for L2Descriptor {
    #[inline]
    fn is_valid(self) -> bool {
        self.0 & 0b1 != 0
    }

    #[inline]
    fn as_raw(self) -> u64 {
        self.0
    }

    #[inline]
    fn from_raw(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    fn invalid() -> Self {
        Self(0)
    }
}

impl TableMapper for L2Descriptor {
    #[inline]
    fn next_table_address(self) -> Option<PA> {
        if self.is_table() {
            Some(PA::new(self.0 & TABLE_OUTPUT_MASK))
        } else {
            None
        }
    }

    #[inline]
    fn new_table(pa: PA) -> Self {
        debug_assert!(pa.is_page_aligned());
        Self((pa.value() & TABLE_OUTPUT_MASK) | Self::TABLE_BITS)
    }

    #[inline]
    fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11
    }
}

impl BlockPageMapper for L2Descriptor {
    const SHIFT: usize = BLOCK_L2_SHIFT;

    fn new_mapping(pa: PA, mem_type: MemoryType, perms: PtePermissions) -> Self {
        debug_assert!(pa.value() & BLOCK_L2_MASK == 0, "L2 block address must be 2MB aligned");

        let mut value = (pa.value() & L2_BLOCK_OUTPUT_MASK) | Self::BLOCK_BITS;

        // Set access flag
        value |= 1 << 10;

        // Set memory attributes
        match mem_type {
            MemoryType::Normal => {
                value |= 0b11 << 8; // SH = Inner Shareable
                // ATTR_INDEX = 0 (Normal)
            }
            MemoryType::Device => {
                value |= 1 << 2; // ATTR_INDEX = 1 (Device)
                // SH = Non-shareable (default)
            }
        }

        // Set permissions
        if perms.user {
            if perms.write {
                value |= 0b01 << 6;
            } else {
                value |= 0b11 << 6;
            }
        } else if !perms.write {
            value |= 0b10 << 6;
        }

        // Set execute permissions
        if !perms.execute {
            value |= 1 << 54;
            value |= 1 << 53;
        } else if !perms.user {
            value |= 1 << 54;
        }

        if perms.cow {
            value |= 1 << 55;
        }

        // Set nG (non-Global) bit for non-global mappings
        if !perms.global {
            value |= 1 << 11; // nG bit
        }

        Self(value)
    }

    fn mapped_address(self) -> Option<PA> {
        if self.is_block() {
            Some(PA::new(self.0 & L2_BLOCK_OUTPUT_MASK))
        } else {
            None
        }
    }

    fn permissions(self) -> Option<PtePermissions> {
        if !self.is_block() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        let ap = reg.read(DescriptorFields::AP);

        let (write, user) = match ap {
            0b00 => (true, false),
            0b01 => (true, true),
            0b10 => (false, false),
            0b11 => (false, true),
            _ => unreachable!(),
        };

        let pxn = reg.is_set(DescriptorFields::PXN);
        let cow = reg.is_set(DescriptorFields::COW);
        let ng = (self.0 >> 11) & 1 != 0; // nG bit at position 11

        Some(PtePermissions {
            read: true,
            write,
            execute: !pxn,
            user,
            cow,
            global: !ng, // global = !nG
        })
    }

    fn memory_type(self) -> Option<MemoryType> {
        if !self.is_block() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        match reg.read(DescriptorFields::ATTR_INDEX) {
            0 => Some(MemoryType::Normal),
            1 => Some(MemoryType::Device),
            _ => None,
        }
    }
}

impl core::fmt::Debug for L2Descriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_valid() {
            write!(f, "L2Desc::Invalid")
        } else if self.is_table() {
            write!(f, "L2Desc::Table({:#x})", self.0 & TABLE_OUTPUT_MASK)
        } else {
            write!(f, "L2Desc::Block({:#x})", self.0 & L2_BLOCK_OUTPUT_MASK)
        }
    }
}

// -- L3 Descriptor - 4KB Page only

/// L3 page descriptor (4KB per entry, page only)
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct L3Descriptor(u64);

impl L3Descriptor {
    /// Page descriptor bits: valid=1, type=1 (page)
    /// Note: At L3, bits[1:0]=11 indicates a valid page (not a table)
    const PAGE_BITS: u64 = 0b11;
}

impl PageTableEntry for L3Descriptor {
    #[inline]
    fn is_valid(self) -> bool {
        // At L3, a valid page has bits[1:0] = 11
        self.0 & 0b11 == 0b11
    }

    #[inline]
    fn as_raw(self) -> u64 {
        self.0
    }

    #[inline]
    fn from_raw(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    fn invalid() -> Self {
        Self(0)
    }
}

impl BlockPageMapper for L3Descriptor {
    const SHIFT: usize = PAGE_SHIFT;

    fn new_mapping(pa: PA, mem_type: MemoryType, perms: PtePermissions) -> Self {
        debug_assert!(pa.is_page_aligned(), "L3 page address must be 4KB aligned");

        let mut value = (pa.value() & L3_OUTPUT_MASK) | Self::PAGE_BITS;

        // Set access flag
        value |= 1 << 10;

        // Set memory attributes
        match mem_type {
            MemoryType::Normal => {
                value |= 0b11 << 8; // SH = Inner Shareable
            }
            MemoryType::Device => {
                value |= 1 << 2; // ATTR_INDEX = 1 (Device)
            }
        }

        // Set permissions
        if perms.user {
            if perms.write {
                value |= 0b01 << 6;
            } else {
                value |= 0b11 << 6;
            }
        } else if !perms.write {
            value |= 0b10 << 6;
        }

        // Set execute permissions
        if !perms.execute {
            value |= 1 << 54;
            value |= 1 << 53;
        } else if !perms.user {
            value |= 1 << 54;
        }

        if perms.cow {
            value |= 1 << 55;
        }

        // Set nG (non-Global) bit for non-global mappings
        if !perms.global {
            value |= 1 << 11; // nG bit
        }

        Self(value)
    }

    fn mapped_address(self) -> Option<PA> {
        if self.is_valid() {
            Some(PA::new(self.0 & L3_OUTPUT_MASK))
        } else {
            None
        }
    }

    fn permissions(self) -> Option<PtePermissions> {
        if !self.is_valid() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        let ap = reg.read(DescriptorFields::AP);

        let (write, user) = match ap {
            0b00 => (true, false),
            0b01 => (true, true),
            0b10 => (false, false),
            0b11 => (false, true),
            _ => unreachable!(),
        };

        let pxn = reg.is_set(DescriptorFields::PXN);
        let cow = reg.is_set(DescriptorFields::COW);
        let ng = (self.0 >> 11) & 1 != 0; // nG bit at position 11

        Some(PtePermissions {
            read: true,
            write,
            execute: !pxn,
            user,
            cow,
            global: !ng, // global = !nG
        })
    }

    fn memory_type(self) -> Option<MemoryType> {
        if !self.is_valid() {
            return None;
        }

        let reg: InMemoryRegister<u64, DescriptorFields::Register> = InMemoryRegister::new(self.0);
        match reg.read(DescriptorFields::ATTR_INDEX) {
            0 => Some(MemoryType::Normal),
            1 => Some(MemoryType::Device),
            _ => None,
        }
    }
}

impl core::fmt::Debug for L3Descriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_valid() {
            write!(f, "L3Desc::Page({:#x})", self.0 & L3_OUTPUT_MASK)
        } else {
            write!(f, "L3Desc::Invalid")
        }
    }
}
