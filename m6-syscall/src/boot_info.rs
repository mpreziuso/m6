//! Boot information passed from kernel to init
//!
//! The kernel creates a `UserBootInfo` structure and maps it read-only into
//! the root task's address space. This provides the init process with:
//!
//! - Capability slot layout
//! - Available untyped memory regions
//! - Platform information
//! - Memory statistics

/// Magic number for validation: "M6UBOOT\0" as little-endian u64.
pub const USER_BOOT_INFO_MAGIC: u64 = 0x00_54_4F_4F_42_55_36_4D;

/// Version of the UserBootInfo structure.
pub const USER_BOOT_INFO_VERSION: u32 = 1;

/// Virtual address where UserBootInfo is mapped.
pub const USER_BOOT_INFO_ADDR: u64 = 0x0000_7FFF_E000_0000;

/// Maximum number of untyped memory regions.
pub const MAX_UNTYPED_REGIONS: usize = 64;

/// Well-known capability slot indices in root task's CSpace.
///
/// These match the slots defined in `m6-kernel/src/cap/bootstrap.rs::slots`.
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapSlot {
    /// Root CNode (self-reference).
    RootCNode = 0,
    /// Root TCB.
    RootTcb = 1,
    /// Root VSpace.
    RootVSpace = 2,
    /// IRQ control capability.
    IrqControl = 3,
    /// ASID control capability.
    AsidControl = 4,
    /// Scheduling control capability.
    SchedControl = 5,
    /// First untyped memory slot.
    FirstUntyped = 6,
}

impl CapSlot {
    /// Get the slot index for a given untyped region index.
    #[inline]
    pub const fn untyped(idx: usize) -> usize {
        Self::FirstUntyped as usize + idx
    }
}

/// Platform identifiers.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformId {
    /// Unknown platform.
    Unknown = 0,
    /// QEMU ARM Virtual Machine (virt).
    QemuVirt = 1,
    /// Radxa Rock 5B+ (RK3588).
    Rock5BPlus = 2,
}

impl PlatformId {
    /// Convert from raw u32.
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::QemuVirt,
            2 => Self::Rock5BPlus,
            _ => Self::Unknown,
        }
    }

    /// Get platform name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::QemuVirt => "QEMU virt",
            Self::Rock5BPlus => "Radxa Rock 5B+",
        }
    }
}

/// Boot information passed from kernel to init via a read-only page.
///
/// The kernel maps this page read-only at [`USER_BOOT_INFO_ADDR`] before
/// starting the init task. The address is also passed in x0 for convenience.
#[repr(C)]
#[derive(Debug)]
pub struct UserBootInfo {
    /// Magic number for validation ([`USER_BOOT_INFO_MAGIC`]).
    pub magic: u64,
    /// Version of this structure ([`USER_BOOT_INFO_VERSION`]).
    pub version: u32,
    /// Number of capability slots in root CNode (log2).
    pub cnode_radix: u32,
    /// Number of untyped memory capabilities.
    pub untyped_count: u32,
    /// Padding for alignment.
    _pad0: u32,
    /// Total physical memory in bytes.
    pub total_memory: u64,
    /// Free physical memory in bytes (at boot time).
    pub free_memory: u64,
    /// Platform identifier (for driver selection).
    pub platform_id: u32,
    /// Number of CPUs.
    pub cpu_count: u32,
    /// Size of each untyped region in bits (log2), indexed by slot - FirstUntyped.
    pub untyped_size_bits: [u8; MAX_UNTYPED_REGIONS],
    /// Whether each untyped is device memory (1) or normal RAM (0).
    pub untyped_is_device: [u8; MAX_UNTYPED_REGIONS],
    /// Physical base address of each untyped region.
    pub untyped_phys_base: [u64; MAX_UNTYPED_REGIONS],
    /// Reserved for future use.
    pub _reserved: [u64; 8],
}

impl UserBootInfo {
    /// Check if the boot info is valid.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.magic == USER_BOOT_INFO_MAGIC && self.version == USER_BOOT_INFO_VERSION
    }

    /// Get the platform identifier.
    #[inline]
    pub fn platform(&self) -> PlatformId {
        PlatformId::from_u32(self.platform_id)
    }

    /// Get the number of slots in the root CNode.
    #[inline]
    pub const fn cnode_slots(&self) -> usize {
        1 << self.cnode_radix
    }

    /// Get the slot index for a given untyped index.
    #[inline]
    pub const fn untyped_slot(&self, idx: usize) -> usize {
        CapSlot::untyped(idx)
    }

    /// Get the size in bytes of an untyped region.
    #[inline]
    pub const fn untyped_size(&self, idx: usize) -> u64 {
        if idx < MAX_UNTYPED_REGIONS {
            1u64 << self.untyped_size_bits[idx]
        } else {
            0
        }
    }

    /// Check if an untyped region is device memory.
    #[inline]
    pub const fn untyped_is_device(&self, idx: usize) -> bool {
        idx < MAX_UNTYPED_REGIONS && self.untyped_is_device[idx] != 0
    }

    /// Get the physical base address of an untyped region.
    #[inline]
    pub const fn untyped_phys(&self, idx: usize) -> u64 {
        if idx < MAX_UNTYPED_REGIONS {
            self.untyped_phys_base[idx]
        } else {
            0
        }
    }
}

// Ensure the structure fits in a single 4K page
const _: () = assert!(
    core::mem::size_of::<UserBootInfo>() <= 4096,
    "UserBootInfo must fit in a single page"
);
