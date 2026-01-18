//! Boot information for device manager
//!
//! This structure is created by init and passed to device-mgr via x0.
//! It contains the addresses where DTB and initrd are mapped, avoiding
//! hardcoded addresses.

/// Magic number for validation: "DEVMBOOT" as little-endian u64.
pub const DEV_MGR_BOOT_INFO_MAGIC: u64 = 0x54_4F_4F_42_4D_56_45_44;

/// Version of the DevMgrBootInfo structure.
pub const DEV_MGR_BOOT_INFO_VERSION: u32 = 1;

/// Maximum number of device untyped regions supported.
pub const MAX_DEVICE_UNTYPED: usize = 8;

/// Boot information passed from init to device-mgr.
#[repr(C)]
#[derive(Debug)]
pub struct DevMgrBootInfo {
    /// Magic number for validation.
    pub magic: u64,
    /// Version of this structure.
    pub version: u32,
    /// CNode radix (for converting slots to CPtrs).
    pub cnode_radix: u8,
    /// Number of device untyped capabilities provided.
    pub device_untyped_count: u8,
    /// Reserved for alignment.
    _reserved: [u8; 2],
    /// Virtual address where DTB is mapped (0 if not available).
    pub dtb_vaddr: u64,
    /// Size of the DTB in bytes.
    pub dtb_size: u64,
    /// Virtual address where initrd is mapped (0 if not available).
    pub initrd_vaddr: u64,
    /// Size of the initrd in bytes.
    pub initrd_size: u64,
    /// Physical base addresses of device untyped regions.
    pub device_untyped_phys: [u64; MAX_DEVICE_UNTYPED],
    /// Sizes (in bits, log2) of device untyped regions.
    pub device_untyped_size_bits: [u8; MAX_DEVICE_UNTYPED],
}

impl DevMgrBootInfo {
    /// Find the device untyped slot that covers a given physical address.
    ///
    /// Returns the slot number and size in bytes if found.
    pub fn find_device_untyped(&self, phys_addr: u64) -> Option<(u64, u64)> {
        for i in 0..self.device_untyped_count as usize {
            let base = self.device_untyped_phys[i];
            let size = 1u64 << self.device_untyped_size_bits[i];
            if phys_addr >= base && phys_addr < base + size {
                // Slot number is FIRST_DEVICE_UNTYPED + index
                let slot = crate::slots::FIRST_DEVICE_UNTYPED + i as u64;
                return Some((slot, size));
            }
        }
        None
    }

    /// Check if the boot info is valid.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.magic == DEV_MGR_BOOT_INFO_MAGIC && self.version == DEV_MGR_BOOT_INFO_VERSION
    }

    /// Check if DTB is available.
    #[inline]
    pub const fn has_dtb(&self) -> bool {
        self.dtb_vaddr != 0 && self.dtb_size != 0
    }

    /// Check if initrd is available.
    #[inline]
    pub const fn has_initrd(&self) -> bool {
        self.initrd_vaddr != 0 && self.initrd_size != 0
    }

    /// Get DTB as a byte slice.
    ///
    /// # Safety
    ///
    /// Caller must ensure dtb_vaddr points to valid mapped memory.
    #[inline]
    pub unsafe fn dtb_slice(&self) -> Option<&[u8]> {
        if self.has_dtb() {
            Some(unsafe {
                core::slice::from_raw_parts(self.dtb_vaddr as *const u8, self.dtb_size as usize)
            })
        } else {
            None
        }
    }

    /// Get initrd as a byte slice.
    ///
    /// # Safety
    ///
    /// Caller must ensure initrd_vaddr points to valid mapped memory.
    #[inline]
    pub unsafe fn initrd_slice(&self) -> Option<&[u8]> {
        if self.has_initrd() {
            Some(unsafe {
                core::slice::from_raw_parts(
                    self.initrd_vaddr as *const u8,
                    self.initrd_size as usize,
                )
            })
        } else {
            None
        }
    }
}
