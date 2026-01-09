//! Frame capability - mappable physical memory pages
//!
//! A frame represents a physical memory page that can be mapped into
//! a virtual address space. M6 supports two frame sizes:
//!
//! - 4KB (standard pages, `SIZE_4K`)
//! - 2MB (huge pages, `SIZE_2M`)
//!
//! # Device Frames
//!
//! Device frames represent MMIO regions. They are mapped with device
//! memory attributes (non-cacheable, ordered access) and are typically
//! used by userspace drivers.

use m6_common::PhysAddr;

/// Frame object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FrameObject {
    /// Physical address of the frame.
    pub phys_addr: PhysAddr,
    /// Size as log2 (12 for 4KB, 21 for 2MB).
    pub size_bits: u8,
    /// Whether this is device memory.
    pub is_device: bool,
    /// Reference count (how many VSpaces have this mapped).
    pub map_count: u16,
}

impl FrameObject {
    /// 4KB frame (standard page).
    pub const SIZE_4K: u8 = 12;

    /// 2MB frame (huge page).
    pub const SIZE_2M: u8 = 21;

    /// Create a new frame object.
    ///
    /// # Parameters
    ///
    /// - `phys_addr`: Physical address (must be aligned to frame size)
    /// - `size_bits`: Size as log2 (12 for 4KB, 21 for 2MB)
    /// - `is_device`: Whether this is device memory
    #[inline]
    #[must_use]
    pub const fn new(phys_addr: PhysAddr, size_bits: u8, is_device: bool) -> Self {
        Self {
            phys_addr,
            size_bits,
            is_device,
            map_count: 0,
        }
    }

    /// Create a 4KB normal frame.
    #[inline]
    #[must_use]
    pub const fn new_4k(phys_addr: PhysAddr) -> Self {
        Self::new(phys_addr, Self::SIZE_4K, false)
    }

    /// Create a 2MB normal frame.
    #[inline]
    #[must_use]
    pub const fn new_2m(phys_addr: PhysAddr) -> Self {
        Self::new(phys_addr, Self::SIZE_2M, false)
    }

    /// Create a 4KB device frame.
    #[inline]
    #[must_use]
    pub const fn new_device_4k(phys_addr: PhysAddr) -> Self {
        Self::new(phys_addr, Self::SIZE_4K, true)
    }

    /// Size in bytes.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> usize {
        1 << self.size_bits
    }

    /// Check if this is a 4KB frame.
    #[inline]
    #[must_use]
    pub const fn is_4k(&self) -> bool {
        self.size_bits == Self::SIZE_4K
    }

    /// Check if this is a 2MB frame.
    #[inline]
    #[must_use]
    pub const fn is_2m(&self) -> bool {
        self.size_bits == Self::SIZE_2M
    }

    /// Check if the frame is currently mapped.
    #[inline]
    #[must_use]
    pub const fn is_mapped(&self) -> bool {
        self.map_count > 0
    }

    /// Increment the map count.
    ///
    /// Called when the frame is mapped into a VSpace.
    #[inline]
    pub fn increment_map_count(&mut self) {
        self.map_count = self.map_count.saturating_add(1);
    }

    /// Decrement the map count.
    ///
    /// Called when the frame is unmapped from a VSpace.
    #[inline]
    pub fn decrement_map_count(&mut self) {
        self.map_count = self.map_count.saturating_sub(1);
    }

    /// Get the alignment mask for this frame size.
    #[inline]
    #[must_use]
    pub const fn alignment_mask(&self) -> u64 {
        (1u64 << self.size_bits) - 1
    }

    /// Check if the physical address is correctly aligned.
    #[inline]
    #[must_use]
    pub const fn is_aligned(&self) -> bool {
        (self.phys_addr.as_u64() & self.alignment_mask()) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_4k() {
        let frame = FrameObject::new_4k(PhysAddr::new(0x1000));
        assert_eq!(frame.size(), 4096);
        assert!(frame.is_4k());
        assert!(!frame.is_2m());
        assert!(!frame.is_device);
    }

    #[test]
    fn test_frame_2m() {
        let frame = FrameObject::new_2m(PhysAddr::new(0x200000));
        assert_eq!(frame.size(), 2 * 1024 * 1024);
        assert!(frame.is_2m());
        assert!(!frame.is_4k());
    }

    #[test]
    fn test_map_count() {
        let mut frame = FrameObject::new_4k(PhysAddr::new(0x1000));
        assert!(!frame.is_mapped());

        frame.increment_map_count();
        assert!(frame.is_mapped());
        assert_eq!(frame.map_count, 1);

        frame.decrement_map_count();
        assert!(!frame.is_mapped());
    }
}
