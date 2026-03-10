//! Physical and Virtual Address Types
//!
//! Simple address newtypes for use in ABI structures like [`BootInfo`](crate::boot::BootInfo).
//! These provide compile-time distinction between physical and virtual addresses
//! without the full type-level machinery of `m6-paging`.
//!
//! # Design
//!
//! These types are intentionally simple `#[repr(transparent)]` wrappers around `u64`:
//! - Zero runtime overhead
//! - Safe to transmute to/from `u64` for FFI
//! - Compatible with `#[repr(C)]` structs
//!
//! For more sophisticated type-safe address handling with typed pointers,
//! see the `PA`, `VA`, `TPA<T>`, and `TVA<T>` types in `m6-paging`.

use core::fmt;

/// Physical memory address.
///
/// Represents an address in physical memory space (as seen by the MMU).
/// Used in bootloader-to-kernel ABI structures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

/// Virtual memory address.
///
/// Represents an address in virtual memory space (as used by CPU instructions).
/// Used in bootloader-to-kernel ABI structures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl PhysAddr {
    /// Create a new physical address.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Get the raw address value.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if this address is null (zero).
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if this address is page-aligned (4KB).
    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.0 & 0xFFF == 0
    }

    /// Align this address down to a page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// Align this address up to a page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }

    /// Add an offset to this address.
    #[inline]
    #[must_use]
    pub const fn offset(self, offset: u64) -> Self {
        Self(self.0.wrapping_add(offset))
    }
}

impl VirtAddr {
    /// Create a new virtual address.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Get the raw address value.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if this address is null (zero).
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if this address is page-aligned (4KB).
    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        self.0 & 0xFFF == 0
    }

    /// Align this address down to a page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !0xFFF)
    }

    /// Align this address up to a page boundary.
    #[inline]
    #[must_use]
    pub const fn page_align_up(self) -> Self {
        Self((self.0 + 0xFFF) & !0xFFF)
    }

    /// Add an offset to this address.
    #[inline]
    #[must_use]
    pub const fn offset(self, offset: u64) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    /// Convert to a raw pointer.
    ///
    /// # Safety
    ///
    /// The address must be valid and properly aligned for type `T`.
    #[inline]
    #[must_use]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Convert to a mutable raw pointer.
    ///
    /// # Safety
    ///
    /// The address must be valid and properly aligned for type `T`.
    #[inline]
    #[must_use]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

// -- Formatting implementations

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#018x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PA:{:#018x}", self.0)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#018x})", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VA:{:#018x}", self.0)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

// -- Conversion implementations

impl From<u64> for PhysAddr {
    #[inline]
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<PhysAddr> for u64 {
    #[inline]
    fn from(addr: PhysAddr) -> Self {
        addr.0
    }
}

impl From<u64> for VirtAddr {
    #[inline]
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<VirtAddr> for u64 {
    #[inline]
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- PhysAddr

    #[test_case]
    fn test_phys_is_page_aligned() {
        assert!(PhysAddr::new(0).is_page_aligned());
        assert!(PhysAddr::new(0x1000).is_page_aligned());
        assert!(!PhysAddr::new(0x1001).is_page_aligned());
        assert!(!PhysAddr::new(0x1FFF).is_page_aligned());
        assert!(PhysAddr::new(0x2000).is_page_aligned());
    }

    #[test_case]
    fn test_phys_page_align_down() {
        assert_eq!(
            PhysAddr::new(0x1000).page_align_down(),
            PhysAddr::new(0x1000)
        );
        assert_eq!(
            PhysAddr::new(0x1001).page_align_down(),
            PhysAddr::new(0x1000)
        );
        assert_eq!(
            PhysAddr::new(0x1FFF).page_align_down(),
            PhysAddr::new(0x1000)
        );
        assert_eq!(PhysAddr::new(0).page_align_down(), PhysAddr::new(0));
    }

    #[test_case]
    fn test_phys_page_align_up() {
        assert_eq!(PhysAddr::new(0x1000).page_align_up(), PhysAddr::new(0x1000));
        assert_eq!(PhysAddr::new(0x1001).page_align_up(), PhysAddr::new(0x2000));
        assert_eq!(PhysAddr::new(0x1FFF).page_align_up(), PhysAddr::new(0x2000));
        assert_eq!(PhysAddr::new(0).page_align_up(), PhysAddr::new(0));
    }

    #[test_case]
    fn test_phys_offset() {
        assert_eq!(PhysAddr::new(0x1000).offset(0x200), PhysAddr::new(0x1200));
        assert_eq!(PhysAddr::new(0).offset(0), PhysAddr::new(0));
        // wrapping addition: u64::MAX + 1 wraps to 0
        assert_eq!(PhysAddr::new(u64::MAX).offset(1), PhysAddr::new(0));
    }

    #[test_case]
    fn test_phys_null() {
        assert!(PhysAddr::new(0).is_null());
        assert!(!PhysAddr::new(1).is_null());
    }

    #[test_case]
    fn test_phys_as_u64() {
        assert_eq!(PhysAddr::new(0xDEAD_BEEF).as_u64(), 0xDEAD_BEEF);
    }

    #[test_case]
    fn test_phys_ordering() {
        assert!(PhysAddr::new(0x1000) < PhysAddr::new(0x2000));
        assert!(PhysAddr::new(0x2000) > PhysAddr::new(0x1000));
        assert_eq!(PhysAddr::new(0x1000), PhysAddr::new(0x1000));
    }

    #[test_case]
    fn test_phys_align_down_then_up_round_trip() {
        // align_down(align_up(x)) == align_up(x) for any x
        let addr = PhysAddr::new(0x1800);
        assert_eq!(addr.page_align_up().page_align_down(), addr.page_align_up());
    }

    #[test_case]
    fn test_phys_from_u64_round_trip() {
        let pa: PhysAddr = 0xCAFE_0000u64.into();
        let val: u64 = pa.into();
        assert_eq!(val, 0xCAFE_0000u64);
    }

    // -- VirtAddr

    #[test_case]
    fn test_virt_is_page_aligned() {
        assert!(VirtAddr::new(0).is_page_aligned());
        assert!(VirtAddr::new(0x1000).is_page_aligned());
        assert!(!VirtAddr::new(0x1001).is_page_aligned());
        assert!(!VirtAddr::new(0xFFF).is_page_aligned());
    }

    #[test_case]
    fn test_virt_page_align_down() {
        assert_eq!(
            VirtAddr::new(0x1FFF).page_align_down(),
            VirtAddr::new(0x1000)
        );
        assert_eq!(VirtAddr::new(0).page_align_down(), VirtAddr::new(0));
    }

    #[test_case]
    fn test_virt_page_align_up() {
        assert_eq!(VirtAddr::new(0x1001).page_align_up(), VirtAddr::new(0x2000));
        assert_eq!(VirtAddr::new(0).page_align_up(), VirtAddr::new(0));
    }

    #[test_case]
    fn test_virt_offset_wrapping() {
        assert_eq!(VirtAddr::new(u64::MAX).offset(1), VirtAddr::new(0));
    }

    #[test_case]
    fn test_virt_as_ptr_non_null() {
        let va = VirtAddr::new(0x1000);
        let ptr: *const u8 = va.as_ptr();
        assert!(!ptr.is_null());
        assert_eq!(ptr as u64, 0x1000u64);
    }

    #[test_case]
    fn test_virt_as_mut_ptr() {
        let va = VirtAddr::new(0x2000);
        let ptr: *mut u8 = va.as_mut_ptr();
        assert_eq!(ptr as u64, 0x2000u64);
    }
}
