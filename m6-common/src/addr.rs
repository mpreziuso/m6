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
