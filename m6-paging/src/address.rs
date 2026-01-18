//! Typed physical and virtual addresses
//!
//! Provides compile-time distinction between physical and virtual addresses,
//! with optional type parameter for additional semantic information.

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, Sub};

use crate::PAGE_SIZE;

/// Marker trait for address kinds (physical or virtual)
pub trait MemKind: private::Sealed + Copy + Clone {}

/// Physical address space marker
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Physical;

/// Virtual address space marker
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Virtual;

impl MemKind for Physical {}
impl MemKind for Virtual {}

mod private {
    pub trait Sealed {}
    impl Sealed for super::Physical {}
    impl Sealed for super::Virtual {}
}

/// A typed address in either physical or virtual address space
///
/// The `K` parameter determines whether this is a physical or virtual address.
/// The `T` parameter can be used to associate the address with a specific type
/// (e.g., `TPA<PageTable>` for a physical address pointing to a page table).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address<K: MemKind, T = ()> {
    value: u64,
    _kind: PhantomData<K>,
    _type: PhantomData<T>,
}

/// Untyped physical address
pub type PA = Address<Physical, ()>;

/// Untyped virtual address
pub type VA = Address<Virtual, ()>;

/// Typed physical address (associated with type T)
pub type TPA<T> = Address<Physical, T>;

/// Typed virtual address (associated with type T)
pub type TVA<T> = Address<Virtual, T>;

impl<K: MemKind, T> Address<K, T> {
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self {
            value,
            _kind: PhantomData,
            _type: PhantomData,
        }
    }

    /// Create a null (zero) address
    #[inline]
    pub const fn null() -> Self {
        Self::new(0)
    }

    /// Get the raw address value
    #[inline]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Check if address is null (zero)
    #[inline]
    pub const fn is_null(self) -> bool {
        self.value == 0
    }

    /// Check if address is page-aligned (4KB)
    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        self.value & (PAGE_SIZE as u64 - 1) == 0
    }

    /// Align address down to page boundary
    #[inline]
    #[must_use]
    pub const fn page_align_down(self) -> Self {
        Self::new(self.value & !(PAGE_SIZE as u64 - 1))
    }

    /// Align address up to page boundary
    #[inline]
    #[must_use]
    pub const fn page_align_up(self) -> Self {
        Self::new((self.value + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1))
    }

    /// Get the page offset (lower 12 bits)
    #[inline]
    pub const fn page_offset(self) -> usize {
        (self.value & (PAGE_SIZE as u64 - 1)) as usize
    }

    /// Add an offset to this address
    #[inline]
    #[must_use]
    pub const fn offset(self, offset: u64) -> Self {
        Self::new(self.value + offset)
    }

    /// Convert to an untyped address (remove type parameter)
    #[inline]
    #[must_use]
    pub const fn to_untyped(self) -> Address<K, ()> {
        Address::new(self.value)
    }

    /// Convert from raw pointer
    ///
    /// # Safety
    /// The pointer must be a valid address in the appropriate address space.
    #[inline]
    pub unsafe fn from_ptr<P>(ptr: *const P) -> Self {
        Self::new(ptr as u64)
    }
}

impl<K: MemKind, T> Address<K, T> {
    /// Cast to a differently typed address
    #[inline]
    #[must_use]
    pub const fn cast<U>(self) -> Address<K, U> {
        Address::new(self.value)
    }
}

// Physical address pointer conversion - applies phys_to_virt offset
impl<T> Address<Physical, T> {
    /// Convert physical address to raw pointer via the direct physical map
    ///
    /// This applies the configured phys_to_virt offset to get a kernel-accessible
    /// virtual address pointer.
    ///
    /// # Safety
    /// The physical address must be within the direct physical map region
    /// and the phys_to_virt offset must be configured correctly.
    #[inline]
    pub fn as_ptr<P>(self) -> *const P {
        crate::phys_to_virt(self.value) as *const P
    }

    /// Convert physical address to mutable raw pointer via the direct physical map
    ///
    /// This applies the configured phys_to_virt offset to get a kernel-accessible
    /// virtual address pointer.
    ///
    /// # Safety
    /// The physical address must be within the direct physical map region
    /// and the phys_to_virt offset must be configured correctly.
    #[inline]
    pub fn as_mut_ptr<P>(self) -> *mut P {
        crate::phys_to_virt(self.value) as *mut P
    }
}

// Virtual address pointer conversion - direct cast
impl<T> Address<Virtual, T> {
    /// Convert virtual address to raw pointer
    ///
    /// This is a direct cast since virtual addresses are directly accessible.
    ///
    /// # Safety
    /// The virtual address must be valid and properly mapped.
    #[inline]
    pub const fn as_ptr<P>(self) -> *const P {
        self.value as *const P
    }

    /// Convert virtual address to mutable raw pointer
    ///
    /// This is a direct cast since virtual addresses are directly accessible.
    ///
    /// # Safety
    /// The virtual address must be valid and properly mapped.
    #[inline]
    pub const fn as_mut_ptr<P>(self) -> *mut P {
        self.value as *mut P
    }
}

// Arithmetic operations

impl<K: MemKind, T> Add<u64> for Address<K, T> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self::new(self.value + rhs)
    }
}

impl<K: MemKind, T> Add<usize> for Address<K, T> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: usize) -> Self::Output {
        Self::new(self.value + rhs as u64)
    }
}

impl<K: MemKind, T> Sub<u64> for Address<K, T> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self::new(self.value - rhs)
    }
}

impl<K: MemKind, T> Sub<usize> for Address<K, T> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: usize) -> Self::Output {
        Self::new(self.value - rhs as u64)
    }
}

impl<K: MemKind, T> Sub for Address<K, T> {
    type Output = u64;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.value - rhs.value
    }
}

// Formatting

impl<K: MemKind, T> fmt::Debug for Address<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.value)
    }
}

impl<K: MemKind, T> fmt::Display for Address<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.value)
    }
}

impl<K: MemKind, T> fmt::LowerHex for Address<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.value, f)
    }
}

impl<K: MemKind, T> fmt::UpperHex for Address<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.value, f)
    }
}

// Default

impl<K: MemKind, T> Default for Address<K, T> {
    fn default() -> Self {
        Self::null()
    }
}
