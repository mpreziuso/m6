//! MMIO Region Abstraction
//!
//! Provides type-safe, offset-based access to memory-mapped I/O regions.
//! All reads and writes use volatile operations to prevent compiler optimisations
//! from reordering or eliding device memory accesses.
//!
//! # Safety
//!
//! The caller is responsible for ensuring the base address points to a valid,
//! mapped MMIO region with device memory attributes.

use core::ptr::{read_volatile, write_volatile};

/// A memory-mapped I/O region.
///
/// Provides offset-based access to device registers with volatile semantics.
/// Reads and writes are performed as 8, 16, 32, or 64-bit operations.
///
/// # Example
///
/// ```ignore
/// let mmio = unsafe { MmioRegion::new(0x1000_0000, 0x1000) };
///
/// // Read 32-bit register at offset 0x10
/// let status = mmio.read32(0x10);
///
/// // Write 32-bit register at offset 0x14
/// mmio.write32(0x14, 0x1234);
/// ```
#[derive(Clone, Copy)]
pub struct MmioRegion {
    base: usize,
    size: usize,
}

impl MmioRegion {
    /// Create a new MMIO region.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `base` points to a valid, mapped MMIO region
    /// - The region has device memory attributes (non-cacheable)
    /// - The region is at least `size` bytes
    /// - No other code accesses this region concurrently without synchronisation
    #[inline]
    #[must_use]
    pub const unsafe fn new(base: usize, size: usize) -> Self {
        Self { base, size }
    }

    /// Get the base address of this region.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> usize {
        self.base
    }

    /// Get the size of this region.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Create a subregion starting at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if `offset + size` would exceed the parent region's bounds.
    #[inline]
    #[must_use]
    pub const fn subregion(&self, offset: usize, size: usize) -> Self {
        assert!(
            offset + size <= self.size,
            "Subregion exceeds parent bounds"
        );
        // SAFETY: Subregion is within the parent's valid bounds
        Self {
            base: self.base + offset,
            size,
        }
    }

    /// Read an 8-bit value from the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds.
    #[inline]
    #[must_use]
    pub fn read8(&self, offset: usize) -> u8 {
        debug_assert!(offset < self.size, "MMIO read8 offset out of bounds");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { read_volatile((self.base + offset) as *const u8) }
    }

    /// Read a 16-bit value from the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    #[must_use]
    pub fn read16(&self, offset: usize) -> u16 {
        debug_assert!(offset + 2 <= self.size, "MMIO read16 offset out of bounds");
        debug_assert!(offset.is_multiple_of(2), "MMIO read16 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { read_volatile((self.base + offset) as *const u16) }
    }

    /// Read a 32-bit value from the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    #[must_use]
    pub fn read32(&self, offset: usize) -> u32 {
        debug_assert!(offset + 4 <= self.size, "MMIO read32 offset out of bounds");
        debug_assert!(offset.is_multiple_of(4), "MMIO read32 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Read a 64-bit value from the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    #[must_use]
    pub fn read64(&self, offset: usize) -> u64 {
        debug_assert!(offset + 8 <= self.size, "MMIO read64 offset out of bounds");
        debug_assert!(offset.is_multiple_of(8), "MMIO read64 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { read_volatile((self.base + offset) as *const u64) }
    }

    /// Write an 8-bit value to the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds.
    #[inline]
    pub fn write8(&self, offset: usize, value: u8) {
        debug_assert!(offset < self.size, "MMIO write8 offset out of bounds");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { write_volatile((self.base + offset) as *mut u8, value) }
    }

    /// Write a 16-bit value to the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    pub fn write16(&self, offset: usize, value: u16) {
        debug_assert!(offset + 2 <= self.size, "MMIO write16 offset out of bounds");
        debug_assert!(offset.is_multiple_of(2), "MMIO write16 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { write_volatile((self.base + offset) as *mut u16, value) }
    }

    /// Write a 32-bit value to the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    pub fn write32(&self, offset: usize, value: u32) {
        debug_assert!(offset + 4 <= self.size, "MMIO write32 offset out of bounds");
        debug_assert!(offset.is_multiple_of(4), "MMIO write32 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Write a 64-bit value to the given offset.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if offset is out of bounds or misaligned.
    #[inline]
    pub fn write64(&self, offset: usize, value: u64) {
        debug_assert!(offset + 8 <= self.size, "MMIO write64 offset out of bounds");
        debug_assert!(offset.is_multiple_of(8), "MMIO write64 offset not aligned");
        // SAFETY: Caller ensured base is valid MMIO, offset is within bounds
        unsafe { write_volatile((self.base + offset) as *mut u64, value) }
    }

    /// Modify a 32-bit register using read-modify-write.
    ///
    /// Reads the register, applies the modifier function, and writes back.
    /// Note: This is NOT atomic - use with care for concurrent access.
    #[inline]
    pub fn modify32<F>(&self, offset: usize, f: F)
    where
        F: FnOnce(u32) -> u32,
    {
        let value = self.read32(offset);
        self.write32(offset, f(value));
    }

    /// Modify a 64-bit register using read-modify-write.
    ///
    /// Reads the register, applies the modifier function, and writes back.
    /// Note: This is NOT atomic - use with care for concurrent access.
    #[inline]
    pub fn modify64<F>(&self, offset: usize, f: F)
    where
        F: FnOnce(u64) -> u64,
    {
        let value = self.read64(offset);
        self.write64(offset, f(value));
    }

    /// Set bits in a 32-bit register.
    #[inline]
    pub fn set_bits32(&self, offset: usize, bits: u32) {
        self.modify32(offset, |v| v | bits);
    }

    /// Clear bits in a 32-bit register.
    #[inline]
    pub fn clear_bits32(&self, offset: usize, bits: u32) {
        self.modify32(offset, |v| v & !bits);
    }

    /// Poll a 32-bit register until a condition is met.
    ///
    /// Returns `true` if the condition was met, `false` if max iterations reached.
    #[inline]
    pub fn poll32<F>(&self, offset: usize, condition: F, max_iterations: usize) -> bool
    where
        F: Fn(u32) -> bool,
    {
        for _ in 0..max_iterations {
            if condition(self.read32(offset)) {
                return true;
            }
            // Hint to the CPU that we're spinning
            core::hint::spin_loop();
        }
        false
    }

    /// Poll a 64-bit register until a condition is met.
    ///
    /// Returns `true` if the condition was met, `false` if max iterations reached.
    #[inline]
    pub fn poll64<F>(&self, offset: usize, condition: F, max_iterations: usize) -> bool
    where
        F: Fn(u64) -> bool,
    {
        for _ in 0..max_iterations {
            if condition(self.read64(offset)) {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

impl core::fmt::Debug for MmioRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmioRegion")
            .field("base", &format_args!("{:#x}", self.base))
            .field("size", &format_args!("{:#x}", self.size))
            .finish()
    }
}
