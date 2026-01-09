//! Untyped memory capability
//!
//! Represents raw physical memory that can be retyped into other kernel
//! objects. Untyped memory is the root of all memory authority in the
//! system.
//!
//! # Watermark
//!
//! Each untyped memory object has a watermark tracking how much has
//! been allocated. The watermark only moves forward; to reclaim memory,
//! all derived capabilities must be revoked, which resets the watermark.
//!
//! # Retype Operation
//!
//! The kernel provides a retype operation that:
//! 1. Checks sufficient space remains (watermark + size <= total)
//! 2. Creates the requested object at the next aligned address
//! 3. Advances the watermark
//! 4. Creates a capability to the new object as a child of the untyped

use m6_common::PhysAddr;

use crate::error::CapError;
use crate::slot::ObjectType;

/// Untyped memory object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct UntypedObject {
    /// Physical base address.
    pub phys_base: PhysAddr,
    /// Total size as log2 (size = 1 << size_bits).
    pub size_bits: u8,
    /// Whether this is device memory.
    pub is_device: bool,
    /// Watermark - offset of first free byte.
    /// All bytes before watermark have been retyped.
    pub watermark: u32,
}

impl UntypedObject {
    /// Minimum untyped size (16 bytes, for a single CapSlot).
    pub const MIN_SIZE_BITS: u8 = 4;

    /// Maximum untyped size (2^47 bytes, 128 TB).
    pub const MAX_SIZE_BITS: u8 = 47;

    /// Create a new untyped memory object.
    ///
    /// # Parameters
    ///
    /// - `phys_base`: Physical base address (must be aligned to size)
    /// - `size_bits`: Size as log2 (4 to 47)
    /// - `is_device`: Whether this is device memory
    #[inline]
    #[must_use]
    pub const fn new(phys_base: PhysAddr, size_bits: u8, is_device: bool) -> Self {
        Self {
            phys_base,
            size_bits,
            is_device,
            watermark: 0,
        }
    }

    /// Total size in bytes.
    #[inline]
    #[must_use]
    pub const fn size(&self) -> usize {
        1 << self.size_bits
    }

    /// Free space remaining.
    #[inline]
    #[must_use]
    pub const fn free_space(&self) -> usize {
        self.size().saturating_sub(self.watermark as usize)
    }

    /// Check if completely consumed.
    #[inline]
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.watermark as usize >= self.size()
    }

    /// Reset watermark (after revocation of all children).
    #[inline]
    pub fn reset(&mut self) {
        self.watermark = 0;
    }

    /// Physical address of the next allocation point.
    #[inline]
    #[must_use]
    pub const fn next_alloc_addr(&self) -> PhysAddr {
        self.phys_base.offset(self.watermark as u64)
    }

    /// Try to allocate space for an object.
    ///
    /// # Parameters
    ///
    /// - `object_size`: Size of the object to allocate
    /// - `alignment`: Required alignment (power of 2)
    ///
    /// # Returns
    ///
    /// Physical address of the allocated space, or error.
    pub fn try_allocate(
        &mut self,
        object_size: usize,
        alignment: usize,
    ) -> Result<PhysAddr, CapError> {
        // Calculate aligned watermark
        let aligned_watermark = (self.watermark as usize + alignment - 1) & !(alignment - 1);
        let end_offset = aligned_watermark + object_size;

        // Check if fits
        if end_offset > self.size() {
            return Err(CapError::UntypedExhausted);
        }

        // Allocate
        let alloc_addr = self.phys_base.offset(aligned_watermark as u64);
        self.watermark = end_offset as u32;

        Ok(alloc_addr)
    }
}

/// Parameters for retyping untyped memory into new objects.
#[derive(Clone, Debug)]
pub struct RetypeParams {
    /// Target object type.
    pub target_type: ObjectType,
    /// Size bits for variable-size objects (CNode, Untyped).
    /// Ignored for fixed-size objects.
    pub size_bits: u8,
    /// Number of objects to create.
    pub count: usize,
}

impl RetypeParams {
    /// Create retype parameters for a single object.
    #[inline]
    #[must_use]
    pub const fn single(target_type: ObjectType) -> Self {
        Self {
            target_type,
            size_bits: 0,
            count: 1,
        }
    }

    /// Create retype parameters for multiple objects.
    #[inline]
    #[must_use]
    pub const fn multiple(target_type: ObjectType, count: usize) -> Self {
        Self {
            target_type,
            size_bits: 0,
            count,
        }
    }

    /// Create retype parameters for a variable-size object.
    #[inline]
    #[must_use]
    pub const fn with_size(target_type: ObjectType, size_bits: u8) -> Self {
        Self {
            target_type,
            size_bits,
            count: 1,
        }
    }
}

/// Get the size of a kernel object type.
///
/// # Parameters
///
/// - `obj_type`: The object type
/// - `size_bits`: Size bits for variable-size objects
///
/// # Returns
///
/// Size in bytes, or error if invalid.
pub const fn object_size(obj_type: ObjectType, size_bits: u8) -> Result<usize, CapError> {
    match obj_type {
        ObjectType::Empty => Err(CapError::InvalidOperation),

        // Variable-size objects
        ObjectType::Untyped => {
            if size_bits < UntypedObject::MIN_SIZE_BITS {
                Err(CapError::SizeTooSmall)
            } else {
                Ok(1 << size_bits)
            }
        }
        ObjectType::CNode => {
            // CNode size = 16 bytes per slot * 2^radix slots
            if size_bits < 1 || size_bits > 12 {
                Err(CapError::InvalidRadix)
            } else {
                Ok(16 << size_bits)
            }
        }

        // Fixed-size objects (page-aligned, 4KB)
        ObjectType::Frame => Ok(4096),
        ObjectType::DeviceFrame => Ok(4096),
        ObjectType::PageTableL0 => Ok(4096),
        ObjectType::PageTableL1 => Ok(4096),
        ObjectType::PageTableL2 => Ok(4096),
        ObjectType::PageTableL3 => Ok(4096),
        ObjectType::VSpace => Ok(4096),
        ObjectType::ASIDPool => Ok(4096),

        // Smaller fixed-size objects
        ObjectType::ASIDControl => Ok(64),
        ObjectType::Endpoint => Ok(64),
        ObjectType::Notification => Ok(64),
        ObjectType::Reply => Ok(64),
        ObjectType::TCB => Ok(1024), // TCBs are larger due to register context
        ObjectType::IRQHandler => Ok(64),
        ObjectType::IRQControl => Ok(64),
        ObjectType::SchedContext => Ok(256),
        ObjectType::SchedControl => Ok(64),
    }
}

/// Get the alignment requirement for a kernel object type.
pub const fn object_alignment(obj_type: ObjectType, size_bits: u8) -> usize {
    match obj_type {
        // Page-aligned objects
        ObjectType::Frame
        | ObjectType::DeviceFrame
        | ObjectType::PageTableL0
        | ObjectType::PageTableL1
        | ObjectType::PageTableL2
        | ObjectType::PageTableL3
        | ObjectType::VSpace
        | ObjectType::ASIDPool => 4096,

        // Variable-size objects align to their size
        ObjectType::Untyped | ObjectType::CNode => 1 << size_bits,

        // Other objects align to 64 bytes (cache line)
        _ => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untyped_creation() {
        let ut = UntypedObject::new(PhysAddr::new(0x1000), 12, false);
        assert_eq!(ut.size(), 4096);
        assert_eq!(ut.free_space(), 4096);
        assert!(!ut.is_exhausted());
    }

    #[test]
    fn test_untyped_allocation() {
        let mut ut = UntypedObject::new(PhysAddr::new(0x1000), 12, false);

        // Allocate 64 bytes aligned to 64
        let addr = ut.try_allocate(64, 64).unwrap();
        assert_eq!(addr.as_u64(), 0x1000);
        assert_eq!(ut.watermark, 64);

        // Allocate another 64 bytes
        let addr = ut.try_allocate(64, 64).unwrap();
        assert_eq!(addr.as_u64(), 0x1040);
        assert_eq!(ut.watermark, 128);
    }

    #[test]
    fn test_untyped_exhaustion() {
        let mut ut = UntypedObject::new(PhysAddr::new(0x1000), 6, false); // 64 bytes

        // Allocate 64 bytes
        let _ = ut.try_allocate(64, 1).unwrap();
        assert!(ut.is_exhausted());

        // Try to allocate more
        assert!(ut.try_allocate(1, 1).is_err());
    }
}
