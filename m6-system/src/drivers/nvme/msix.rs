//! MSI-X Interrupt Handling for NVMe
//!
//! NVMe uses MSI-X for efficient per-queue interrupt delivery. Each completion
//! queue can be assigned its own interrupt vector, allowing for parallel
//! processing across multiple CPUs.
//!
//! # Vector Assignment
//!
//! - Vector 0: Admin completion queue
//! - Vector 1..N: I/O completion queues
//!
//! # Integration with M6
//!
//! MSI-X vectors are mapped to ARM GIC SPIs. Each completion queue binds to
//! a Notification capability via `irq_set_handler()`. The driver waits on the
//! notification and then processes completions.

#![allow(dead_code)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// MSI-X Table Entry (16 bytes)
///
/// Each entry in the MSI-X table describes one interrupt vector.
#[repr(C)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MsixTableEntry {
    /// Message Address Low (bits [31:0])
    pub msg_addr_lo: u32,
    /// Message Address High (bits [63:32])
    pub msg_addr_hi: u32,
    /// Message Data (interrupt vector identifier)
    pub msg_data: u32,
    /// Vector Control (bit 0 = mask)
    pub vector_ctrl: u32,
}

impl MsixTableEntry {
    /// Create a new MSI-X table entry.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64, data: u32) -> Self {
        Self {
            msg_addr_lo: addr as u32,
            msg_addr_hi: (addr >> 32) as u32,
            msg_data: data,
            vector_ctrl: 0, // Unmasked
        }
    }

    /// Get the full message address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> u64 {
        (self.msg_addr_lo as u64) | ((self.msg_addr_hi as u64) << 32)
    }

    /// Check if the vector is masked.
    #[inline]
    #[must_use]
    pub const fn is_masked(&self) -> bool {
        (self.vector_ctrl & 1) != 0
    }
}

/// MSI-X Pending Bit Array entry
///
/// Each bit in the PBA indicates whether an interrupt is pending for the
/// corresponding vector when the vector is masked.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsixPbaEntry {
    /// Pending bits (64 vectors per entry)
    pub pending: u64,
}

/// MSI-X Configuration for NVMe
///
/// Manages the MSI-X table and provides methods for configuring vectors.
pub struct MsixConfig {
    /// Base address of MSI-X table in MMIO space
    table_base: *mut MsixTableEntry,
    /// Number of vectors available
    table_size: u16,
}

impl MsixConfig {
    /// Create a new MSI-X configuration.
    ///
    /// # Safety
    ///
    /// The caller must ensure `table_base` points to a valid, mapped MSI-X
    /// table region.
    #[inline]
    pub unsafe fn new(table_base: *mut MsixTableEntry, table_size: u16) -> Self {
        Self {
            table_base,
            table_size,
        }
    }

    /// Get the number of vectors available.
    #[inline]
    #[must_use]
    pub const fn table_size(&self) -> u16 {
        self.table_size
    }

    /// Configure a vector for interrupt delivery.
    ///
    /// # Arguments
    ///
    /// - `vector`: Vector index (0..table_size)
    /// - `target_addr`: Message signalled interrupt target address
    /// - `data`: Message data (typically contains the interrupt vector number)
    pub fn configure_vector(&mut self, vector: u16, target_addr: u64, data: u32) {
        debug_assert!(vector < self.table_size, "Vector index out of range");

        // SAFETY: vector is within bounds, table_base is valid
        unsafe {
            let entry = &mut *self.table_base.add(vector as usize);
            entry.msg_addr_lo = target_addr as u32;
            entry.msg_addr_hi = (target_addr >> 32) as u32;
            entry.msg_data = data;
            entry.vector_ctrl = 0; // Unmask
        }
    }

    /// Mask a vector (disable interrupts for this vector).
    pub fn mask_vector(&mut self, vector: u16) {
        debug_assert!(vector < self.table_size, "Vector index out of range");

        // SAFETY: vector is within bounds
        unsafe {
            let entry = &mut *self.table_base.add(vector as usize);
            entry.vector_ctrl |= 1;
        }
    }

    /// Unmask a vector (enable interrupts for this vector).
    pub fn unmask_vector(&mut self, vector: u16) {
        debug_assert!(vector < self.table_size, "Vector index out of range");

        // SAFETY: vector is within bounds
        unsafe {
            let entry = &mut *self.table_base.add(vector as usize);
            entry.vector_ctrl &= !1;
        }
    }

    /// Check if a vector is masked.
    #[must_use]
    pub fn is_vector_masked(&self, vector: u16) -> bool {
        debug_assert!(vector < self.table_size, "Vector index out of range");

        // SAFETY: vector is within bounds
        unsafe {
            let entry = &*self.table_base.add(vector as usize);
            entry.is_masked()
        }
    }

    /// Read a vector entry.
    #[must_use]
    pub fn read_vector(&self, vector: u16) -> MsixTableEntry {
        debug_assert!(vector < self.table_size, "Vector index out of range");

        // SAFETY: vector is within bounds
        unsafe { core::ptr::read_volatile(self.table_base.add(vector as usize)) }
    }
}

// SAFETY: MsixConfig can be sent if the underlying memory is valid
unsafe impl Send for MsixConfig {}

/// MSI-X capability header (found in PCI configuration space)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsixCapability {
    /// Capability ID (0x11 for MSI-X)
    pub cap_id: u8,
    /// Next capability pointer
    pub next_ptr: u8,
    /// Message Control
    pub msg_ctrl: u16,
    /// Table Offset and BIR
    pub table_offset_bir: u32,
    /// PBA Offset and BIR
    pub pba_offset_bir: u32,
}

impl MsixCapability {
    /// MSI-X Capability ID
    pub const CAP_ID: u8 = 0x11;

    /// Get the table size (number of vectors - 1).
    #[inline]
    #[must_use]
    pub const fn table_size(&self) -> u16 {
        (self.msg_ctrl & 0x7FF) + 1
    }

    /// Check if MSI-X is enabled.
    #[inline]
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        (self.msg_ctrl & (1 << 15)) != 0
    }

    /// Check if function mask is set.
    #[inline]
    #[must_use]
    pub const fn is_function_masked(&self) -> bool {
        (self.msg_ctrl & (1 << 14)) != 0
    }

    /// Get the table BAR indicator (which BAR contains the table).
    #[inline]
    #[must_use]
    pub const fn table_bir(&self) -> u8 {
        (self.table_offset_bir & 0x7) as u8
    }

    /// Get the table offset within the BAR.
    #[inline]
    #[must_use]
    pub const fn table_offset(&self) -> u32 {
        self.table_offset_bir & !0x7
    }

    /// Get the PBA BAR indicator.
    #[inline]
    #[must_use]
    pub const fn pba_bir(&self) -> u8 {
        (self.pba_offset_bir & 0x7) as u8
    }

    /// Get the PBA offset within the BAR.
    #[inline]
    #[must_use]
    pub const fn pba_offset(&self) -> u32 {
        self.pba_offset_bir & !0x7
    }
}

/// NVMe interrupt vector assignments
pub struct NvmeVectors {
    /// Admin queue vector
    pub admin_vector: u16,
    /// First I/O queue vector
    pub io_vector_base: u16,
    /// Number of I/O vectors available
    pub io_vector_count: u16,
}

impl NvmeVectors {
    /// Create a new vector assignment with the given table size.
    ///
    /// Uses vector 0 for admin queue, remaining vectors for I/O queues.
    #[inline]
    #[must_use]
    pub const fn new(table_size: u16) -> Self {
        Self {
            admin_vector: 0,
            io_vector_base: 1,
            io_vector_count: table_size.saturating_sub(1),
        }
    }

    /// Get the vector for an I/O queue.
    ///
    /// If there are fewer vectors than I/O queues, vectors are shared.
    #[inline]
    #[must_use]
    pub const fn io_vector(&self, qid: u16) -> u16 {
        if self.io_vector_count == 0 {
            self.admin_vector // Fall back to admin vector
        } else {
            // qid is 1-based for I/O queues, so (qid - 1) % count + base
            self.io_vector_base + ((qid - 1) % self.io_vector_count)
        }
    }
}
