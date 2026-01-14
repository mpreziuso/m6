//! VirtIO MMIO device abstraction.
//!
//! Provides a safe interface to VirtIO MMIO registers.

#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

/// VirtIO MMIO magic value ("virt" in little-endian)
pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// VirtIO device version (legacy = 1, modern = 2)
pub const VIRTIO_VERSION_LEGACY: u32 = 1;
pub const VIRTIO_VERSION_MODERN: u32 = 2;

/// VirtIO device IDs
pub mod device_id {
    pub const NETWORK: u32 = 1;
    pub const BLOCK: u32 = 2;
    pub const CONSOLE: u32 = 3;
    pub const ENTROPY: u32 = 4;
    pub const GPU: u32 = 16;
    pub const INPUT: u32 = 18;
}

/// VirtIO device status bits
pub mod status {
    /// Guest OS has acknowledged the device
    pub const ACKNOWLEDGE: u32 = 1;
    /// Guest OS knows how to drive the device
    pub const DRIVER: u32 = 2;
    /// Driver is set up and ready to drive the device
    pub const DRIVER_OK: u32 = 4;
    /// Driver has acknowledged all features it understands
    pub const FEATURES_OK: u32 = 8;
    /// Something went wrong - device needs reset
    pub const DEVICE_NEEDS_RESET: u32 = 64;
    /// Driver gave up on the device
    pub const FAILED: u32 = 128;
}

/// VirtIO MMIO register offsets
mod regs {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
    pub const HOST_FEATURES: usize = 0x010;
    pub const HOST_FEATURES_SEL: usize = 0x014;
    pub const GUEST_FEATURES: usize = 0x020;
    pub const GUEST_FEATURES_SEL: usize = 0x024;
    pub const GUEST_PAGE_SIZE: usize = 0x028; // Legacy only
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_ALIGN: usize = 0x03c; // Legacy only
    pub const QUEUE_PFN: usize = 0x040; // Legacy only
    pub const QUEUE_READY: usize = 0x044; // Modern only
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    // Modern queue address registers
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_AVAIL_LOW: usize = 0x090;
    pub const QUEUE_AVAIL_HIGH: usize = 0x094;
    pub const QUEUE_USED_LOW: usize = 0x0a0;
    pub const QUEUE_USED_HIGH: usize = 0x0a4;
    pub const CONFIG_GEN: usize = 0x0fc;
    pub const CONFIG: usize = 0x100;
}

/// VirtIO MMIO device abstraction.
pub struct VirtioMmio {
    base: usize,
}

impl VirtioMmio {
    /// Create a new VirtIO MMIO device instance.
    ///
    /// # Safety
    /// The caller must ensure `base` points to a valid, mapped VirtIO MMIO region.
    pub unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read a 32-bit register.
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: Caller of new() guarantees base is valid and mapped
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a 32-bit register.
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: Caller of new() guarantees base is valid and mapped
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Read magic value (should be 0x74726976).
    pub fn magic(&self) -> u32 {
        self.read32(regs::MAGIC)
    }

    /// Read device version (1 = legacy, 2 = modern).
    pub fn version(&self) -> u32 {
        self.read32(regs::VERSION)
    }

    /// Read device ID (1 = net, 2 = block, etc.).
    pub fn device_id(&self) -> u32 {
        self.read32(regs::DEVICE_ID)
    }

    /// Read vendor ID.
    pub fn vendor_id(&self) -> u32 {
        self.read32(regs::VENDOR_ID)
    }

    /// Check if this is a valid VirtIO device.
    pub fn is_valid(&self) -> bool {
        self.magic() == VIRTIO_MMIO_MAGIC && self.device_id() != 0
    }

    /// Check if this is a block device.
    pub fn is_block_device(&self) -> bool {
        self.device_id() == device_id::BLOCK
    }

    /// Read device status.
    pub fn status(&self) -> u32 {
        self.read32(regs::STATUS)
    }

    /// Write device status.
    pub fn set_status(&self, status: u32) {
        self.write32(regs::STATUS, status);
    }

    /// Reset the device (write 0 to status).
    pub fn reset(&self) {
        self.write32(regs::STATUS, 0);
    }

    /// Read host features (device-supported features).
    pub fn host_features(&self, sel: u32) -> u32 {
        self.write32(regs::HOST_FEATURES_SEL, sel);
        self.read32(regs::HOST_FEATURES)
    }

    /// Write guest features (driver-accepted features).
    pub fn set_guest_features(&self, sel: u32, features: u32) {
        self.write32(regs::GUEST_FEATURES_SEL, sel);
        self.write32(regs::GUEST_FEATURES, features);
    }

    /// Set guest page size (legacy devices only).
    pub fn set_guest_page_size(&self, size: u32) {
        self.write32(regs::GUEST_PAGE_SIZE, size);
    }

    /// Select a virtqueue for configuration.
    pub fn select_queue(&self, queue: u32) {
        self.write32(regs::QUEUE_SEL, queue);
    }

    /// Get maximum queue size for selected queue.
    pub fn queue_num_max(&self) -> u32 {
        self.read32(regs::QUEUE_NUM_MAX)
    }

    /// Set queue size for selected queue.
    pub fn set_queue_num(&self, num: u32) {
        self.write32(regs::QUEUE_NUM, num);
    }

    /// Set queue alignment (legacy devices only).
    pub fn set_queue_align(&self, align: u32) {
        self.write32(regs::QUEUE_ALIGN, align);
    }

    /// Set queue PFN (legacy devices only).
    /// PFN = physical_address / page_size
    pub fn set_queue_pfn(&self, pfn: u32) {
        self.write32(regs::QUEUE_PFN, pfn);
    }

    /// Set queue ready (modern devices only).
    pub fn set_queue_ready(&self, ready: bool) {
        self.write32(regs::QUEUE_READY, if ready { 1 } else { 0 });
    }

    /// Set queue descriptor address (modern devices only).
    pub fn set_queue_desc(&self, addr: u64) {
        self.write32(regs::QUEUE_DESC_LOW, addr as u32);
        self.write32(regs::QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }

    /// Set queue available ring address (modern devices only).
    pub fn set_queue_avail(&self, addr: u64) {
        self.write32(regs::QUEUE_AVAIL_LOW, addr as u32);
        self.write32(regs::QUEUE_AVAIL_HIGH, (addr >> 32) as u32);
    }

    /// Set queue used ring address (modern devices only).
    pub fn set_queue_used(&self, addr: u64) {
        self.write32(regs::QUEUE_USED_LOW, addr as u32);
        self.write32(regs::QUEUE_USED_HIGH, (addr >> 32) as u32);
    }

    /// Notify device that a queue has available buffers.
    pub fn queue_notify(&self, queue: u32) {
        self.write32(regs::QUEUE_NOTIFY, queue);
    }

    /// Read interrupt status.
    pub fn interrupt_status(&self) -> u32 {
        self.read32(regs::INTERRUPT_STATUS)
    }

    /// Acknowledge interrupts.
    pub fn interrupt_ack(&self, flags: u32) {
        self.write32(regs::INTERRUPT_ACK, flags);
    }

    /// Read configuration generation counter.
    pub fn config_generation(&self) -> u32 {
        self.read32(regs::CONFIG_GEN)
    }

    /// Read a byte from device-specific configuration space.
    pub fn config_read8(&self, offset: usize) -> u8 {
        // SAFETY: Caller of new() guarantees base is valid and mapped
        unsafe { read_volatile((self.base + regs::CONFIG + offset) as *const u8) }
    }

    /// Read a 32-bit value from device-specific configuration space.
    pub fn config_read32(&self, offset: usize) -> u32 {
        self.read32(regs::CONFIG + offset)
    }

    /// Read a 64-bit value from device-specific configuration space.
    pub fn config_read64(&self, offset: usize) -> u64 {
        let low = self.read32(regs::CONFIG + offset) as u64;
        let high = self.read32(regs::CONFIG + offset + 4) as u64;
        low | (high << 32)
    }
}
