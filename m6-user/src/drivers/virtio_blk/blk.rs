//! VirtIO block device operations.
//!
//! Implements the block-specific request/response protocol.

#![allow(dead_code)]

use super::virtio::VirtioMmio;
use super::virtqueue::Virtqueue;

/// VirtIO block device feature flags
pub mod features {
    /// Maximum size of any single segment is in `size_max`
    pub const SIZE_MAX: u64 = 1 << 1;
    /// Maximum number of segments in a request is in `seg_max`
    pub const SEG_MAX: u64 = 1 << 2;
    /// Disk-style geometry specified in `geometry`
    pub const GEOMETRY: u64 = 1 << 4;
    /// Device is read-only
    pub const RO: u64 = 1 << 5;
    /// Block size of disk is in `blk_size`
    pub const BLK_SIZE: u64 = 1 << 6;
    /// Cache flush command support
    pub const FLUSH: u64 = 1 << 9;
    /// Device exports information on optimal I/O alignment
    pub const TOPOLOGY: u64 = 1 << 10;
    /// Device can toggle its cache between writeback and writethrough modes
    pub const CONFIG_WCE: u64 = 1 << 11;
}

/// VirtIO block request types
pub mod req_type {
    /// Read from device
    pub const IN: u32 = 0;
    /// Write to device
    pub const OUT: u32 = 1;
    /// Flush device buffers
    pub const FLUSH: u32 = 4;
    /// Get device ID string
    pub const GET_ID: u32 = 8;
    /// Discard sectors
    pub const DISCARD: u32 = 11;
    /// Write zeroes
    pub const WRITE_ZEROES: u32 = 13;
}

/// VirtIO block request status
pub mod req_status {
    /// Success
    pub const OK: u8 = 0;
    /// I/O error
    pub const IOERR: u8 = 1;
    /// Operation not supported
    pub const UNSUPP: u8 = 2;
}

/// VirtIO block request header (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioBlkReqHeader {
    /// Request type (IN, OUT, FLUSH, etc.)
    pub type_: u32,
    /// Reserved (must be 0)
    pub reserved: u32,
    /// Sector number (512-byte sectors)
    pub sector: u64,
}

/// VirtIO block device configuration (read from config space)
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkConfig {
    /// Device capacity in 512-byte sectors
    pub capacity: u64,
    /// Maximum segment size (if SIZE_MAX feature)
    pub size_max: u32,
    /// Maximum segments per request (if SEG_MAX feature)
    pub seg_max: u32,
    /// Geometry (if GEOMETRY feature)
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
    /// Block size (if BLK_SIZE feature)
    pub blk_size: u32,
}

impl VirtioBlkConfig {
    /// Read configuration from device.
    pub fn read_from(dev: &VirtioMmio) -> Self {
        // Read capacity atomically using config generation
        let capacity = loop {
            let gen1 = dev.config_generation();
            let cap = dev.config_read64(0);
            let gen2 = dev.config_generation();
            if gen1 == gen2 {
                break cap;
            }
        };

        Self {
            capacity,
            size_max: dev.config_read32(8),
            seg_max: dev.config_read32(12),
            cylinders: dev.config_read32(16) as u16,
            heads: dev.config_read8(18),
            sectors: dev.config_read8(19),
            blk_size: dev.config_read32(20),
        }
    }

    /// Get capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity * 512
    }
}

/// VirtIO block device driver.
pub struct VirtioBlkDevice {
    /// MMIO device access
    dev: VirtioMmio,
    /// Request virtqueue
    vq: Option<Virtqueue>,
    /// Device configuration
    config: VirtioBlkConfig,
    /// Negotiated features
    features: u64,
    /// Request header buffer (one per pending request)
    req_header: VirtioBlkReqHeader,
    /// Status byte buffer
    status: u8,
    /// IOVA base for DMA buffers (when using IOSpace/IOMMU)
    dma_iova_base: u64,
    /// Whether IOSpace/IOMMU is used for DMA
    uses_iommu: bool,
}

impl VirtioBlkDevice {
    /// Create a new block device driver.
    ///
    /// # Safety
    ///
    /// The caller must ensure `mmio_base` points to a valid, mapped VirtIO MMIO region.
    pub unsafe fn new(mmio_base: usize) -> Self {
        // SAFETY: Caller guarantees mmio_base is valid and mapped
        let dev = unsafe { VirtioMmio::new(mmio_base) };
        Self {
            dev,
            vq: None,
            config: VirtioBlkConfig::default(),
            features: 0,
            req_header: VirtioBlkReqHeader::default(),
            status: 0,
            dma_iova_base: 0,
            uses_iommu: false,
        }
    }

    /// Initialise the device.
    ///
    /// # Safety
    ///
    /// `vq_mem` must point to properly aligned, physically contiguous memory
    /// that is at least `Virtqueue::memory_layout(queue_size).3` bytes.
    pub unsafe fn init(&mut self, vq_mem: *mut u8, vq_phys: u64) -> Result<(), &'static str> {
        use super::virtio::status;

        // 1. Reset the device
        self.dev.reset();

        // 2. Acknowledge the device
        self.dev.set_status(status::ACKNOWLEDGE);

        // 3. Set DRIVER status
        self.dev.set_status(status::ACKNOWLEDGE | status::DRIVER);

        // 4. Read and negotiate features
        let host_features = self.dev.host_features(0) as u64;
        // Accept basic features we understand
        let accepted = host_features & (features::SIZE_MAX | features::SEG_MAX |
                                         features::BLK_SIZE | features::FLUSH | features::RO);
        self.features = accepted;
        self.dev.set_guest_features(0, accepted as u32);

        // 5. Set FEATURES_OK
        self.dev.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        // 6. Check FEATURES_OK was accepted
        if self.dev.status() & status::FEATURES_OK == 0 {
            self.dev.set_status(status::FAILED);
            return Err("Device rejected features");
        }

        // 7. Read device configuration
        self.config = VirtioBlkConfig::read_from(&self.dev);

        // 8. Configure virtqueue (queue 0)
        self.dev.select_queue(0);
        let max_size = self.dev.queue_num_max();
        if max_size == 0 {
            self.dev.set_status(status::FAILED);
            return Err("No virtqueue available");
        }

        // Use a reasonable queue size
        let queue_size = max_size.min(64) as u16;
        self.dev.set_queue_num(queue_size as u32);

        // Create virtqueue
        // SAFETY: caller guarantees vq_mem is valid
        let vq = unsafe { Virtqueue::new(vq_mem, queue_size) };
        let (desc_addr, avail_addr, used_addr) = vq.addresses();

        // Check if legacy or modern device
        let version = self.dev.version();
        if version == 1 {
            // Legacy: use page-based addressing
            self.dev.set_guest_page_size(4096);
            self.dev.set_queue_align(4096);
            self.dev.set_queue_pfn((vq_phys / 4096) as u32);
        } else {
            // Modern: use direct addresses
            self.dev.set_queue_desc(desc_addr);
            self.dev.set_queue_avail(avail_addr);
            self.dev.set_queue_used(used_addr);
            self.dev.set_queue_ready(true);
        }

        self.vq = Some(vq);

        // 9. Set DRIVER_OK
        self.dev.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK);

        Ok(())
    }

    /// Get device configuration.
    pub fn config(&self) -> &VirtioBlkConfig {
        &self.config
    }

    /// Check if device is read-only.
    pub fn is_read_only(&self) -> bool {
        self.features & features::RO != 0
    }

    /// Check if device supports flush.
    pub fn supports_flush(&self) -> bool {
        self.features & features::FLUSH != 0
    }

    /// Enable IOSpace/IOMMU mode with the given IOVA base.
    ///
    /// When IOSpace is enabled, all DMA addresses passed to read_sector/write_sector
    /// are treated as IOVAs (I/O Virtual Addresses) rather than physical addresses.
    pub fn enable_iospace(&mut self, iova_base: u64) {
        self.uses_iommu = true;
        self.dma_iova_base = iova_base;
    }

    /// Get the IOVA base (for calculating descriptor IOVAs).
    pub fn iova_base(&self) -> u64 {
        self.dma_iova_base
    }

    /// Submit a read request.
    ///
    /// Returns the descriptor head for tracking.
    pub fn read_sector(
        &mut self,
        sector: u64,
        data_phys: u64,
        data_len: u32,
        header_phys: u64,
        status_phys: u64,
    ) -> Option<u16> {
        // Prepare header
        self.req_header.type_ = req_type::IN;
        self.req_header.reserved = 0;
        self.req_header.sector = sector;

        // Write header to its buffer
        // SAFETY: header_phys must point to valid DMA memory
        // In a real implementation, we'd copy to the DMA buffer
        // For now, assume header is at header_phys

        let vq = self.vq.as_mut()?;
        let head = vq.add_block_request(
            header_phys,
            16, // sizeof(VirtioBlkReqHeader)
            data_phys,
            data_len,
            status_phys,
            false, // is_write = false (device writes to data buffer)
        )?;

        // Notify device
        self.dev.queue_notify(0);

        Some(head)
    }

    /// Submit a write request.
    pub fn write_sector(
        &mut self,
        sector: u64,
        data_phys: u64,
        data_len: u32,
        header_phys: u64,
        status_phys: u64,
    ) -> Option<u16> {
        if self.is_read_only() {
            return None;
        }

        // Prepare header
        self.req_header.type_ = req_type::OUT;
        self.req_header.reserved = 0;
        self.req_header.sector = sector;

        let vq = self.vq.as_mut()?;
        let head = vq.add_block_request(
            header_phys,
            16,
            data_phys,
            data_len,
            status_phys,
            true, // is_write = true (device reads from data buffer)
        )?;

        // Notify device
        self.dev.queue_notify(0);

        Some(head)
    }

    /// Submit a flush request.
    pub fn flush(&mut self, header_phys: u64, status_phys: u64) -> Option<u16> {
        if !self.supports_flush() {
            return None;
        }

        self.req_header.type_ = req_type::FLUSH;
        self.req_header.reserved = 0;
        self.req_header.sector = 0;

        let vq = self.vq.as_mut()?;
        // Flush has no data buffer, just header + status
        let _head = vq.add_buf(header_phys, 16, false)?;
        // We need to manually add the status descriptor
        // For simplicity, use the block request helper with zero-length data
        let head = vq.add_block_request(
            header_phys,
            16,
            header_phys, // dummy data address
            0,           // zero length
            status_phys,
            true,
        )?;

        self.dev.queue_notify(0);
        Some(head)
    }

    /// Poll for completed requests.
    ///
    /// Returns (descriptor_head, bytes_written, status) if a request completed.
    pub fn poll_completion(&mut self) -> Option<(u16, u32)> {
        let vq = self.vq.as_mut()?;
        vq.pop_used()
    }

    /// Check if there are completed requests.
    pub fn has_completion(&self) -> bool {
        self.vq.as_ref().is_some_and(|vq| vq.has_used())
    }

    /// Free a descriptor chain after processing.
    pub fn free_request(&mut self, head: u16) {
        if let Some(vq) = self.vq.as_mut() {
            vq.free_chain(head);
        }
    }

    /// Acknowledge interrupt.
    pub fn ack_interrupt(&self) {
        let status = self.dev.interrupt_status();
        self.dev.interrupt_ack(status);
    }

    /// Get the request header buffer address.
    pub fn req_header_addr(&self) -> *const VirtioBlkReqHeader {
        &self.req_header
    }

    /// Get the status buffer address.
    pub fn status_addr(&self) -> *const u8 {
        &self.status
    }
}
