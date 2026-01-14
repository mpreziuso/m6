//! VirtIO Block Device Driver
//!
//! Userspace driver for VirtIO block devices (virtio-blk).
//! Provides sector read/write/flush operations via IPC.
//!
//! Capabilities received from device-mgr:
//! - Slot 10: DeviceFrame for MMIO access
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 14: Notification for IRQ delivery
//! - Slots 21-28: DMA buffer frames for virtqueue and data buffers

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate m6_std as std;

mod blk;
mod ipc;
mod virtio;
mod virtqueue;

// Re-use io module from parent crate (for early debug output)
#[path = "../../io.rs"]
mod io;

use m6_syscall::invoke::{
    dma_pool_alloc, ipc_get_recv_caps, ipc_set_recv_slots, iospace_map_frame,
    iospace_unmap_frame, irq_set_handler, map_frame, recv, reply_recv,
    sched_yield,
};

use blk::VirtioBlkDevice;

// -- Well-known capability slots (mirroring device_mgr::slots::driver)
// The driver's CSpace has radix 10 (1024 slots).
// CPtrs are formatted as: slot << (64 - radix) = slot << 54

const CNODE_RADIX: u8 = 10;

/// Convert slot number to CPtr.
#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

/// Root CNode (slot 0)
#[allow(dead_code)]
const ROOT_CNODE: u64 = cptr(0);
/// Root VSpace capability (slot 2)
const ROOT_VSPACE: u64 = cptr(2);
/// DeviceFrame for MMIO access (slot 10)
const DEVICE_FRAME: u64 = cptr(10);
/// IRQHandler for interrupt handling (slot 11)
const IRQ_HANDLER: u64 = cptr(11);
/// Service endpoint for clients (slot 12)
const SERVICE_EP: u64 = cptr(12);
/// IOSpace for DMA (slot 13)
const IOSPACE: u64 = cptr(13);
/// Notification for IRQ delivery (slot 14)
const IRQ_NOTIF: u64 = cptr(14);
/// DMA pool for IOVA allocation (slot 16)
const DMA_POOL: u64 = cptr(16);
/// First DMA buffer frame (slots 21-28)
#[allow(dead_code)]
const DMA_BUFFER_START: u64 = 21;
/// Number of DMA buffer frames
#[allow(dead_code)]
const DMA_BUFFER_COUNT: usize = 8;

/// Virtual address where we map the VirtIO MMIO region.
const VIRTIO_MMIO_VADDR: u64 = 0x0000_8000_0000;

/// Virtual address for DMA buffer region.
const DMA_BUFFER_VADDR: u64 = 0x0000_8001_0000;

/// Badge value for IRQ notification (for future IRQ-driven I/O)
const IRQ_BADGE: u64 = 1;

/// First free slot for dynamic allocations (client frame capabilities)
const FIRST_FREE_SLOT: u64 = 100;

/// Simple slot allocator for capability slots.
struct SlotAllocator {
    next_free_slot: u64,
}

impl SlotAllocator {
    const fn new() -> Self {
        Self {
            next_free_slot: FIRST_FREE_SLOT,
        }
    }

    /// Allocate a free capability slot.
    fn alloc_slot(&mut self) -> u64 {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }
}

/// Entry point for VirtIO block driver.
///
/// # Arguments (passed via registers)
/// - x0: Device offset within the mapped page (for non-page-aligned devices)
///
/// # Safety
///
/// Must be called only once as the entry point. Device-mgr must have provided
/// the required capabilities in well-known slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_offset: u64) -> ! {
    // Note: We don't call init_console() here because this driver is spawned
    // before the UART driver, so there's no console endpoint available.
    // The io module will fall back to debug_putc() for output.

    io::puts("\n\x1b[36m[drv-virtio-blk] Starting VirtIO block driver\x1b[0m\n");

    // Map the DeviceFrame to our address space
    match map_frame(ROOT_VSPACE, DEVICE_FRAME, VIRTIO_MMIO_VADDR, 0b011, 0) {
        Ok(_) => {
            io::puts("[drv-virtio-blk] Mapped MMIO at ");
            io::put_hex(VIRTIO_MMIO_VADDR);
            io::newline();
        }
        Err(e) => {
            io::puts("[drv-virtio-blk] ERROR: Failed to map MMIO: ");
            io::put_u64(e as u64);
            io::newline();
            loop {
                sched_yield();
            }
        }
    }

    // Calculate actual device address (page base + offset within page)
    let device_addr = VIRTIO_MMIO_VADDR + device_offset;
    io::puts("[drv-virtio-blk] Device at ");
    io::put_hex(device_addr);
    io::puts(" (offset ");
    io::put_hex(device_offset);
    io::puts(")\n");

    // Get DMA buffer base address (already mapped by device-mgr)
    let dma_base = get_dma_buffers();
    io::puts("[drv-virtio-blk] DMA buffers at ");
    io::put_hex(dma_base);
    io::newline();

    // Create device instance
    // SAFETY: We just mapped the device frame and calculated the correct offset
    let mut device = unsafe { VirtioBlkDevice::new(device_addr as usize) };

    // Check device type
    // SAFETY: MMIO region is valid
    let dev_mmio = unsafe { virtio::VirtioMmio::new(device_addr as usize) };
    if !dev_mmio.is_valid() {
        io::puts("[drv-virtio-blk] ERROR: Invalid VirtIO device\n");
        loop {
            sched_yield();
        }
    }

    if !dev_mmio.is_block_device() {
        io::puts("[drv-virtio-blk] ERROR: Not a block device (ID=");
        io::put_u64(dev_mmio.device_id() as u64);
        io::puts(")\n");
        loop {
            sched_yield();
        }
    }

    io::puts("[drv-virtio-blk] Found VirtIO block device (vendor=");
    io::put_hex(dev_mmio.vendor_id() as u64);
    io::puts(", version=");
    io::put_u64(dev_mmio.version() as u64);
    io::puts(")\n");

    // Initialise device with DMA buffers
    // Use first 4KB for virtqueue structures, rest for data
    // SAFETY: dma_base points to valid mapped DMA memory
    let vq_mem = dma_base as *mut u8;
    let vq_phys = DMA_BUFFER_VADDR; // In real impl, need to get physical address
    match unsafe { device.init(vq_mem, vq_phys) } {
        Ok(_) => {}
        Err(e) => {
            io::puts("[drv-virtio-blk] ERROR: Device init failed: ");
            io::puts(e);
            io::newline();
            loop {
                sched_yield();
            }
        }
    }

    // Report device info
    let config = device.config();
    io::puts("[drv-virtio-blk] Capacity: ");
    io::put_u64(config.capacity);
    io::puts(" sectors (");
    io::put_u64(config.capacity_bytes() / (1024 * 1024));
    io::puts(" MiB)\n");

    if device.is_read_only() {
        io::puts("[drv-virtio-blk] Device is read-only\n");
    }

    // Set up IRQ handling
    let irq_enabled = setup_irq();

    if irq_enabled {
        io::puts("[drv-virtio-blk] IRQ handler configured\n");
    }

    io::puts("[drv-virtio-blk] Initialised, entering service loop\n");

    // Enter the service loop
    service_loop(&mut device);
}

/// Get DMA buffer base address.
///
/// DMA buffer frames (slots 21-28) are pre-mapped by device-mgr at spawn time
/// to `DMA_BUFFER_VADDR` (0x8001_0000). We just return that address.
fn get_dma_buffers() -> u64 {
    // DMA buffers are already mapped by device-mgr
    DMA_BUFFER_VADDR
}

/// Set up IRQ handling.
fn setup_irq() -> bool {
    match irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE) {
        Ok(_) => true,
        Err(e) => {
            io::puts("[drv-virtio-blk] irq_set_handler failed: ");
            io::put_u64(e as u64);
            io::newline();
            false
        }
    }
}

/// Main service loop - handles client IPC requests.
fn service_loop(device: &mut VirtioBlkDevice) -> ! {
    let mut tracker = SlotAllocator::new();

    // Set up IPC receive slots for capability transfer (slot for client frame caps)
    let recv_slot = tracker.alloc_slot();
    // SAFETY: IPC buffer is mapped at fixed address by kernel
    unsafe {
        ipc_set_recv_slots(&[recv_slot]);
    }

    // Receive first message
    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                // Handle client request
                let response = handle_request(
                    device,
                    &mut tracker,
                    ipc_result.badge,
                    ipc_result.label,
                    &ipc_result.msg,
                );

                // Reply and receive next message
                result = reply_recv(SERVICE_EP, response, 0, 0, 0);
            }
            Err(err) => {
                io::puts("[drv-virtio-blk] IPC error: ");
                io::put_u64(err as u64);
                io::newline();
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(
    device: &mut VirtioBlkDevice,
    tracker: &mut SlotAllocator,
    badge: u64,
    label: u64,
    msg: &[u64; 4],
) -> u64 {
    match label & 0xFFFF {
        ipc::request::GET_INFO => handle_get_info(device),
        ipc::request::GET_STATUS => handle_get_status(device),
        ipc::request::READ_SECTOR => handle_read_sector(device, tracker, badge, msg),
        ipc::request::WRITE_SECTOR => handle_write_sector(device, tracker, badge, msg),
        ipc::request::FLUSH => handle_flush(device),
        _ => ipc::response::ERR_INVALID,
    }
}

/// Handle GET_INFO request.
fn handle_get_info(device: &VirtioBlkDevice) -> u64 {
    let config = device.config();
    // In a real implementation, we'd return config in reply registers
    // For now, just acknowledge
    let _ = config;
    ipc::response::OK
}

/// Handle GET_STATUS request.
fn handle_get_status(device: &VirtioBlkDevice) -> u64 {
    let mut flags = ipc::status::READY;
    if device.is_read_only() {
        flags |= ipc::status::READ_ONLY;
    }
    if device.supports_flush() {
        flags |= ipc::status::FLUSH_SUPPORTED;
    }
    // Would return flags in x1
    let _ = flags;
    ipc::response::OK
}

/// Handle READ_SECTOR request (synchronous with shared memory).
fn handle_read_sector(
    device: &mut VirtioBlkDevice,
    tracker: &mut SlotAllocator,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let sector = msg[0];
    let count = msg[1];

    // Validate parameters
    let config = device.config();
    if sector >= config.capacity {
        return ipc::response::ERR_INVALID_SECTOR;
    }
    if count == 0 || count > 8 {
        return ipc::response::ERR_INVALID;
    }

    // Get received capability slots
    // SAFETY: IPC buffer is mapped
    let recv_caps = unsafe { ipc_get_recv_caps() };
    if recv_caps[0] == 0 {
        return ipc::response::ERR_INVALID; // No frame capability received
    }

    let client_frame_slot = recv_caps[0];

    // Allocate a unique slot for this frame
    let frame_slot = tracker.alloc_slot();

    // Map client's frame into our VSpace
    let vaddr = 0x8002_0000;
    if map_frame(ROOT_VSPACE, cptr(client_frame_slot), vaddr, 3, 0).is_err() {
        return ipc::response::ERR_IO;
    }

    // Allocate IOVA from DmaPool
    let data_size = count * 512;
    let data_iova = match dma_pool_alloc(DMA_POOL, data_size, 512) {
        Ok(iova) => iova,
        Err(_) => return ipc::response::ERR_IO,
    };

    // Map frame into IOSpace at allocated IOVA
    if iospace_map_frame(IOSPACE, cptr(client_frame_slot), data_iova, 3).is_err() {
        return ipc::response::ERR_IO;
    }

    // Calculate IOVAs for request header and status
    let iova_base = device.iova_base();
    let header_iova = iova_base + 4096; // After virtqueue structures
    let status_iova = header_iova + 16; // After header

    // Submit to virtqueue
    let desc_head = match device.read_sector(
        sector,
        data_iova,
        data_size as u32,
        header_iova,
        status_iova,
    ) {
        Some(head) => head,
        None => {
            let _ = iospace_unmap_frame(IOSPACE, data_iova);
            return ipc::response::ERR_IO;
        }
    };

    // Wait for completion (synchronous for now)
    // In a real implementation, we'd wait on IRQ_NOTIF notification
    let mut attempts = 0;
    let bytes_written = loop {
        if let Some((head, bytes)) = device.poll_completion()
            && head == desc_head
        {
            device.ack_interrupt();
            break bytes;
        }
        sched_yield();
        attempts += 1;
        if attempts > 10000 {
            // Timeout
            let _ = iospace_unmap_frame(IOSPACE, data_iova);
            device.free_request(desc_head);
            return ipc::response::ERR_IO;
        }
    };

    // Clean up mappings
    let _ = iospace_unmap_frame(IOSPACE, data_iova);
    device.free_request(desc_head);

    // Data is now in client's frame, reply with success
    let _ = frame_slot; // Suppress warning
    ipc::response::OK | ((bytes_written as u64) << 16)
}

/// Handle WRITE_SECTOR request (synchronous with shared memory).
fn handle_write_sector(
    device: &mut VirtioBlkDevice,
    tracker: &mut SlotAllocator,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    if device.is_read_only() {
        return ipc::response::ERR_UNSUPPORTED;
    }

    let sector = msg[0];
    let count = msg[1];

    // Validate parameters
    let config = device.config();
    if sector >= config.capacity {
        return ipc::response::ERR_INVALID_SECTOR;
    }
    if count == 0 || count > 8 {
        return ipc::response::ERR_INVALID;
    }

    // Get received capability slots
    // SAFETY: IPC buffer is mapped
    let recv_caps = unsafe { ipc_get_recv_caps() };
    if recv_caps[0] == 0 {
        return ipc::response::ERR_INVALID; // No frame capability received
    }

    let client_frame_slot = recv_caps[0];

    // Allocate a unique slot for this frame
    let frame_slot = tracker.alloc_slot();

    // Map client's frame into our VSpace
    let vaddr = 0x8002_0000;
    if map_frame(ROOT_VSPACE, cptr(client_frame_slot), vaddr, 3, 0).is_err() {
        return ipc::response::ERR_IO;
    }

    // Allocate IOVA from DmaPool
    let data_size = count * 512;
    let data_iova = match dma_pool_alloc(DMA_POOL, data_size, 512) {
        Ok(iova) => iova,
        Err(_) => return ipc::response::ERR_IO,
    };

    // Map frame into IOSpace at allocated IOVA
    if iospace_map_frame(IOSPACE, cptr(client_frame_slot), data_iova, 3).is_err() {
        return ipc::response::ERR_IO;
    }

    // Calculate IOVAs for request header and status
    let iova_base = device.iova_base();
    let header_iova = iova_base + 4096;
    let status_iova = header_iova + 16;

    // Submit to virtqueue
    let desc_head = match device.write_sector(
        sector,
        data_iova,
        data_size as u32,
        header_iova,
        status_iova,
    ) {
        Some(head) => head,
        None => {
            let _ = iospace_unmap_frame(IOSPACE, data_iova);
            return ipc::response::ERR_IO;
        }
    };

    // Wait for completion (synchronous for now)
    let mut attempts = 0;
    let bytes_written = loop {
        if let Some((head, bytes)) = device.poll_completion()
            && head == desc_head
        {
            device.ack_interrupt();
            break bytes;
        }
        sched_yield();
        attempts += 1;
        if attempts > 10000 {
            // Timeout
            let _ = iospace_unmap_frame(IOSPACE, data_iova);
            device.free_request(desc_head);
            return ipc::response::ERR_IO;
        }
    };

    // Clean up mappings
    let _ = iospace_unmap_frame(IOSPACE, data_iova);
    device.free_request(desc_head);

    let _ = frame_slot; // Suppress warning
    ipc::response::OK | ((bytes_written as u64) << 16)
}

/// Handle FLUSH request.
fn handle_flush(device: &mut VirtioBlkDevice) -> u64 {
    if !device.supports_flush() {
        return ipc::response::ERR_UNSUPPORTED;
    }

    io::puts("[drv-virtio-blk] FLUSH (not fully implemented)\n");

    ipc::response::OK
}

// Panic handler is provided by m6-std
