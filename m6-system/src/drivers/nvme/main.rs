//! NVMe Block Device Driver
//!
//! Userspace driver for NVMe storage devices. Provides sector read/write/flush
//! operations via IPC.
//!
//! # Capabilities received from device-mgr
//!
//! - Slot 10: DeviceFrame for BAR0 MMIO access
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 13: IOSpace for DMA
//! - Slot 14: Notification for IRQ delivery
//! - Slot 16: DMA pool for IOVA allocation
//! - Slots 21+: DMA buffer frames

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod command;
mod controller;
mod ipc;
mod msix;
mod prp;
mod queue;

#[path = "../../io.rs"]
mod io;

use command::{NvmeCommand, NvmeCompletion};
use controller::{IdentifyController, IdentifyNamespace, NvmeController};
use ipc::{DeviceInfo, request, response, status};
use queue::{NvmeCq, NvmeSq};

use m6_syscall::invoke::{
    dma_pool_alloc, iospace_map_frame, iospace_unmap_frame, ipc_get_recv_caps, ipc_set_recv_slots,
    irq_set_handler, map_frame, recv, reply_recv, sched_yield,
};

// -- Capability slot definitions

const CNODE_RADIX: u8 = 10;

#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

const ROOT_VSPACE: u64 = cptr(2);
const DEVICE_FRAME: u64 = cptr(10);
const IRQ_HANDLER: u64 = cptr(11);
const SERVICE_EP: u64 = cptr(12);
const IOSPACE: u64 = cptr(13);
const IRQ_NOTIF: u64 = cptr(14);
const DMA_POOL: u64 = cptr(16);

// DMA buffer frame slots (provided by device-mgr for DMA-capable drivers)
const DMA_BUFFER_START: u64 = 21;
const DMA_BUFFER_COUNT: usize = 8;

/// Get CPtr for DMA buffer frame at index
#[inline]
const fn dma_buffer_frame(index: usize) -> u64 {
    cptr(DMA_BUFFER_START + index as u64)
}

// MSI-X slots (provided by device-mgr for PCIe devices with MSI-X)
#[allow(dead_code)]
// TODO: Import from shared slot constants crate
const MSIX_IRQ_START: u64 = 48;
const MSIX_NOTIF_START: u64 = 48;
const MSIX_MAX_VECTORS: usize = 8;

/// Get CPtr for MSI-X IRQ handler at vector index
#[inline]
#[allow(dead_code)]
const fn msix_irq_handler(vector: usize) -> u64 {
    cptr(MSIX_IRQ_START + vector as u64)
}

/// Get CPtr for MSI-X notification at vector index
#[inline]
const fn msix_notif(vector: usize) -> u64 {
    cptr(MSIX_NOTIF_START + vector as u64)
}

/// Virtual address for MMIO region
const NVME_MMIO_VADDR: u64 = 0x0000_8000_0000;
/// Virtual address for DMA buffers (8 pages = 32KB)
const DMA_BUFFER_VADDR: u64 = 0x0000_8001_0000;
/// Page size for DMA buffers
const PAGE_SIZE: u64 = 4096;
/// Size of each queue (in entries)
const QUEUE_DEPTH: u16 = 64;
/// IRQ badge
const IRQ_BADGE: u64 = 1;
/// First free slot for dynamic allocations
const FIRST_FREE_SLOT: u64 = 100;

/// Slot allocator for dynamic capability allocation
struct SlotAllocator {
    next_free_slot: u64,
}

impl SlotAllocator {
    const fn new() -> Self {
        Self {
            next_free_slot: FIRST_FREE_SLOT,
        }
    }

    fn alloc_slot(&mut self) -> u64 {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }
}

/// DMA buffer allocation state
///
/// Layout (8 x 4KB pages):
/// - Page 0: Admin SQ (64 * 64 = 4096 bytes)
/// - Page 1: Admin CQ (64 * 16 = 1024 bytes) + scratch
/// - Page 2: Identify buffer (4096 bytes)
/// - Page 3: I/O CQ (64 * 16 = 1024 bytes) + scratch
/// - Page 4: I/O SQ (64 * 64 = 4096 bytes)
/// - Page 5: PRP list page for I/O commands
/// - Page 6-7: Data staging buffers
struct DmaBuffers {
    /// Virtual addresses of DMA buffer pages
    vaddrs: [u64; DMA_BUFFER_COUNT],
    /// IOVAs of DMA buffer pages (for device access)
    iovas: [u64; DMA_BUFFER_COUNT],
    /// Number of pages successfully mapped
    count: usize,
}

impl DmaBuffers {
    const fn new() -> Self {
        Self {
            vaddrs: [0; DMA_BUFFER_COUNT],
            iovas: [0; DMA_BUFFER_COUNT],
            count: 0,
        }
    }

    /// Get virtual address of admin SQ
    #[inline]
    fn admin_sq_vaddr(&self) -> *mut NvmeCommand {
        self.vaddrs[0] as *mut NvmeCommand
    }

    /// Get IOVA of admin SQ
    #[inline]
    fn admin_sq_iova(&self) -> u64 {
        self.iovas[0]
    }

    /// Get virtual address of admin CQ
    #[inline]
    fn admin_cq_vaddr(&self) -> *const NvmeCompletion {
        self.vaddrs[1] as *const NvmeCompletion
    }

    /// Get IOVA of admin CQ
    #[inline]
    fn admin_cq_iova(&self) -> u64 {
        self.iovas[1]
    }

    /// Get virtual address of identify buffer
    #[inline]
    fn identify_vaddr(&self) -> *mut u8 {
        self.vaddrs[2] as *mut u8
    }

    /// Get IOVA of identify buffer
    #[inline]
    fn identify_iova(&self) -> u64 {
        self.iovas[2]
    }

    /// Get virtual address of I/O CQ
    #[inline]
    fn io_cq_vaddr(&self) -> *const NvmeCompletion {
        self.vaddrs[3] as *const NvmeCompletion
    }

    /// Get IOVA of I/O CQ
    #[inline]
    fn io_cq_iova(&self) -> u64 {
        self.iovas[3]
    }

    /// Get virtual address of I/O SQ
    #[inline]
    fn io_sq_vaddr(&self) -> *mut NvmeCommand {
        self.vaddrs[4] as *mut NvmeCommand
    }

    /// Get IOVA of I/O SQ
    #[inline]
    fn io_sq_iova(&self) -> u64 {
        self.iovas[4]
    }

    /// Get virtual address of PRP list page
    #[inline]
    #[allow(dead_code)]
    fn prp_list_vaddr(&self) -> *mut u8 {
        self.vaddrs[5] as *mut u8
    }

    /// Get IOVA of PRP list page
    #[inline]
    #[allow(dead_code)]
    fn prp_list_iova(&self) -> u64 {
        self.iovas[5]
    }

    /// Get virtual address of data staging buffer (2 pages)
    #[inline]
    #[allow(dead_code)]
    fn data_vaddr(&self) -> *mut u8 {
        self.vaddrs[6] as *mut u8
    }

    /// Get IOVA of data staging buffer
    #[inline]
    #[allow(dead_code)]
    fn data_iova(&self) -> u64 {
        self.iovas[6]
    }
}

/// NVMe device state
#[allow(dead_code)]
struct NvmeDevice {
    /// Controller instance
    ctrl: NvmeController,
    /// Admin submission queue (for runtime admin commands)
    admin_sq: NvmeSq,
    /// Admin completion queue (for runtime admin commands)
    admin_cq: NvmeCq,
    /// I/O submission queue
    io_sq: Option<NvmeSq>,
    /// I/O completion queue
    io_cq: Option<NvmeCq>,
    /// DMA buffer memory
    dma: DmaBuffers,
    /// Device information
    info: DeviceInfo,
    /// IRQ configuration (for interrupt-driven I/O)
    irq_config: IrqConfig,
    /// Namespace ID
    nsid: u32,
    /// Next command ID for admin queue
    next_admin_cid: u16,
    /// Next command ID for I/O queue
    next_io_cid: u16,
}

/// Map DMA buffer frames to driver's address space and IOSpace.
///
/// Returns a DmaBuffers struct with vaddrs and iovas populated.
fn map_dma_buffers() -> Result<DmaBuffers, &'static str> {
    let mut dma = DmaBuffers::new();

    for i in 0..DMA_BUFFER_COUNT {
        let frame_cap = dma_buffer_frame(i);
        let vaddr = DMA_BUFFER_VADDR + (i as u64) * PAGE_SIZE;

        // Map frame to driver's address space (RW, non-exec)
        if map_frame(ROOT_VSPACE, frame_cap, vaddr, 0b011, 0).is_err() {
            return Err("DMA frame map failed");
        }

        // Allocate IOVA for this page
        let iova = dma_pool_alloc(DMA_POOL, PAGE_SIZE, PAGE_SIZE)
            .map_err(|_| "IOVA allocation failed")?;

        // Map frame to IOSpace for device DMA access (RW)
        if iospace_map_frame(IOSPACE, frame_cap, iova, 0b11).is_err() {
            return Err("IOSpace map failed");
        }

        dma.vaddrs[i] = vaddr;
        dma.iovas[i] = iova;
        dma.count = i + 1;

        // Zero the page
        // SAFETY: We just mapped this memory
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    Ok(dma)
}

/// Entry point for NVMe driver.
///
/// # Safety
///
/// Must be called only once as the driver entry point with valid capability slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_offset: u64) -> ! {
    // Map the DeviceFrame (BAR0) to our address space
    if let Err(e) = map_frame(ROOT_VSPACE, DEVICE_FRAME, NVME_MMIO_VADDR, 0b011, 0) {
        io::puts("[drv-nvme] ERROR: Failed to map MMIO: ");
        io::put_u64(e as u64);
        io::newline();
        halt();
    }

    let device_addr = NVME_MMIO_VADDR + device_offset;

    // Map DMA buffer frames
    let dma = match map_dma_buffers() {
        Ok(dma) => dma,
        Err(e) => {
            io::puts("[drv-nvme] ERROR: ");
            io::puts(e);
            io::newline();
            halt();
        }
    };

    // Create controller instance
    // SAFETY: We just mapped the device at this address
    let mut ctrl = unsafe { NvmeController::new(device_addr as usize) };

    // Initialise controller with admin queues
    if let Err(e) = ctrl.init(dma.admin_sq_iova(), dma.admin_cq_iova(), QUEUE_DEPTH) {
        io::puts("[drv-nvme] ERROR: Controller init failed: ");
        io::puts(e);
        io::newline();
        halt();
    }

    // Create admin queues
    // SAFETY: DMA buffers are properly mapped
    let mut admin_sq =
        unsafe { NvmeSq::new(dma.admin_sq_vaddr(), dma.admin_sq_iova(), QUEUE_DEPTH, 0) };
    let mut admin_cq =
        unsafe { NvmeCq::new(dma.admin_cq_vaddr(), dma.admin_cq_iova(), QUEUE_DEPTH, 0) };

    // Issue Identify Controller command
    let identify_ctrl = match identify_controller(&ctrl, &mut admin_sq, &mut admin_cq, &dma) {
        Some(id) => id,
        None => {
            io::puts("[drv-nvme] ERROR: Identify Controller failed\n");
            halt();
        }
    };

    io::puts("[drv-nvme] Model: ");
    io::puts(identify_ctrl.model_number());
    io::puts(", Serial: ");
    io::puts(identify_ctrl.serial_number());
    io::puts(", FW: ");
    io::puts(identify_ctrl.firmware_revision());
    io::newline();

    // Identify first namespace (NSID=1)
    let nsid = 1u32;
    let identify_ns = match identify_namespace(&ctrl, &mut admin_sq, &mut admin_cq, &dma, nsid) {
        Some(id) => id,
        None => {
            io::puts("[drv-nvme] ERROR: Identify Namespace failed\n");
            halt();
        }
    };

    let block_size = identify_ns.block_size();
    let capacity_blocks = identify_ns.size_blocks();
    let capacity_mb = (capacity_blocks * block_size as u64) / (1024 * 1024);

    io::puts("[drv-nvme] Namespace 1: ");
    io::put_u64(capacity_blocks);
    io::puts(" blocks (");
    io::put_u64(capacity_mb);
    io::puts(" MiB), block size ");
    io::put_u64(block_size as u64);
    io::puts(" bytes\n");

    // Build device info
    let info = DeviceInfo {
        capacity_blocks,
        block_size: block_size as u32,
        max_transfer_blocks: identify_ctrl
            .max_transfer_size(ctrl.page_size())
            .map(|s| (s / block_size) as u32)
            .unwrap_or(256), // Default to 256 blocks if no limit
        optimal_alignment: 1,
    };

    // Set up IRQ handling
    let irq_config = setup_irq();

    // Create I/O queues via admin commands
    let (io_sq, io_cq) = match create_io_queues(&ctrl, &mut admin_sq, &mut admin_cq, &dma) {
        Some(queues) => queues,
        None => {
            io::puts("[drv-nvme] ERROR: Failed to create I/O queues\n");
            halt();
        }
    };

    // Create device state
    let mut device = NvmeDevice {
        ctrl,
        admin_sq,
        admin_cq,
        io_sq: Some(io_sq),
        io_cq: Some(io_cq),
        dma,
        info,
        irq_config,
        nsid,
        next_admin_cid: 0,
        next_io_cid: 0,
    };

    // Enter service loop
    service_loop(&mut device);
}

/// Halt the driver on fatal error.
fn halt() -> ! {
    loop {
        sched_yield();
    }
}

/// Maximum command completion timeout (iterations)
const CMD_TIMEOUT: usize = 100_000;

/// Submit an admin command and wait for completion.
///
/// Returns the completion entry if successful.
fn submit_admin_cmd(
    ctrl: &NvmeController,
    sq: &mut NvmeSq,
    cq: &mut NvmeCq,
    cmd: NvmeCommand,
) -> Option<NvmeCompletion> {
    // Submit the command
    let cid = sq.submit(cmd)?;
    sq.ring_doorbell(ctrl);

    // Poll for completion
    for _ in 0..CMD_TIMEOUT {
        if cq.has_completion() {
            let completion = cq.pop()?;
            cq.ring_doorbell(ctrl);

            // Check if this is our command
            if completion.cid == cid {
                if completion.is_success() {
                    return Some(completion);
                } else {
                    io::puts("[drv-nvme] Admin command failed: SCT=");
                    io::put_u64(completion.status_code_type() as u64);
                    io::puts(" SC=");
                    io::put_u64(completion.status_code() as u64);
                    io::newline();
                    return None;
                }
            }
        }
        core::hint::spin_loop();
    }

    io::puts("[drv-nvme] Admin command timeout (CID=");
    io::put_u64(cid as u64);
    io::puts(")\n");
    None
}

/// Identify Controller command.
///
/// Submits an Identify Controller admin command and returns the parsed data.
fn identify_controller(
    ctrl: &NvmeController,
    sq: &mut NvmeSq,
    cq: &mut NvmeCq,
    dma: &DmaBuffers,
) -> Option<IdentifyController> {
    // Build Identify Controller command
    let cmd = NvmeCommand::identify_controller(0, dma.identify_iova());

    // Submit and wait
    submit_admin_cmd(ctrl, sq, cq, cmd)?;

    // Copy data from DMA buffer
    // SAFETY: identify buffer is valid and properly mapped
    let data =
        unsafe { core::ptr::read_volatile(dma.identify_vaddr() as *const IdentifyController) };

    Some(data)
}

/// Identify Namespace command.
///
/// Submits an Identify Namespace admin command and returns the parsed data.
fn identify_namespace(
    ctrl: &NvmeController,
    sq: &mut NvmeSq,
    cq: &mut NvmeCq,
    dma: &DmaBuffers,
    nsid: u32,
) -> Option<IdentifyNamespace> {
    // Build Identify Namespace command
    let cmd = NvmeCommand::identify_namespace(0, nsid, dma.identify_iova());

    // Submit and wait
    submit_admin_cmd(ctrl, sq, cq, cmd)?;

    // Copy data from DMA buffer
    // SAFETY: identify buffer is valid and properly mapped
    let data =
        unsafe { core::ptr::read_volatile(dma.identify_vaddr() as *const IdentifyNamespace) };

    Some(data)
}

/// Create I/O queue pair (QID=1).
///
/// Creates an I/O completion queue and submission queue via admin commands.
fn create_io_queues(
    ctrl: &NvmeController,
    admin_sq: &mut NvmeSq,
    admin_cq: &mut NvmeCq,
    dma: &DmaBuffers,
) -> Option<(NvmeSq, NvmeCq)> {
    // Create I/O Completion Queue (QID=1)
    // - Uses interrupt vector 0 (or 1 if MSI-X has multiple vectors)
    // - Interrupts enabled
    let cq_cmd = NvmeCommand::create_io_cq(
        0,                // CID
        1,                // QID
        dma.io_cq_iova(), // PRP1
        QUEUE_DEPTH,      // Queue size
        0,                // Interrupt vector
        true,             // Interrupts enabled
    );

    submit_admin_cmd(ctrl, admin_sq, admin_cq, cq_cmd)?;

    // Create I/O Submission Queue (QID=1, using CQ 1)
    let sq_cmd = NvmeCommand::create_io_sq(
        0,                // CID
        1,                // QID
        dma.io_sq_iova(), // PRP1
        QUEUE_DEPTH,      // Queue size
        1,                // Associated CQ ID
    );

    submit_admin_cmd(ctrl, admin_sq, admin_cq, sq_cmd)?;

    // Create queue objects
    // SAFETY: DMA buffers are properly mapped
    let io_cq = unsafe { NvmeCq::new(dma.io_cq_vaddr(), dma.io_cq_iova(), QUEUE_DEPTH, 1) };
    let io_sq = unsafe { NvmeSq::new(dma.io_sq_vaddr(), dma.io_sq_iova(), QUEUE_DEPTH, 1) };

    Some((io_sq, io_cq))
}

/// IRQ configuration result
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct IrqConfig {
    /// Whether interrupts are configured
    enabled: bool,
    /// Whether MSI-X is being used (vs legacy)
    msix: bool,
    /// Number of MSI-X vectors available (0 if legacy)
    msix_vectors: usize,
    /// Notification to wait on for admin queue interrupts
    admin_notif: u64,
}

impl IrqConfig {
    const fn disabled() -> Self {
        Self {
            enabled: false,
            msix: false,
            msix_vectors: 0,
            admin_notif: IRQ_NOTIF,
        }
    }
}

/// Set up IRQ handling
///
/// Tries MSI-X first (vectors 0+), falls back to legacy IRQ.
fn setup_irq() -> IrqConfig {
    // First try MSI-X - device-mgr puts vectors in slots 40-47 (IRQ) and 48-55 (notif)
    // The IRQ handlers are already bound to notifications by device-mgr

    // Check if MSI-X vector 0 notification exists by trying to use it
    // device-mgr binds the IRQ handler to notification during setup, so we just need to check
    // if the notification cap exists
    use m6_syscall::invoke::poll;

    // Try polling the MSI-X notification for admin queue (vector 0)
    // If the cap doesn't exist, poll will fail immediately
    let admin_msix_notif = msix_notif(0);

    match poll(admin_msix_notif) {
        Ok(_) | Err(m6_syscall::error::SyscallError::WouldBlock) => {
            // Count available vectors by checking slots
            let mut msix_vectors = 0;
            for i in 0..MSIX_MAX_VECTORS {
                match poll(msix_notif(i)) {
                    Ok(_) | Err(m6_syscall::error::SyscallError::WouldBlock) => {
                        msix_vectors = i + 1;
                    }
                    _ => break,
                }
            }

            return IrqConfig {
                enabled: true,
                msix: true,
                msix_vectors,
                admin_notif: admin_msix_notif,
            };
        }
        Err(_) => {
            // MSI-X not available, fall back to legacy
        }
    }

    // Fall back to legacy IRQ
    match irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE) {
        Ok(_) => IrqConfig {
            enabled: true,
            msix: false,
            msix_vectors: 0,
            admin_notif: IRQ_NOTIF,
        },
        Err(_) => IrqConfig::disabled(),
    }
}

/// Main service loop
fn service_loop(device: &mut NvmeDevice) -> ! {
    let mut tracker = SlotAllocator::new();

    // Set up IPC receive slots
    let recv_slot = tracker.alloc_slot();
    // SAFETY: IPC buffer is mapped
    unsafe {
        ipc_set_recv_slots(&[recv_slot]);
    }

    // Receive first message
    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                let response = handle_request(
                    device,
                    &mut tracker,
                    ipc_result.badge,
                    ipc_result.label,
                    &ipc_result.msg,
                );

                result = reply_recv(SERVICE_EP, response, 0, 0, 0);
            }
            Err(_) => {
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(
    device: &mut NvmeDevice,
    tracker: &mut SlotAllocator,
    badge: u64,
    label: u64,
    msg: &[u64; 4],
) -> u64 {
    match label & 0xFFFF {
        request::GET_INFO => handle_get_info(device),
        request::GET_STATUS => handle_get_status(device),
        request::READ_SECTOR => handle_read_sector(device, tracker, badge, msg),
        request::WRITE_SECTOR => handle_write_sector(device, tracker, badge, msg),
        request::FLUSH => handle_flush(device),
        request::DISCARD => response::ERR_UNSUPPORTED,
        _ => response::ERR_INVALID,
    }
}

/// Handle GET_INFO request
fn handle_get_info(device: &NvmeDevice) -> u64 {
    // In a real implementation, we'd pack info into reply registers
    let _ = device.info.pack();
    response::OK
}

/// Handle GET_STATUS request
fn handle_get_status(_device: &NvmeDevice) -> u64 {
    let mut flags = status::READY;
    flags |= status::FLUSH_SUPPORTED;
    // Check if volatile write cache is enabled
    // flags |= status::VOLATILE_WRITE_CACHE;
    let _ = flags;
    response::OK
}

/// Submit an I/O command and wait for completion.
fn submit_io_cmd(device: &mut NvmeDevice, cmd: NvmeCommand) -> Option<NvmeCompletion> {
    let io_sq = device.io_sq.as_mut()?;
    let io_cq = device.io_cq.as_mut()?;

    // Submit the command
    let cid = io_sq.submit(cmd)?;
    io_sq.ring_doorbell(&device.ctrl);

    // Poll for completion
    for _ in 0..CMD_TIMEOUT {
        if io_cq.has_completion() {
            let completion = io_cq.pop()?;
            io_cq.ring_doorbell(&device.ctrl);

            // Check if this is our command
            if completion.cid == cid {
                if completion.is_success() {
                    return Some(completion);
                } else {
                    io::puts("[drv-nvme] I/O command failed: SCT=");
                    io::put_u64(completion.status_code_type() as u64);
                    io::puts(" SC=");
                    io::put_u64(completion.status_code() as u64);
                    io::newline();
                    return None;
                }
            }
        }
        core::hint::spin_loop();
    }

    io::puts("[drv-nvme] I/O command timeout (CID=");
    io::put_u64(cid as u64);
    io::puts(")\n");
    None
}

/// Handle READ_SECTOR request.
///
/// Reads sectors from the NVMe device into the client's buffer.
fn handle_read_sector(
    device: &mut NvmeDevice,
    _tracker: &mut SlotAllocator,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let lba = msg[0];
    let count = msg[1] as u16;

    // Validate
    if lba + count as u64 > device.info.capacity_blocks {
        return response::ERR_INVALID_SECTOR;
    }
    if count == 0 || count > 8 {
        return response::ERR_INVALID;
    }

    // Check we have I/O queues
    if device.io_sq.is_none() || device.io_cq.is_none() {
        io::puts("[drv-nvme] ERROR: I/O queues not initialised\n");
        return response::ERR_IO;
    }

    // Get received frame capability
    // SAFETY: IPC buffer is mapped
    let recv_caps = unsafe { ipc_get_recv_caps() };
    if recv_caps[0] == 0 {
        return response::ERR_INVALID;
    }

    let client_frame_slot = recv_caps[0];

    // Allocate IOVA for data
    let data_size = (count as u64) * (device.info.block_size as u64);
    let data_iova = match dma_pool_alloc(DMA_POOL, data_size, PAGE_SIZE) {
        Ok(iova) => iova,
        Err(_) => return response::ERR_IO,
    };

    // Map client's frame into IOSpace for device DMA access
    if iospace_map_frame(IOSPACE, cptr(client_frame_slot), data_iova, 0b11).is_err() {
        return response::ERR_IO;
    }

    // Build and submit NVMe Read command
    // PRP2 is only needed if transfer spans multiple pages
    let prp2 = if data_size > PAGE_SIZE {
        data_iova + PAGE_SIZE
    } else {
        0
    };

    let cmd = NvmeCommand::read(0, device.nsid, lba, count, data_iova, prp2);

    let result = submit_io_cmd(device, cmd);

    // Clean up - unmap from IOSpace
    let _ = iospace_unmap_frame(IOSPACE, data_iova);

    if result.is_some() {
        response::OK | (data_size << 16)
    } else {
        response::ERR_IO
    }
}

/// Handle WRITE_SECTOR request.
///
/// Writes sectors from the client's buffer to the NVMe device.
fn handle_write_sector(
    device: &mut NvmeDevice,
    _tracker: &mut SlotAllocator,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let lba = msg[0];
    let count = msg[1] as u16;

    // Validate
    if lba + count as u64 > device.info.capacity_blocks {
        return response::ERR_INVALID_SECTOR;
    }
    if count == 0 || count > 8 {
        return response::ERR_INVALID;
    }

    // Check we have I/O queues
    if device.io_sq.is_none() || device.io_cq.is_none() {
        io::puts("[drv-nvme] ERROR: I/O queues not initialised\n");
        return response::ERR_IO;
    }

    // Get received frame capability
    // SAFETY: IPC buffer is mapped
    let recv_caps = unsafe { ipc_get_recv_caps() };
    if recv_caps[0] == 0 {
        return response::ERR_INVALID;
    }

    let client_frame_slot = recv_caps[0];

    // Allocate IOVA for data
    let data_size = (count as u64) * (device.info.block_size as u64);
    let data_iova = match dma_pool_alloc(DMA_POOL, data_size, PAGE_SIZE) {
        Ok(iova) => iova,
        Err(_) => return response::ERR_IO,
    };

    // Map client's frame into IOSpace for device DMA access
    if iospace_map_frame(IOSPACE, cptr(client_frame_slot), data_iova, 0b11).is_err() {
        return response::ERR_IO;
    }

    // Build and submit NVMe Write command
    let prp2 = if data_size > PAGE_SIZE {
        data_iova + PAGE_SIZE
    } else {
        0
    };

    let cmd = NvmeCommand::write(0, device.nsid, lba, count, data_iova, prp2);

    let result = submit_io_cmd(device, cmd);

    // Clean up - unmap from IOSpace
    let _ = iospace_unmap_frame(IOSPACE, data_iova);

    if result.is_some() {
        response::OK | (data_size << 16)
    } else {
        response::ERR_IO
    }
}

/// Handle FLUSH request.
///
/// Flushes the volatile write cache to non-volatile storage.
fn handle_flush(device: &mut NvmeDevice) -> u64 {
    // Check we have I/O queues
    if device.io_sq.is_none() || device.io_cq.is_none() {
        io::puts("[drv-nvme] ERROR: I/O queues not initialised\n");
        return response::ERR_IO;
    }

    // Build and submit NVMe Flush command
    let cmd = NvmeCommand::flush(0, device.nsid);

    if submit_io_cmd(device, cmd).is_some() {
        response::OK
    } else {
        response::ERR_IO
    }
}
