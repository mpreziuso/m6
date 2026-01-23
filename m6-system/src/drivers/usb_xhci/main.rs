//! USB xHCI Host Controller Driver
//!
//! Userspace driver for xHCI USB host controllers. Provides USB host
//! functionality via IPC for both QEMU virt (PCIe xHCI) and platform
//! xHCI controllers.
//!
//! # Capabilities received from device-mgr
//!
//! - Slot 10: DeviceFrame for xHCI MMIO access
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 13: IOSpace for DMA
//! - Slot 14: Notification for IRQ delivery
//! - Slot 16: DMA pool for IOVA allocation
//! - Slots 21+: DMA buffer frames
//! - Slots 40+: MSI-X IRQ handlers (for PCIe)
//! - Slots 48+: MSI-X notifications (for PCIe)

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(iterator_try_collect)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod executor;
mod hal;
mod ipc;

#[path = "../../io.rs"]
mod io;

use core::ptr::NonNull;

use core::time::Duration;

use crab_usb::{impl_trait, DeviceInfo, EventHandler, Kernel, USBHost};

use m6_syscall::invoke::{
    dma_pool_alloc, iospace_map_frame, irq_set_handler, map_frame, poll, recv, reply_recv,
    sched_yield,
};

use ipc::{request, response, status, ControllerInfo};

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
const MSIX_NOTIF_START: u64 = 48;
const MSIX_MAX_VECTORS: usize = 8;

/// Get CPtr for MSI-X notification at vector index
#[inline]
const fn msix_notif(vector: usize) -> u64 {
    cptr(MSIX_NOTIF_START + vector as u64)
}

/// Virtual address for MMIO region
const XHCI_MMIO_VADDR: u64 = 0x0000_8000_0000;
/// Virtual address for DMA buffers (8 pages = 32KB)
const DMA_BUFFER_VADDR: u64 = 0x0000_8001_0000;
/// Page size for DMA buffers
const PAGE_SIZE: u64 = 4096;
/// IRQ badge
const IRQ_BADGE: u64 = 1;

/// DMA buffer allocation state
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

    /// Get the base virtual address of the DMA region
    fn base_vaddr(&self) -> u64 {
        self.vaddrs[0]
    }

    /// Get the base IOVA of the DMA region
    fn base_iova(&self) -> u64 {
        self.iovas[0]
    }

    /// Get total size of mapped DMA region
    fn total_size(&self) -> usize {
        self.count * PAGE_SIZE as usize
    }
}

/// Map DMA buffer frames to driver's address space and IOSpace.
fn map_dma_buffers() -> Result<DmaBuffers, &'static str> {
    let mut dma = DmaBuffers::new();

    // IOVA base for DMA buffers (from DMA pool)
    const IOVA_BASE: u64 = 0x1000_0000; // 256MB

    for i in 0..DMA_BUFFER_COUNT {
        let frame_cap = dma_buffer_frame(i);
        let vaddr = DMA_BUFFER_VADDR + (i as u64) * PAGE_SIZE;

        // Map frame to driver's address space (RW, non-exec)
        if let Err(e) = map_frame(ROOT_VSPACE, frame_cap, vaddr, 0b011, 0) {
            io::puts("[drv-usb-xhci] ERROR: Failed to map DMA frame ");
            io::put_u64(i as u64);
            io::puts(": ");
            io::put_u64(e as u64);
            io::newline();
            return Err("DMA frame map failed");
        }

        // Allocate IOVA for this page
        let iova = match dma_pool_alloc(DMA_POOL, PAGE_SIZE, PAGE_SIZE) {
            Ok(iova) => iova,
            Err(e) => {
                io::puts("[drv-usb-xhci] ERROR: Failed to allocate IOVA for frame ");
                io::put_u64(i as u64);
                io::puts(": ");
                io::put_u64(e as u64);
                io::newline();
                return Err("IOVA allocation failed");
            }
        };

        // Map frame to IOSpace for device DMA access (RW)
        if let Err(e) = iospace_map_frame(IOSPACE, frame_cap, iova, 0b11) {
            io::puts("[drv-usb-xhci] ERROR: Failed to map frame to IOSpace ");
            io::put_u64(i as u64);
            io::puts(": ");
            io::put_u64(e as u64);
            io::newline();
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

    io::puts("[drv-usb-xhci] Mapped ");
    io::put_u64(dma.count as u64);
    io::puts(" DMA buffer pages\n");

    Ok(dma)
}

// -- crab-usb Kernel trait implementation

struct M6Kernel;

impl_trait! {
    impl Kernel for M6Kernel {
        fn page_size() -> usize {
            PAGE_SIZE as usize
        }

        fn delay(duration: Duration) {
            // Use kernel sleep syscall for delays
            let nanos = duration.as_nanos() as u64;
            let _ = m6_syscall::invoke::tcb_sleep(nanos);
        }
    }
}

/// xHCI device state
struct XhciDevice {
    /// USB host instance from crab-usb
    host: USBHost,
    /// Event handler for interrupt processing
    event_handler: Option<EventHandler>,
    /// DMA buffer memory
    dma: DmaBuffers,
    /// Controller information
    info: ControllerInfo,
    /// Whether controller is initialised
    initialised: bool,
    /// Detected devices
    devices: alloc::vec::Vec<DeviceInfo>,
}

/// IRQ configuration result
#[derive(Clone, Copy)]
struct IrqConfig {
    /// Whether interrupts are configured
    enabled: bool,
    /// Whether MSI-X is being used (vs legacy)
    msix: bool,
    /// Notification to wait on
    notif: u64,
}

impl IrqConfig {
    const fn disabled() -> Self {
        Self {
            enabled: false,
            msix: false,
            notif: IRQ_NOTIF,
        }
    }
}

/// Set up IRQ handling
fn setup_irq() -> IrqConfig {
    // First try MSI-X notification for vector 0
    let msix_notif = msix_notif(0);

    match poll(msix_notif) {
        Ok(_) | Err(m6_syscall::error::SyscallError::WouldBlock) => {
            io::puts("[drv-usb-xhci] Using MSI-X interrupts (vector 0)\n");
            return IrqConfig {
                enabled: true,
                msix: true,
                notif: msix_notif,
            };
        }
        Err(_) => {
            io::puts("[drv-usb-xhci] MSI-X not available, trying legacy IRQ\n");
        }
    }

    // Fall back to legacy IRQ
    match irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE) {
        Ok(_) => {
            io::puts("[drv-usb-xhci] Using legacy IRQ\n");
            IrqConfig {
                enabled: true,
                msix: false,
                notif: IRQ_NOTIF,
            }
        }
        Err(e) => {
            io::puts("[drv-usb-xhci] irq_set_handler failed: ");
            io::put_u64(e as u64);
            io::newline();
            IrqConfig::disabled()
        }
    }
}

/// Entry point for xHCI driver.
///
/// # Arguments
///
/// * `device_phys_addr` - Physical address of the device (from DTB reg property or PCIe BAR)
///
/// # Safety
///
/// Must be called only once as the driver entry point with valid capability slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_phys_addr: u64) -> ! {
    io::puts("\n\x1b[36m[drv-usb-xhci] Starting xHCI USB driver\x1b[0m\n");
    io::puts("[drv-usb-xhci] Device phys addr: ");
    io::put_hex(device_phys_addr);
    io::newline();

    // Map the DeviceFrame (xHCI MMIO) to our address space
    match map_frame(ROOT_VSPACE, DEVICE_FRAME, XHCI_MMIO_VADDR, 0b011, 0) {
        Ok(_) => {
            io::puts("[drv-usb-xhci] Mapped MMIO at ");
            io::put_hex(XHCI_MMIO_VADDR);
            io::newline();
        }
        Err(e) => {
            io::puts("[drv-usb-xhci] ERROR: Failed to map MMIO: ");
            io::put_u64(e as u64);
            io::newline();
            halt();
        }
    }

    // Compute page offset for non-page-aligned devices (e.g., PCIe BARs)
    let page_offset = device_phys_addr & 0xFFF;
    let device_addr = XHCI_MMIO_VADDR + page_offset;
    io::puts("[drv-usb-xhci] Device at ");
    io::put_hex(device_addr);
    io::puts(" (page offset ");
    io::put_hex(page_offset);
    io::puts(")\n");

    // Map DMA buffer frames
    let dma = match map_dma_buffers() {
        Ok(dma) => dma,
        Err(e) => {
            io::puts("[drv-usb-xhci] ERROR: ");
            io::puts(e);
            io::newline();
            halt();
        }
    };

    // Initialise the DMA HAL
    // SAFETY: Called once during init
    unsafe {
        hal::init_dma_hal(dma.base_vaddr(), dma.base_iova(), dma.total_size());
        hal::register_osal();
    }

    io::puts("[drv-usb-xhci] DMA HAL initialised\n");

    // Set up IRQ handling
    let _irq_config = setup_irq();

    // Create xHCI host instance
    let mmio = NonNull::new(device_addr as *mut u8).expect("MMIO address is null");
    let dma_mask: u64 = 0xFFFF_FFFF_FFFF; // 48-bit DMA

    io::puts("[drv-usb-xhci] Creating xHCI host...\n");

    let host = match USBHost::new_xhci(mmio, dma_mask as usize) {
        Ok(h) => h,
        Err(e) => {
            io::puts("[drv-usb-xhci] ERROR: Failed to create xHCI host: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
            halt();
        }
    };

    io::puts("[drv-usb-xhci] xHCI host created\n");

    // Create device state
    let mut device = XhciDevice {
        host,
        event_handler: None,
        dma,
        info: ControllerInfo::default(),
        initialised: false,
        devices: alloc::vec::Vec::new(),
    };

    // Initialise the controller
    io::puts("[drv-usb-xhci] Initialising controller...\n");

    let init_result = executor::block_on(device.host.init());
    if let Err(e) = init_result {
        io::puts("[drv-usb-xhci] ERROR: Controller init failed: ");
        io::puts(core::any::type_name_of_val(&e));
        io::newline();
        halt();
    }

    io::puts("[drv-usb-xhci] Controller initialised\n");

    // Create event handler for interrupt processing
    device.event_handler = Some(device.host.create_event_handler());

    // Probe for connected devices
    io::puts("[drv-usb-xhci] Probing for devices...\n");

    match executor::block_on(device.host.probe_devices()) {
        Ok(devices) => {
            io::puts("[drv-usb-xhci] Found ");
            io::put_u64(devices.len() as u64);
            io::puts(" device(s)\n");
            device.devices = devices;
        }
        Err(e) => {
            io::puts("[drv-usb-xhci] ERROR: Device probe failed: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
            // Continue anyway - devices may be hot-plugged later
        }
    }

    device.initialised = true;
    io::puts("[drv-usb-xhci] Entering service loop\n");

    // Enter service loop
    service_loop(&mut device);
}

/// Halt the driver on fatal error.
fn halt() -> ! {
    loop {
        sched_yield();
    }
}

/// Main service loop
fn service_loop(device: &mut XhciDevice) -> ! {
    // Receive first message
    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                let response = handle_request(device, ipc_result.label, &ipc_result.msg);
                result = reply_recv(SERVICE_EP, response, 0, 0, 0);
            }
            Err(err) => {
                io::puts("[drv-usb-xhci] IPC error: ");
                io::put_u64(err as u64);
                io::newline();
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(device: &mut XhciDevice, label: u64, msg: &[u64; 4]) -> u64 {
    match label & 0xFFFF {
        request::GET_INFO => handle_get_info(device),
        request::GET_STATUS => handle_get_status(device),
        request::GET_PORT_COUNT => handle_get_port_count(device),
        request::GET_PORT_STATUS => handle_get_port_status(device, msg[0] as u8),
        request::LIST_DEVICES => handle_list_devices(device),
        request::GET_DEVICE_DESCRIPTOR => handle_get_device_descriptor(device, msg[0] as u8),
        _ => response::ERR_UNSUPPORTED,
    }
}

/// Handle GET_INFO request
fn handle_get_info(device: &XhciDevice) -> u64 {
    let _ = device.info.pack();
    response::OK
}

/// Handle GET_STATUS request
fn handle_get_status(device: &XhciDevice) -> u64 {
    let mut flags = 0u64;
    if device.initialised {
        flags |= status::READY;
        flags |= status::USB2_SUPPORTED;
        flags |= status::USB3_SUPPORTED;
        flags |= status::PORTS_POWERED;
    }
    flags
}

/// Handle GET_PORT_COUNT request
///
/// # Status
///
/// Returns hardcoded port count. Proper implementation requires querying
/// xHCI HCSPARAMS1.MaxPorts via crab-usb API.
/// Handle GET_PORT_COUNT request
///
/// # Limitation
///
/// Cannot be implemented with current crab-usb API. The library doesn't expose
/// xHCI HCSPARAMS1 register or port count query method.
///
/// Returns hardcoded 4 ports as best-effort approximation.
fn handle_get_port_count(_device: &XhciDevice) -> u64 {
    response::OK | (4 << 16)
}

/// Handle GET_PORT_STATUS request
///
/// # Limitation
///
/// Cannot be implemented with current crab-usb API. The library doesn't expose
/// xHCI PORTSC registers or port status query methods. Would require:
/// - Extension to crab-usb's public API, OR
/// - Direct unsafe register access (breaks abstraction)
///
/// Device enumeration works via `LIST_DEVICES` and `GET_DEVICE_DESCRIPTOR`.
fn handle_get_port_status(_device: &XhciDevice, port: u8) -> u64 {
    if port == 0 || port > 16 {
        return response::ERR_INVALID_PORT;
    }
    response::ERR_UNSUPPORTED
}

/// Handle LIST_DEVICES request
fn handle_list_devices(device: &XhciDevice) -> u64 {
    let count = device.devices.len() as u64;
    response::OK | (count << 16)
}

/// Handle GET_DEVICE_DESCRIPTOR request
///
/// # Limitation
///
/// Cannot be fully implemented with current crab-usb API. The library's `DeviceInfo`
/// type doesn't expose device address or descriptor fields publicly.
///
/// # Workaround
///
/// Returns OK with device count if any devices are present. Full descriptor support
/// would require either:
/// - Extension to crab-usb's public API, OR
/// - Maintaining separate device descriptor cache in driver
///
/// Device presence can be checked via `LIST_DEVICES`.
fn handle_get_device_descriptor(device: &XhciDevice, addr: u8) -> u64 {
    // Check if we have any devices at all
    if addr == 0 || addr as usize > device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    // We have device(s) but can't access descriptor fields from crab-usb DeviceInfo
    // Return OK to indicate device exists, but actual descriptor info requires API extension
    response::OK | ((device.devices.len() as u64) << 16)
}
