//! USB xHCI Host Controller Driver
//!
//! Userspace driver for xHCI USB host controllers. Provides USB host
//! functionality via IPC for QEMU virt (PCIe xHCI) and platform xHCI controllers.
//!
//! This driver uses direct xHCI register access - firmware (UEFI) is expected
//! to have already initialised the controller.
//!
//! # Capabilities received from device-mgr
//!
//! - Slot 10: DeviceFrame for xHCI MMIO access
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 14: Notification for IRQ delivery
//! - Slots 21-36: DMA buffer frames (16 pages = 64KB)

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod ipc;
mod xhci;

use m6_syscall::invoke::{
    frame_get_phys, irq_set_handler, map_frame, poll, recv, reply_recv, sched_yield,
};

use ipc::{request, response, status};
use xhci::{DeviceDescriptor, PortSpeed, PortStatus, XhciController, XhciDmaRegion};

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
const IRQ_NOTIF: u64 = cptr(14);

// MSI-X slots (provided by device-mgr for PCIe devices with MSI-X)
const MSIX_NOTIF_START: u64 = 48;

/// Get CPtr for MSI-X notification at vector index
#[inline]
const fn msix_notif(vector: usize) -> u64 {
    cptr(MSIX_NOTIF_START + vector as u64)
}

/// Virtual address for MMIO region
const XHCI_MMIO_VADDR: u64 = 0x0000_8000_0000;
/// IRQ badge
const IRQ_BADGE: u64 = 1;

// -- DMA Buffer slots (provided by device-mgr for DMA-capable drivers)

/// First DMA buffer frame slot
const DMA_BUFFER_START: u64 = 21;
/// Number of DMA buffer frames (16 pages = 64KB)
const DMA_BUFFER_COUNT: usize = 16;
/// Virtual address for DMA buffer region
const DMA_BUFFER_VADDR: u64 = 0x0000_8001_0000;

/// Get CPtr for DMA buffer frame at index
#[inline]
const fn dma_buffer_cptr(index: usize) -> u64 {
    cptr(DMA_BUFFER_START + index as u64)
}

/// xHCI device state
struct XhciDevice {
    /// Direct xHCI controller for register access
    xhci_ctrl: XhciController,
    /// Cached port status
    port_status_cache: alloc::vec::Vec<PortStatus>,
    /// Enumerated USB devices
    devices: alloc::vec::Vec<UsbDeviceInfo>,
    /// Whether device enumeration has been performed
    devices_enumerated: bool,
    /// Whether xHCI has been initialised with DMA
    xhci_initialized: bool,
    /// DMA region IOVA (physical address for device access)
    dma_iova: u64,
}

/// Basic USB device info
#[derive(Clone)]
struct UsbDeviceInfo {
    slot_id: u8,
    port: u8,
    speed: PortSpeed,
    interfaces: alloc::vec::Vec<UsbInterfaceInfo>,
}

/// Basic USB interface info
#[derive(Clone)]
struct UsbInterfaceInfo {
    interface_number: u8,
    class: u8,
    subclass: u8,
    protocol: u8,
    endpoint_address: u8,
    endpoint_interval: u8,
}

/// Set up IRQ handling
fn setup_irq() {
    // First try MSI-X notification for vector 0
    let msix_notif_cap = msix_notif(0);

    match poll(msix_notif_cap) {
        Ok(_) | Err(m6_syscall::error::SyscallError::WouldBlock) => {
            return;
        }
        Err(_) => {}
    }

    // Fall back to legacy IRQ
    let _ = irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE);
}

/// Entry point for xHCI driver.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_phys_addr: u64) -> ! {
    // Initialise heap allocator
    rt::init_allocator();

    // Map the DeviceFrame (xHCI MMIO) to our address space
    if let Err(_) = map_frame(ROOT_VSPACE, DEVICE_FRAME, XHCI_MMIO_VADDR, 0b011, 0) {
        halt();
    }

    // Compute page offset for non-page-aligned devices (e.g., PCIe BARs)
    let page_offset = device_phys_addr & 0xFFF;
    let device_addr = XHCI_MMIO_VADDR + page_offset;

    // Set up IRQ handling
    setup_irq();

    // Create xHCI controller for direct register access
    // SAFETY: device_addr is mapped
    let mut xhci_ctrl = unsafe { XhciController::new(device_addr) };

    // Get physical address of first DMA buffer frame for IOVA
    let dma_iova: u64 = match frame_get_phys(dma_buffer_cptr(0)) {
        Ok(phys) => phys as u64,
        Err(_) => 0,
    };

    // Initialise xHCI with DMA buffers (if available)
    let xhci_initialized = if dma_iova != 0 {
        let dma = XhciDmaRegion {
            vaddr: DMA_BUFFER_VADDR,
            iova: dma_iova,
            size: DMA_BUFFER_COUNT * 4096, // 64KB
        };

        // SAFETY: DMA region is mapped by device-mgr
        match unsafe { xhci_ctrl.initialize(&dma) } {
            Ok(()) => true,
            Err(_) => false,
        }
    } else {
        false
    };

    // Scan ports using direct register access
    let port_status_cache = xhci_ctrl.scan_ports();

    let mut device = XhciDevice {
        xhci_ctrl,
        port_status_cache,
        devices: alloc::vec::Vec::new(),
        devices_enumerated: false,
        xhci_initialized,
        dma_iova,
    };

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
    let mut result = recv(SERVICE_EP);
    let mut poll_counter = 0u32;

    loop {
        match result {
            Ok(ipc_result) => {
                let resp = handle_request(device, ipc_result.label, &ipc_result.msg);
                result = reply_recv(SERVICE_EP, resp.label, resp.msg[0], resp.msg[1], resp.msg[2]);
            }
            Err(err) => {
                // Timeout or error - do background work
                if poll_counter % 100 == 0 {
                    poll_interrupt_transfers(device);
                }
                poll_counter = poll_counter.wrapping_add(1);

                let _ = err;
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Poll all active interrupt transfers for new data
fn poll_interrupt_transfers(device: &mut XhciDevice) {
    if !device.xhci_initialized {
        return;
    }

    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    for transfer in transfers.iter_mut() {
        if !transfer.active || !transfer.hw_configured {
            continue;
        }

        // Poll for data from hardware
        if let Some((data, len)) = device.xhci_ctrl.poll_interrupt_data(
            transfer.slot_id,
            transfer.ep_idx as usize,
        ) {
            let copy_len = len.min(8);
            transfer.buffer[..copy_len].copy_from_slice(&data[..copy_len]);
            transfer.buffer_len = copy_len as u8;
            transfer.has_pending_data = true;

            // Re-queue the transfer
            let _ = device.xhci_ctrl.queue_interrupt_transfer(
                transfer.slot_id,
                transfer.ep_idx as usize,
            );
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(device: &mut XhciDevice, label: u64, msg: &[u64; 4]) -> IpcResponse {
    match label & 0xFFFF {
        request::GET_INFO => IpcResponse::simple(response::OK),
        request::GET_STATUS => IpcResponse::simple(
            status::READY | status::USB2_SUPPORTED | status::USB3_SUPPORTED | status::PORTS_POWERED
        ),
        request::GET_PORT_COUNT => {
            let count = device.xhci_ctrl.max_ports() as u64;
            IpcResponse::simple(response::OK | (count << 16))
        }
        request::GET_PORT_STATUS => IpcResponse::simple(handle_get_port_status(device, msg[0] as u8)),
        request::LIST_DEVICES => IpcResponse::simple(handle_list_devices(device)),
        request::GET_INTERFACES => IpcResponse::simple(handle_get_interfaces(device, msg[0] as u8)),
        request::SET_PROTOCOL => {
            let device_addr = (msg[0] & 0xFF) as u8;
            let interface = ((msg[0] >> 8) & 0xFF) as u8;
            let protocol = ((msg[0] >> 16) & 0xFF) as u8;
            IpcResponse::simple(handle_set_protocol(device, device_addr, interface, protocol))
        }
        request::SET_IDLE => {
            let device_addr = (msg[0] & 0xFF) as u8;
            let interface = ((msg[0] >> 8) & 0xFF) as u8;
            let duration = ((msg[0] >> 16) & 0xFF) as u8;
            let report_id = ((msg[0] >> 24) & 0xFF) as u8;
            IpcResponse::simple(handle_set_idle(device, device_addr, interface, duration, report_id))
        }
        request::START_INTERRUPT => {
            let packed = msg[0];
            let device_addr = (packed & 0xFF) as u8;
            let endpoint = ((packed >> 8) & 0xFF) as u8;
            let interval = ((packed >> 16) & 0xFFFF) as u16;
            IpcResponse::simple(handle_start_interrupt(device, device_addr, endpoint, msg[1], interval))
        }
        request::STOP_INTERRUPT => IpcResponse::simple(handle_stop_interrupt(device, msg[0] as u8, msg[1] as u8)),
        request::GET_INTERRUPT_DATA => {
            handle_get_interrupt_data(device, msg[0] as u8, msg[1] as u8)
        }
        _ => IpcResponse::simple(response::ERR_UNSUPPORTED),
    }
}

/// Handle SET_PROTOCOL request (HID boot/report protocol)
fn handle_set_protocol(device: &mut XhciDevice, device_addr: u8, interface: u8, protocol: u8) -> u64 {
    ensure_enumerated(device);

    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 || !device.xhci_initialized {
        return response::ERR_NO_DEVICE;
    }

    // SET_PROTOCOL: bmRequestType=0x21, bRequest=0x0B
    let mut dummy = [0u8; 0];
    let _ = device.xhci_ctrl.control_transfer(
        slot_id,
        0x21,
        0x0B,
        protocol as u16,
        interface as u16,
        &mut dummy,
    );
    // Return OK regardless - some devices don't support SET_PROTOCOL
    response::OK
}

/// Handle SET_IDLE request (HID idle rate)
fn handle_set_idle(device: &mut XhciDevice, device_addr: u8, interface: u8, duration: u8, report_id: u8) -> u64 {
    ensure_enumerated(device);

    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 || !device.xhci_initialized {
        return response::ERR_NO_DEVICE;
    }

    // SET_IDLE: bmRequestType=0x21, bRequest=0x0A
    let w_value = ((duration as u16) << 8) | (report_id as u16);
    let mut dummy = [0u8; 0];
    let _ = device.xhci_ctrl.control_transfer(
        slot_id,
        0x21,
        0x0A,
        w_value,
        interface as u16,
        &mut dummy,
    );
    // Return OK regardless - some devices don't support SET_IDLE
    response::OK
}

fn handle_get_port_status(device: &mut XhciDevice, port: u8) -> u64 {
    if port == 0 {
        return response::ERR_INVALID_PORT;
    }

    let port_idx = port - 1;
    if port_idx >= device.xhci_ctrl.max_ports() {
        return response::ERR_INVALID_PORT;
    }

    // Read fresh port status from registers
    let port_status = device.xhci_ctrl.read_port_status(port_idx);

    // Update cache
    if (port_idx as usize) < device.port_status_cache.len() {
        device.port_status_cache[port_idx as usize] = port_status;
    }

    // Build response
    let mut flags: u64 = 0;
    if port_status.connected {
        flags |= ipc::port_status::CONNECTED;
    }
    if port_status.enabled {
        flags |= ipc::port_status::ENABLED;
    }
    if port_status.powered {
        flags |= ipc::port_status::POWER;
    }
    if port_status.in_reset {
        flags |= ipc::port_status::RESET;
    }
    if port_status.connect_changed {
        flags |= ipc::port_status::CHANGED;
    }

    let speed_flags = match port_status.speed {
        PortSpeed::Low => ipc::port_status::LOW_SPEED,
        PortSpeed::Full => ipc::port_status::FULL_SPEED,
        PortSpeed::High => ipc::port_status::HIGH_SPEED,
        PortSpeed::Super | PortSpeed::SuperPlus => ipc::port_status::SUPER_SPEED,
        PortSpeed::Unknown => 0,
    };
    flags |= speed_flags;

    response::OK | flags
}

fn handle_list_devices(device: &mut XhciDevice) -> u64 {
    ensure_enumerated(device);
    let count = device.devices.len() as u64;
    response::OK | (count << 16)
}

/// Ensure devices have been enumerated (lazy enumeration)
fn ensure_enumerated(device: &mut XhciDevice) {
    if device.devices_enumerated {
        return;
    }

    // First, reset any connected but not enabled ports
    for i in 0..device.port_status_cache.len() {
        let port_status = &device.port_status_cache[i];
        if port_status.connected && !port_status.enabled {
            // Port numbers are 1-indexed, convert to 0-indexed for reset
            match device.xhci_ctrl.reset_port(port_status.port - 1) {
                Ok(new_status) => {
                    device.port_status_cache[i] = new_status;
                }
                Err(_) => {}
            }
        }
    }

    // If xHCI is not initialised, create placeholder entries
    if !device.xhci_initialized {
        for port_status in &device.port_status_cache {
            if port_status.connected && port_status.enabled {
                let dev = UsbDeviceInfo {
                    slot_id: 0,
                    port: port_status.port,
                    speed: port_status.speed,
                    interfaces: alloc::vec::Vec::new(),
                };
                device.devices.push(dev);
            }
        }
        device.devices_enumerated = true;
        return;
    }

    // Full enumeration using xHCI hardware
    for port_status in device.port_status_cache.clone() {
        if !port_status.connected || !port_status.enabled {
            continue;
        }

        // Enable slot for this device
        let slot_id = match device.xhci_ctrl.enable_slot() {
            Ok(id) => id,
            Err(_) => continue,
        };

        // Address the device
        if let Err(_) = device.xhci_ctrl.address_device(slot_id, port_status.port, port_status.speed) {
            continue;
        }

        // Get device descriptor
        let _dev_desc = match device.xhci_ctrl.get_device_descriptor(slot_id) {
            Ok(desc) => desc,
            Err(_) => DeviceDescriptor::default(),
        };

        // Get configuration descriptor and parse interfaces
        let mut config_buf = [0u8; 256];
        let interfaces = match device.xhci_ctrl.get_configuration_descriptor(slot_id, 0, &mut config_buf) {
            Ok(len) => parse_interfaces(&config_buf[..len]),
            Err(_) => alloc::vec::Vec::new(),
        };

        let dev = UsbDeviceInfo {
            slot_id,
            port: port_status.port,
            speed: port_status.speed,
            interfaces,
        };
        device.devices.push(dev);
    }

    device.devices_enumerated = true;
}

/// Parse interfaces from a configuration descriptor
fn parse_interfaces(config_data: &[u8]) -> alloc::vec::Vec<UsbInterfaceInfo> {
    let mut interfaces = alloc::vec::Vec::new();

    // USB descriptor format:
    // - byte 0: length
    // - byte 1: descriptor type
    // Configuration descriptor type = 0x02
    // Interface descriptor type = 0x04
    // Endpoint descriptor type = 0x05

    if config_data.len() < 4 {
        return interfaces;
    }

    let mut offset = 0;
    let mut current_interface: Option<UsbInterfaceInfo> = None;

    while offset + 2 <= config_data.len() {
        let desc_len = config_data[offset] as usize;
        let desc_type = config_data[offset + 1];

        if desc_len < 2 || offset + desc_len > config_data.len() {
            break;
        }

        match desc_type {
            0x04 if desc_len >= 9 => {
                // Interface descriptor
                // Save previous interface if any
                if let Some(iface) = current_interface.take() {
                    interfaces.push(iface);
                }

                current_interface = Some(UsbInterfaceInfo {
                    interface_number: config_data[offset + 2],
                    class: config_data[offset + 5],
                    subclass: config_data[offset + 6],
                    protocol: config_data[offset + 7],
                    endpoint_address: 0,
                    endpoint_interval: 0,
                });
            }
            0x05 if desc_len >= 7 => {
                // Endpoint descriptor
                if let Some(ref mut iface) = current_interface {
                    let ep_addr = config_data[offset + 2];
                    let ep_attrs = config_data[offset + 3];
                    let ep_interval = config_data[offset + 6];

                    // Check if this is an IN interrupt endpoint
                    let is_in = (ep_addr & 0x80) != 0;
                    let is_interrupt = (ep_attrs & 0x03) == 0x03;

                    if is_in && is_interrupt && iface.endpoint_address == 0 {
                        iface.endpoint_address = ep_addr;
                        iface.endpoint_interval = ep_interval;
                    }
                }
            }
            _ => {}
        }

        offset += desc_len;
    }

    // Don't forget the last interface
    if let Some(iface) = current_interface {
        interfaces.push(iface);
    }

    interfaces
}

fn handle_get_interfaces(device: &mut XhciDevice, addr: u8) -> u64 {
    ensure_enumerated(device);

    let idx = (addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let dev = &device.devices[idx];
    let iface_count = dev.interfaces.len() as u8;

    if iface_count == 0 {
        // No interfaces enumerated yet - requires GET_DESCRIPTOR (future work)
        return response::OK;
    }

    // Pack first interface into response
    let mut first_iface_packed = 0u32;
    if let Some(iface) = dev.interfaces.first() {
        first_iface_packed = (iface.class as u32)
            | ((iface.subclass as u32) << 8)
            | ((iface.protocol as u32) << 16)
            | ((iface.endpoint_address as u32) << 24);
    }

    response::OK | ((iface_count as u64) << 16) | ((first_iface_packed as u64) << 32)
}

// -- Interrupt transfer management

struct InterruptTransfer {
    device_addr: u8,
    endpoint: u8,
    notif_cptr: u64,
    interval_ms: u16,
    buffer: [u8; 8],
    buffer_len: u8,
    has_pending_data: bool,
    active: bool,
    /// xHCI slot ID (1-based, 0 = not assigned)
    slot_id: u8,
    /// xHCI endpoint index (from configure_interrupt_endpoint)
    ep_idx: u8,
    /// Whether hardware endpoint is configured
    hw_configured: bool,
}

impl InterruptTransfer {
    const fn empty() -> Self {
        Self {
            device_addr: 0,
            endpoint: 0,
            notif_cptr: 0,
            interval_ms: 0,
            buffer: [0; 8],
            buffer_len: 0,
            has_pending_data: false,
            active: false,
            slot_id: 0,
            ep_idx: 0,
            hw_configured: false,
        }
    }
}

const MAX_INTERRUPT_TRANSFERS: usize = 8;

static mut INTERRUPT_TRANSFERS: [InterruptTransfer; MAX_INTERRUPT_TRANSFERS] =
    [const { InterruptTransfer::empty() }; MAX_INTERRUPT_TRANSFERS];

fn handle_start_interrupt(
    device: &mut XhciDevice,
    device_addr: u8,
    endpoint: u8,
    notif_cptr: u64,
    interval_ms: u16,
) -> u64 {
    // Check endpoint is IN direction
    if (endpoint & 0x80) == 0 {
        return response::ERR_INVALID;
    }

    // Ensure devices are enumerated
    ensure_enumerated(device);

    // Find the device's slot_id
    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 {
        return response::ERR_NO_DEVICE;
    }

    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };
    let slot = transfers.iter_mut().find(|t| !t.active);

    match slot {
        Some(transfer) => {
            transfer.device_addr = device_addr;
            transfer.endpoint = endpoint;
            transfer.notif_cptr = notif_cptr;
            transfer.interval_ms = if interval_ms == 0 { 10 } else { interval_ms };
            transfer.buffer = [0; 8];
            transfer.buffer_len = 0;
            transfer.has_pending_data = false;
            transfer.active = true;
            transfer.slot_id = slot_id;
            transfer.ep_idx = 0;
            transfer.hw_configured = false;

            // Configure the hardware endpoint if xHCI is initialised
            if device.xhci_initialized {
                // Find endpoint interval from device interfaces
                let ep_interval = device.devices[idx]
                    .interfaces
                    .iter()
                    .find(|i| i.endpoint_address == endpoint)
                    .map(|i| i.endpoint_interval)
                    .unwrap_or(10);

                match device.xhci_ctrl.configure_interrupt_endpoint(
                    slot_id,
                    endpoint,
                    8, // max_packet_size for HID boot protocol
                    ep_interval,
                ) {
                    Ok(ep_idx) => {
                        transfer.ep_idx = ep_idx as u8;
                        transfer.hw_configured = true;

                        // Queue initial transfer
                        let _ = device.xhci_ctrl.queue_interrupt_transfer(slot_id, ep_idx);
                    }
                    Err(_) => {
                        // Software will poll but won't get hardware data
                    }
                }
            }

            response::OK
        }
        None => response::ERR_NO_RESOURCES,
    }
}

fn handle_stop_interrupt(_device: &mut XhciDevice, device_addr: u8, endpoint: u8) -> u64 {
    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    for transfer in transfers.iter_mut() {
        if transfer.active && transfer.device_addr == device_addr && transfer.endpoint == endpoint {
            transfer.active = false;
            return response::OK;
        }
    }

    response::ERR_INVALID
}

/// IPC response with message data
struct IpcResponse {
    label: u64,
    msg: [u64; 4],
}

impl IpcResponse {
    const fn simple(label: u64) -> Self {
        Self { label, msg: [0; 4] }
    }
}

fn handle_get_interrupt_data(device: &mut XhciDevice, device_addr: u8, endpoint: u8) -> IpcResponse {
    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    for transfer in transfers.iter_mut() {
        if transfer.active && transfer.device_addr == device_addr && transfer.endpoint == endpoint {
            // Poll hardware for new data if configured
            if transfer.hw_configured && device.xhci_initialized {
                if let Some((data, len)) = device.xhci_ctrl.poll_interrupt_data(
                    transfer.slot_id,
                    transfer.ep_idx as usize,
                ) {
                    // Store in transfer buffer
                    let copy_len = len.min(8);
                    transfer.buffer[..copy_len].copy_from_slice(&data[..copy_len]);
                    transfer.buffer_len = copy_len as u8;
                    transfer.has_pending_data = true;

                    // Re-queue the transfer for continuous polling
                    let _ = device.xhci_ctrl.queue_interrupt_transfer(
                        transfer.slot_id,
                        transfer.ep_idx as usize,
                    );
                }
            }

            if transfer.has_pending_data {
                let count = transfer.buffer_len;

                // Pack all 8 bytes into msg[0] for full boot keyboard report
                let packed_all = u64::from_le_bytes(transfer.buffer);

                transfer.has_pending_data = false;
                transfer.buffer_len = 0;

                return IpcResponse {
                    label: response::OK | ((count as u64) << 16),
                    msg: [packed_all, 0, 0, 0],
                };
            } else {
                return IpcResponse::simple(response::OK);
            }
        }
    }

    IpcResponse::simple(response::ERR_INVALID)
}
