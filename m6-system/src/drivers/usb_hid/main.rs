//! USB HID (Human Interface Device) Driver
//!
//! Userspace driver for USB keyboards and mice. Discovers HID devices
//! via the USB host controller driver (xHCI or DWC3) and provides
//! input events to client applications via IPC.
//!
//! # Architecture
//!
//! This driver is a class driver that sits above the USB host controller.
//! It communicates with either the xHCI or DWC3 driver via IPC to:
//! - Enumerate connected USB devices
//! - Configure HID interfaces (boot protocol)
//! - Poll interrupt endpoints for HID reports
//! - Deliver input events to subscribed clients
//!
//! # Capabilities received from device-mgr
//!
//! - Slot 12: Service endpoint for client requests
//! - Slot 13: USB host driver endpoint (xHCI or DWC3)
//! - Slot 14: Notification for interrupt transfer completions

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod boot_keyboard;
mod boot_mouse;
mod device;
mod input_event;
mod ipc;

#[path = "../../io.rs"]
mod io;

use alloc::vec::Vec;

use device::{HidDeviceConfig, HidDeviceManager, HidDeviceType};
use input_event::InputEvent;

use m6_syscall::invoke::{poll, recv, reply_recv, sched_yield};

// Import USB host IPC protocol (shared with xHCI/DWC3)
#[path = "../usb_xhci/ipc.rs"]
mod usb_ipc;

// -- Capability slot definitions

const CNODE_RADIX: u8 = 10;

#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

/// Service endpoint for client requests (slot 12)
const SERVICE_EP: u64 = cptr(12);
/// USB host driver endpoint (slot 13)
const USB_HOST_EP: u64 = cptr(13);
/// Notification for interrupt completions (slot 14)
const INTERRUPT_NOTIF: u64 = cptr(14);

/// Maximum number of client subscriptions
const MAX_SUBSCRIPTIONS: usize = 8;

/// Maximum events to return per GET_EVENTS request
const MAX_EVENTS_PER_REQUEST: usize = 32;

/// Client subscription
struct Subscription {
    /// Subscription ID
    id: u16,
    /// Device type mask
    device_mask: u64,
    /// Active flag
    active: bool,
}

impl Subscription {
    const fn empty() -> Self {
        Self {
            id: 0,
            device_mask: 0,
            active: false,
        }
    }
}

/// HID driver state
struct HidDriver {
    /// Device manager
    devices: HidDeviceManager,
    /// Client subscriptions
    subscriptions: [Subscription; MAX_SUBSCRIPTIONS],
    /// Next subscription ID
    next_sub_id: u16,
    /// USB host driver available
    usb_available: bool,
}

impl HidDriver {
    fn new() -> Self {
        Self {
            devices: HidDeviceManager::new(),
            subscriptions: [const { Subscription::empty() }; MAX_SUBSCRIPTIONS],
            next_sub_id: 1,
            usb_available: false,
        }
    }

    /// Check USB host availability
    fn check_usb_host(&mut self) -> bool {
        match m6_syscall::invoke::call(USB_HOST_EP, usb_ipc::request::GET_STATUS, 0, 0, 0) {
            Ok(result) => {
                let status = result.label;
                self.usb_available = (status & usb_ipc::status::READY) != 0;
                self.usb_available
            }
            Err(_) => {
                self.usb_available = false;
                false
            }
        }
    }

    /// Enumerate HID devices from USB host
    fn enumerate_devices(&mut self) -> usize {
        if !self.usb_available {
            return 0;
        }

        let device_count = match m6_syscall::invoke::call(
            USB_HOST_EP,
            usb_ipc::request::LIST_DEVICES,
            0,
            0,
            0,
        ) {
            Ok(result) => {
                if (result.label & 0xFFFF) == usb_ipc::response::OK {
                    ((result.label >> 16) & 0xFFFF) as usize
                } else {
                    0
                }
            }
            Err(_) => 0,
        };

        if device_count == 0 {
            return 0;
        }

        let mut hid_count = 0;

        for addr in 1..=device_count as u8 {
            let configs = self.probe_device_for_hid(addr);
            for config in configs {
                self.devices.add_device(config);
                hid_count += 1;
            }
        }

        hid_count
    }

    /// Probe a USB device for HID interfaces.
    /// Returns a list of HID configs for all keyboard/mouse interfaces found.
    fn probe_device_for_hid(&self, device_addr: u8) -> Vec<HidDeviceConfig> {
        let mut configs = Vec::new();

        let result = match m6_syscall::invoke::call(
            USB_HOST_EP,
            usb_ipc::request::GET_INTERFACES,
            device_addr as u64,
            0,
            0,
        ) {
            Ok(r) => r,
            Err(_) => {
                return configs;
            }
        };

        let response_code = result.label & 0xFFFF;
        if response_code != usb_ipc::response::OK {
            return configs;
        }

        let iface_count = ((result.label >> 16) & 0xFF) as usize;
        if iface_count == 0 {
            return configs;
        }

        // Extract first interface's packed data from upper bits
        // Format: class | subclass<<8 | protocol<<16 | endpoint<<24
        let first_iface_packed = (result.label >> 32) as u32;
        let class = (first_iface_packed & 0xFF) as u8;
        let subclass = ((first_iface_packed >> 8) & 0xFF) as u8;
        let protocol = ((first_iface_packed >> 16) & 0xFF) as u8;
        let endpoint = ((first_iface_packed >> 24) & 0xFF) as u8;


        // Check for HID class (0x03) with boot interface subclass (0x01)
        if class != usb_ipc::class::HID {
            return configs;
        }

        // Determine device type from protocol
        let device_type = if subclass == usb_ipc::hid_subclass::BOOT {
            match protocol {
                usb_ipc::hid_protocol::KEYBOARD => HidDeviceType::Keyboard,
                usb_ipc::hid_protocol::MOUSE => HidDeviceType::Mouse,
                _ => HidDeviceType::Unknown,
            }
        } else {
            HidDeviceType::Unknown
        };

        // Add boot protocol interface if it's a keyboard or mouse
        if device_type != HidDeviceType::Unknown {
            configs.push(HidDeviceConfig {
                device_addr,
                interface: 0,
                endpoint_in: endpoint | 0x80,
                interval_ms: 10,
                max_packet_size: 8,
                device_type,
            });
        }

        // For keyboards with multiple interfaces (like QMK/Ergodox), also try
        // the NKRO interface. NKRO is typically interface 1 with endpoint 0x83.
        // Many QMK keyboards send actual key data on NKRO, not boot protocol.
        if device_type == HidDeviceType::Keyboard && iface_count > 1 {
            // Try endpoint 0x83 (typically NKRO on QMK keyboards)
            configs.push(HidDeviceConfig {
                device_addr,
                interface: 1,
                endpoint_in: 0x83,
                interval_ms: 10,
                max_packet_size: 8,
                device_type: HidDeviceType::Keyboard,
            });
        }

        configs
    }

    /// Start interrupt polling for a HID device
    fn start_device_polling(&mut self, device_idx: usize) {
        let device = match self.devices.get_device(device_idx) {
            Some(d) => d,
            None => return,
        };

        let device_addr = device.config.device_addr;
        let interface = device.config.interface;

        // First, set boot protocol (protocol=0) for HID boot devices
        // This is required for keyboards/mice with boot protocol support
        // Pack: device_addr | interface<<8 | protocol<<16
        let set_protocol_arg = (device_addr as u64)
            | ((interface as u64) << 8)
            | (0u64 << 16); // protocol=0 for boot protocol

        let _ = m6_syscall::invoke::call(
            USB_HOST_EP,
            usb_ipc::request::SET_PROTOCOL,
            set_protocol_arg,
            0,
            0,
        );

        // Also set idle rate to 0 (report only on change)
        // Pack: device_addr | interface<<8 | duration<<16 | report_id<<24
        let set_idle_arg = (device_addr as u64)
            | ((interface as u64) << 8)
            | (0u64 << 16)  // duration=0 (only report on change)
            | (0u64 << 24); // report_id=0 (all reports)

        let _ = m6_syscall::invoke::call(
            USB_HOST_EP,
            usb_ipc::request::SET_IDLE,
            set_idle_arg,
            0,
            0,
        );

        // Now start interrupt transfers
        // Pack: x1 = device_addr | endpoint<<8 | interval<<16
        let packed_arg = (device_addr as u64)
            | ((device.config.endpoint_in as u64) << 8)
            | ((device.config.interval_ms as u64) << 16);

        let result = m6_syscall::invoke::call(
            USB_HOST_EP,
            usb_ipc::request::START_INTERRUPT,
            packed_arg,
            INTERRUPT_NOTIF,
            0,
        );
        match result {
            Ok(r) => {
                let code = r.label & 0xFFFF;
                if code != 0 {
                    io::puts("[drv-usb-hid] START_INT err=");
                    io::put_u64(code);
                    io::newline();
                }
            }
            Err(e) => {
                io::puts("[drv-usb-hid] START_INT IPC err=");
                io::put_u64(e as u64);
                io::newline();
            }
        }
    }

    /// Handle interrupt data from USB host
    fn handle_interrupt_data(&mut self) {
        static mut TIMESTAMP: u64 = 0;
        static mut DATA_LOG_COUNT: u64 = 0;
        // SAFETY: Single-threaded driver
        let timestamp_ns = unsafe {
            TIMESTAMP = TIMESTAMP.wrapping_add(1_000_000);
            TIMESTAMP
        };

        for device_idx in 0..self.devices.device_count() {
            let device = match self.devices.get_device(device_idx) {
                Some(d) => d,
                None => continue,
            };

            let device_addr = device.config.device_addr;
            let endpoint = device.config.endpoint_in;

            let result = m6_syscall::invoke::call(
                USB_HOST_EP,
                usb_ipc::request::GET_INTERRUPT_DATA,
                device_addr as u64,
                endpoint as u64,
                0,
            );

            if let Ok(r) = result {
                let response_code = r.label & 0xFFFF;
                let byte_count = ((r.label >> 16) & 0xFF) as usize;

                // Log first few non-OK responses to diagnose pipeline
                if response_code != usb_ipc::response::OK {
                    // SAFETY: Single-threaded
                    let log_count = unsafe { DATA_LOG_COUNT };
                    if log_count < 3 {
                        io::puts("[drv-usb-hid] GET_INT_DATA err=");
                        io::put_u64(response_code);
                        io::newline();
                        unsafe { DATA_LOG_COUNT += 1; }
                    }
                }

                if response_code == usb_ipc::response::OK && byte_count > 0 {
                    let packed_data = r.msg[0];
                    let report = packed_data.to_le_bytes();
                    let actual_len = byte_count.min(8);

                    self.devices.process_report(device_addr, endpoint, &report[..actual_len], timestamp_ns);
                }
            }
        }
    }

    /// Create a subscription
    fn subscribe(&mut self, device_mask: u64) -> Option<u16> {
        // Find an empty slot
        for sub in &mut self.subscriptions {
            if !sub.active {
                let id = self.next_sub_id;
                self.next_sub_id = self.next_sub_id.wrapping_add(1);
                if self.next_sub_id == 0 {
                    self.next_sub_id = 1;
                }

                sub.id = id;
                sub.device_mask = device_mask;
                sub.active = true;
                return Some(id);
            }
        }
        None
    }

    /// Cancel a subscription
    fn unsubscribe(&mut self, sub_id: u16) -> bool {
        for sub in &mut self.subscriptions {
            if sub.active && sub.id == sub_id {
                sub.active = false;
                return true;
            }
        }
        false
    }

    /// Get pending events for a subscription
    fn get_events(&mut self, sub_id: u16, max_events: usize) -> Option<Vec<InputEvent>> {
        // Find the subscription
        let sub = self.subscriptions.iter().find(|s| s.active && s.id == sub_id)?;
        let device_mask = sub.device_mask;

        let mut events = Vec::new();
        let limit = max_events.min(MAX_EVENTS_PER_REQUEST);

        // Collect events from matching devices
        for device in self.devices.devices_mut() {
            // Check if subscription matches this device type
            let type_bit = match device.config.device_type {
                HidDeviceType::Keyboard => ipc::device_type::KEYBOARD,
                HidDeviceType::Mouse => ipc::device_type::MOUSE,
                HidDeviceType::Unknown => continue,
            };

            if (device_mask & type_bit) == 0 {
                continue;
            }

            // Drain events from this device
            let device_events = device.drain_events(limit - events.len());
            events.extend(device_events);

            if events.len() >= limit {
                break;
            }
        }

        Some(events)
    }

    /// Poll for event count
    fn poll_events(&self, sub_id: u16) -> Option<usize> {
        let sub = self.subscriptions.iter().find(|s| s.active && s.id == sub_id)?;
        let device_mask = sub.device_mask;

        let mut count = 0;
        for device in self.devices.devices() {
            let type_bit = match device.config.device_type {
                HidDeviceType::Keyboard => ipc::device_type::KEYBOARD,
                HidDeviceType::Mouse => ipc::device_type::MOUSE,
                HidDeviceType::Unknown => continue,
            };

            if (device_mask & type_bit) != 0 {
                count += device.pending_event_count();
            }
        }

        Some(count)
    }
}

/// Entry point for USB HID driver.
///
/// # Safety
///
/// Must be called only once as the driver entry point with valid capability slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    // Initialise heap allocator before any heap allocations
    rt::init_allocator();

    let mut driver = HidDriver::new();

    // Enter service loop immediately - don't block on USB host availability
    service_loop(&mut driver);
}

/// IPC response with label and optional message data.
struct IpcResponse {
    label: u64,
    msg: [u64; 4],
}

impl IpcResponse {
    const fn simple(label: u64) -> Self {
        Self { label, msg: [0; 4] }
    }
}

/// Main service loop
fn service_loop(driver: &mut HidDriver) -> ! {
    let mut result = recv(SERVICE_EP);
    let mut poll_counter = 0u32;

    loop {
        match result {
            Ok(ipc_result) => {
                let response = handle_request(driver, ipc_result.label, &ipc_result.msg);
                result = reply_recv(
                    SERVICE_EP,
                    response.label,
                    response.msg[0],
                    response.msg[1],
                    response.msg[2],
                );
            }
            Err(_) => {
                // Check for interrupt notifications
                if driver.devices.device_count() > 0 {
                    if let Ok(badge) = poll(INTERRUPT_NOTIF) {
                        if badge != 0 {
                            driver.handle_interrupt_data();
                        }
                    }
                }

                // Periodic polling fallback
                poll_counter = poll_counter.wrapping_add(1);
                if poll_counter % 100 == 0 && driver.devices.device_count() > 0 {
                    driver.handle_interrupt_data();
                }

                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(driver: &mut HidDriver, label: u64, msg: &[u64; 4]) -> IpcResponse {
    match label & 0xFFFF {
        ipc::request::SUBSCRIBE => IpcResponse::simple(handle_subscribe(driver, msg[0])),
        ipc::request::UNSUBSCRIBE => IpcResponse::simple(handle_unsubscribe(driver, msg[0] as u16)),
        ipc::request::GET_EVENTS => handle_get_events(driver, msg[0] as u16, msg[1] as usize),
        ipc::request::POLL_EVENTS => IpcResponse::simple(handle_poll_events(driver, msg[0] as u16)),
        ipc::request::LIST_DEVICES => IpcResponse::simple(handle_list_devices(driver)),
        ipc::request::GET_DEVICE_INFO => IpcResponse::simple(handle_get_device_info(driver, msg[0] as usize)),
        _ => IpcResponse::simple(ipc::response::ERR_UNSUPPORTED),
    }
}

/// Handle SUBSCRIBE request
fn handle_subscribe(driver: &mut HidDriver, device_mask: u64) -> u64 {
    // Lazily discover HID devices on first subscription
    if driver.devices.device_count() == 0 && !driver.usb_available {
        if driver.check_usb_host() {
            let count = driver.enumerate_devices();
            io::puts("[drv-usb-hid] ");
            io::put_u64(count as u64);
            io::puts(" HID device(s)\n");
            for i in 0..count {
                driver.start_device_polling(i);
            }
        }
    }

    match driver.subscribe(device_mask) {
        Some(sub_id) => ipc::response::OK | ((sub_id as u64) << 16),
        None => ipc::response::ERR_BUSY,
    }
}

/// Handle UNSUBSCRIBE request
fn handle_unsubscribe(driver: &mut HidDriver, sub_id: u16) -> u64 {
    if driver.unsubscribe(sub_id) {
        ipc::response::OK
    } else {
        ipc::response::ERR_INVALID_SUB
    }
}

/// Handle GET_EVENTS request
fn handle_get_events(driver: &mut HidDriver, sub_id: u16, max_events: usize) -> IpcResponse {
    match driver.get_events(sub_id, max_events.min(2)) {
        Some(events) => {
            let count = events.len();
            let mut msg = [0u64; 4];

            // Pack up to 2 events into the message (each event = 2 u64 words)
            if count >= 1 {
                let (w0, w1) = events[0].pack();
                msg[0] = w0;
                msg[1] = w1;
            }
            if count >= 2 {
                let (w0, w1) = events[1].pack();
                msg[2] = w0;
                msg[3] = w1;
            }

            IpcResponse {
                label: ipc::response::OK | ((count as u64) << 16),
                msg,
            }
        }
        None => IpcResponse::simple(ipc::response::ERR_INVALID_SUB),
    }
}

/// Handle POLL_EVENTS request
fn handle_poll_events(driver: &mut HidDriver, sub_id: u16) -> u64 {
    // Fetch any pending USB data before checking event count
    if driver.devices.device_count() > 0 {
        driver.handle_interrupt_data();
    }

    match driver.poll_events(sub_id) {
        Some(count) => ipc::response::OK | ((count as u64) << 16),
        None => ipc::response::ERR_INVALID_SUB,
    }
}

/// Handle LIST_DEVICES request
fn handle_list_devices(driver: &HidDriver) -> u64 {
    let count = driver.devices.device_count();
    ipc::response::OK | ((count as u64) << 16)
}

/// Handle GET_DEVICE_INFO request
fn handle_get_device_info(driver: &HidDriver, index: usize) -> u64 {
    match driver.devices.get_device(index) {
        Some(device) => {
            let device_type = match device.config.device_type {
                HidDeviceType::Keyboard => 0,
                HidDeviceType::Mouse => 1,
                HidDeviceType::Unknown => 255,
            };

            let info = ipc::DeviceInfo {
                index: index as u8,
                device_type,
                usb_addr: device.config.device_addr,
                interface: device.config.interface,
                endpoint: device.config.endpoint_in,
                interval: device.config.interval_ms,
                _reserved: [0; 2],
            };

            // Pack info into response (device info in x1)
            // For now, return packed u64 format
            ipc::response::OK | (info.pack() << 16)
        }
        None => ipc::response::ERR_INVALID_DEVICE,
    }
}

