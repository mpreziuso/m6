//! HID driver IPC protocol for input clients.
//!
//! Defines the message protocol for applications to receive
//! keyboard and mouse events from the HID driver.

#![allow(dead_code)]

/// Client IPC request message labels
pub mod request {
    /// Subscribe to HID events
    /// x1: device type mask (bit 0=keyboard, bit 1=mouse)
    /// x2: notification capability slot (for event signalling)
    /// Returns: subscription ID
    pub const SUBSCRIBE: u64 = 0x0001;

    /// Unsubscribe from HID events
    /// x1: subscription ID
    pub const UNSUBSCRIBE: u64 = 0x0002;

    /// Get pending input events
    /// x1: subscription ID
    /// x2: max events to retrieve
    /// Returns: event count, events in IPC buffer
    pub const GET_EVENTS: u64 = 0x0003;

    /// Poll for event availability (non-blocking)
    /// x1: subscription ID
    /// Returns: event count available
    pub const POLL_EVENTS: u64 = 0x0004;

    /// List available HID devices
    /// Returns: device count, device info in IPC buffer
    pub const LIST_DEVICES: u64 = 0x0005;

    /// Get device information
    /// x1: device index
    /// Returns: device type, endpoint info
    pub const GET_DEVICE_INFO: u64 = 0x0006;

    /// Set keyboard LEDs (Caps Lock, Num Lock, Scroll Lock)
    /// x1: device index
    /// x2: LED mask (bit 0=Num, bit 1=Caps, bit 2=Scroll)
    pub const SET_LEDS: u64 = 0x0010;

    /// Grab exclusive access to a device
    /// x1: device index
    /// Returns: OK or error if already grabbed
    pub const GRAB_DEVICE: u64 = 0x0020;

    /// Release exclusive access
    /// x1: device index
    pub const UNGRAB_DEVICE: u64 = 0x0021;
}

/// IPC response codes
pub mod response {
    /// Operation completed successfully
    pub const OK: u64 = 0;
    /// Invalid request
    pub const ERR_INVALID: u64 = 1;
    /// No HID devices found
    pub const ERR_NO_DEVICES: u64 = 2;
    /// Invalid subscription ID
    pub const ERR_INVALID_SUB: u64 = 3;
    /// Device index out of range
    pub const ERR_INVALID_DEVICE: u64 = 4;
    /// No events available
    pub const ERR_NO_EVENTS: u64 = 5;
    /// Device already grabbed by another client
    pub const ERR_BUSY: u64 = 6;
    /// USB host driver not available
    pub const ERR_NO_USB: u64 = 7;
    /// Operation not supported
    pub const ERR_UNSUPPORTED: u64 = 8;
    /// IPC buffer too small
    pub const ERR_BUFFER_TOO_SMALL: u64 = 9;
}

/// Device type bits for subscription mask
pub mod device_type {
    /// Keyboard devices
    pub const KEYBOARD: u64 = 1 << 0;
    /// Mouse devices
    pub const MOUSE: u64 = 1 << 1;
    /// All HID devices
    pub const ALL: u64 = KEYBOARD | MOUSE;
}

/// LED bits for SET_LEDS
pub mod led {
    /// Num Lock LED
    pub const NUM_LOCK: u64 = 1 << 0;
    /// Caps Lock LED
    pub const CAPS_LOCK: u64 = 1 << 1;
    /// Scroll Lock LED
    pub const SCROLL_LOCK: u64 = 1 << 2;
}

/// Badge values for event notifications
pub mod badge {
    /// Base badge for HID events
    pub const HID_EVENT: u64 = 0x2000;

    /// Generate badge for subscription
    pub const fn subscription(sub_id: u16) -> u64 {
        HID_EVENT | (sub_id as u64)
    }

    /// Check if badge is a HID event notification
    pub const fn is_hid_event(badge: u64) -> bool {
        (badge & 0xF000) == HID_EVENT
    }

    /// Extract subscription ID from badge
    pub const fn sub_id_from_badge(badge: u64) -> u16 {
        (badge & 0x0FFF) as u16
    }
}

/// Device info structure returned by LIST_DEVICES.
///
/// Packed into IPC message registers.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct DeviceInfo {
    /// Device index (0-based)
    pub index: u8,
    /// Device type (0=keyboard, 1=mouse)
    pub device_type: u8,
    /// USB device address
    pub usb_addr: u8,
    /// Interface number
    pub interface: u8,
    /// Endpoint address
    pub endpoint: u8,
    /// Polling interval in ms
    pub interval: u8,
    /// Reserved
    pub _reserved: [u8; 2],
}

impl DeviceInfo {
    /// Pack into a u64 for IPC
    pub const fn pack(&self) -> u64 {
        (self.index as u64)
            | ((self.device_type as u64) << 8)
            | ((self.usb_addr as u64) << 16)
            | ((self.interface as u64) << 24)
            | ((self.endpoint as u64) << 32)
            | ((self.interval as u64) << 40)
    }

    /// Unpack from a u64
    pub const fn unpack(val: u64) -> Self {
        Self {
            index: val as u8,
            device_type: (val >> 8) as u8,
            usb_addr: (val >> 16) as u8,
            interface: (val >> 24) as u8,
            endpoint: (val >> 32) as u8,
            interval: (val >> 40) as u8,
            _reserved: [0; 2],
        }
    }
}
