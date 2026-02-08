//! IPC Protocol for USB Host Controller
//!
//! Defines the message protocol for USB operations between clients
//! and the USB host controller driver.
//!
//! # API Limitations
//!
//! Some operations are not currently supported due to crab-usb library constraints:
//! - `GET_PORT_COUNT` returns hardcoded value (crab-usb doesn't expose HCSPARAMS1)
//! - `GET_PORT_STATUS` returns ERR_UNSUPPORTED (crab-usb doesn't expose PORTSC)
//! - `GET_DEVICE_DESCRIPTOR` has limited support (crab-usb DeviceInfo doesn't expose descriptor fields)
//!
//! Device enumeration works via `LIST_DEVICES` to get device count.

#![allow(dead_code)]

/// IPC request message labels
pub mod request {
    /// Get controller information (port count, speed support, etc.)
    pub const GET_INFO: u64 = 0x0001;
    /// Get controller status
    pub const GET_STATUS: u64 = 0x0002;
    /// Get port count
    pub const GET_PORT_COUNT: u64 = 0x0010;
    /// Get port status
    /// x1: port number (1-based)
    pub const GET_PORT_STATUS: u64 = 0x0011;
    /// Reset port
    /// x1: port number (1-based)
    pub const RESET_PORT: u64 = 0x0012;
    /// List connected devices
    pub const LIST_DEVICES: u64 = 0x0020;
    /// Get device descriptor
    /// x1: device address
    pub const GET_DEVICE_DESCRIPTOR: u64 = 0x0021;
    /// Get configuration descriptor
    /// x1: device address
    /// x2: config index
    pub const GET_CONFIG_DESCRIPTOR: u64 = 0x0022;
    /// Submit control transfer
    /// x1: device address
    /// x2: request type | request | value (packed)
    /// x3: index | length (packed)
    /// Requires: Frame capability in IPC buffer for data
    pub const SUBMIT_CONTROL: u64 = 0x0030;
    /// Submit bulk transfer
    /// x1: device address
    /// x2: endpoint (with direction bit)
    /// x3: length
    /// Requires: Frame capability in IPC buffer for data
    pub const SUBMIT_BULK: u64 = 0x0031;
    /// Submit interrupt transfer
    /// x1: device address
    /// x2: endpoint (with direction bit)
    /// x3: length
    /// Requires: Frame capability in IPC buffer for data
    pub const SUBMIT_INTERRUPT: u64 = 0x0032;

    // -- HID-related requests

    /// Get interface descriptors for a device
    /// x1: device address
    /// Returns: x1 = interface count, interface data in IPC buffer
    pub const GET_INTERFACES: u64 = 0x0023;

    /// Get specific interface info by index
    /// x1: device address
    /// x2: interface index (0-based)
    /// Returns: label = OK | (class<<16) | (subclass<<24) | (protocol<<32) | (endpoint<<40) | (interval<<48)
    pub const GET_INTERFACE_INFO: u64 = 0x0028;

    /// Claim interface for exclusive use
    /// x1: device address
    /// x2: interface number
    pub const CLAIM_INTERFACE: u64 = 0x0024;

    /// Release a claimed interface
    /// x1: device address
    /// x2: interface number
    pub const RELEASE_INTERFACE: u64 = 0x0025;

    /// HID SET_PROTOCOL (boot/report protocol)
    /// x1: device address
    /// x2: interface number
    /// x3: protocol (0 = boot, 1 = report)
    pub const SET_PROTOCOL: u64 = 0x0026;

    /// HID SET_IDLE rate
    /// x1: device address
    /// x2: interface number
    /// x3: idle rate (duration in 4ms units, 0 = infinite)
    pub const SET_IDLE: u64 = 0x0027;

    /// Start interrupt transfer polling for an endpoint
    /// x1: device address
    /// x2: endpoint (with IN direction bit 0x80)
    /// x3: interval (polling interval in ms)
    /// x4: notification capability to signal on data
    pub const START_INTERRUPT: u64 = 0x0040;

    /// Stop interrupt transfer polling
    /// x1: device address
    /// x2: endpoint
    pub const STOP_INTERRUPT: u64 = 0x0041;

    /// Get pending interrupt transfer data
    /// x1: device address
    /// x2: endpoint
    /// Returns: x1 = bytes available, data in IPC buffer
    pub const GET_INTERRUPT_DATA: u64 = 0x0042;
}

/// IPC response codes
pub mod response {
    /// Operation completed successfully
    pub const OK: u64 = 0;
    /// Invalid request
    pub const ERR_INVALID: u64 = 1;
    /// I/O error
    pub const ERR_IO: u64 = 2;
    /// Controller not ready
    pub const ERR_NOT_READY: u64 = 3;
    /// Invalid port number
    pub const ERR_INVALID_PORT: u64 = 4;
    /// Device not found
    pub const ERR_NO_DEVICE: u64 = 5;
    /// Transfer stall
    pub const ERR_STALL: u64 = 6;
    /// Transfer timeout
    pub const ERR_TIMEOUT: u64 = 7;
    /// Operation not supported
    pub const ERR_UNSUPPORTED: u64 = 8;
    /// No resources available
    pub const ERR_NO_RESOURCES: u64 = 9;
}

/// Controller status flags
pub mod status {
    /// Controller is ready for operations
    pub const READY: u64 = 1 << 0;
    /// Controller supports USB 2.0
    pub const USB2_SUPPORTED: u64 = 1 << 1;
    /// Controller supports USB 3.0
    pub const USB3_SUPPORTED: u64 = 1 << 2;
    /// Controller has powered ports
    pub const PORTS_POWERED: u64 = 1 << 3;
}

/// Port status flags
pub mod port_status {
    /// Port has a device connected
    pub const CONNECTED: u64 = 1 << 0;
    /// Port is enabled
    pub const ENABLED: u64 = 1 << 1;
    /// Port is in reset state
    pub const RESET: u64 = 1 << 2;
    /// Port power is on
    pub const POWER: u64 = 1 << 3;
    /// Port status changed
    pub const CHANGED: u64 = 1 << 4;
    /// Low speed device (USB 1.x)
    pub const LOW_SPEED: u64 = 1 << 8;
    /// Full speed device (USB 1.x/2.0)
    pub const FULL_SPEED: u64 = 2 << 8;
    /// High speed device (USB 2.0)
    pub const HIGH_SPEED: u64 = 3 << 8;
    /// SuperSpeed device (USB 3.x)
    pub const SUPER_SPEED: u64 = 4 << 8;
    /// Speed mask
    pub const SPEED_MASK: u64 = 0xF << 8;
}

/// USB device speed encoding (matches xHCI)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbSpeed {
    /// Low speed (1.5 Mbps)
    Low = 1,
    /// Full speed (12 Mbps)
    Full = 2,
    /// High speed (480 Mbps)
    High = 3,
    /// SuperSpeed (5 Gbps)
    Super = 4,
    /// SuperSpeed+ (10 Gbps)
    SuperPlus = 5,
}

impl UsbSpeed {
    /// Convert from xHCI port speed value
    pub fn from_xhci(speed: u8) -> Option<Self> {
        match speed {
            1 => Some(Self::Low),
            2 => Some(Self::Full),
            3 => Some(Self::High),
            4 => Some(Self::Super),
            5 => Some(Self::SuperPlus),
            _ => None,
        }
    }

    /// Convert to port status speed bits
    pub fn to_port_status(self) -> u64 {
        (self as u64) << 8
    }
}

/// Controller information structure
#[derive(Clone, Copy, Debug, Default)]
pub struct ControllerInfo {
    /// Number of root hub ports
    pub port_count: u8,
    /// Maximum device slots
    pub max_slots: u8,
    /// xHCI version (major.minor packed as 0xMMmm)
    pub version: u16,
    /// Controller capabilities flags
    pub capabilities: u32,
}

impl ControllerInfo {
    /// Pack into IPC message format.
    /// Returns (x1, x2) for reply.
    #[must_use]
    pub const fn pack(&self) -> (u64, u64) {
        (
            (self.port_count as u64)
                | ((self.max_slots as u64) << 8)
                | ((self.version as u64) << 16),
            self.capabilities as u64,
        )
    }
}

/// USB device descriptor (standard 18-byte format)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct DeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub usb_version: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_index: u8,
    pub num_configurations: u8,
}

/// USB class codes
pub mod class {
    /// Human Interface Device (HID)
    pub const HID: u8 = 0x03;
    /// Mass Storage
    pub const MASS_STORAGE: u8 = 0x08;
    /// Hub
    pub const HUB: u8 = 0x09;
    /// Vendor-specific
    pub const VENDOR_SPECIFIC: u8 = 0xFF;
}

/// HID subclass codes
pub mod hid_subclass {
    /// No subclass
    pub const NONE: u8 = 0x00;
    /// Boot interface subclass
    pub const BOOT: u8 = 0x01;
}

/// HID protocol codes (for boot subclass)
pub mod hid_protocol {
    /// No specific protocol
    pub const NONE: u8 = 0x00;
    /// Keyboard
    pub const KEYBOARD: u8 = 0x01;
    /// Mouse
    pub const MOUSE: u8 = 0x02;
}

/// USB interface descriptor (standard 9-byte format)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct InterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_string: u8,
}

/// USB endpoint descriptor (standard 7-byte format)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct EndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointDescriptor {
    /// Check if this is an IN endpoint
    #[inline]
    pub const fn is_in(&self) -> bool {
        (self.endpoint_address & 0x80) != 0
    }

    /// Get the endpoint number (0-15)
    #[inline]
    pub const fn number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    /// Check if this is an interrupt endpoint
    #[inline]
    pub const fn is_interrupt(&self) -> bool {
        (self.attributes & 0x03) == 0x03
    }
}

/// Badge values for port change notifications
pub mod badge {
    /// Generate badge for port change notification
    pub const fn port_change(port: u8) -> u64 {
        0x1000 | (port as u64)
    }

    /// Extract port number from badge
    pub const fn port_from_badge(badge: u64) -> u8 {
        (badge & 0xFF) as u8
    }

    /// Check if badge is a port change notification
    pub const fn is_port_change(badge: u64) -> bool {
        (badge & 0xF000) == 0x1000
    }
}
