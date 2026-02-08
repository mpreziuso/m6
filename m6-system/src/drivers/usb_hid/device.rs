//! HID device state machine.
//!
//! Manages the state of discovered HID devices including device
//! enumeration, report parsing, and event generation.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::boot_keyboard::{BootKeyboardReport, BootKeyboardState};
use crate::boot_mouse::{BootMouseReport, BootMouseState};
use crate::input_event::InputEvent;

/// Maximum number of pending events per device
const MAX_PENDING_EVENTS: usize = 64;

/// Maximum report size (boot protocol uses 8 bytes max)
const MAX_REPORT_SIZE: usize = 8;

/// HID device type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidDeviceType {
    /// Boot protocol keyboard
    Keyboard,
    /// Boot protocol mouse
    Mouse,
    /// Unknown or unsupported HID device
    Unknown,
}

/// HID device configuration
#[derive(Clone, Copy, Debug)]
pub struct HidDeviceConfig {
    /// USB device address
    pub device_addr: u8,
    /// Interface number
    pub interface: u8,
    /// Interrupt IN endpoint address (with direction bit)
    pub endpoint_in: u8,
    /// Polling interval in milliseconds
    pub interval_ms: u8,
    /// Maximum packet size for the endpoint
    pub max_packet_size: u16,
    /// Device type (keyboard, mouse, etc.)
    pub device_type: HidDeviceType,
}

/// Report parser state (type-specific)
enum ReportParser {
    Keyboard(BootKeyboardState),
    Mouse(BootMouseState),
    None,
}

/// HID device state
pub struct HidDevice {
    /// Device configuration
    pub config: HidDeviceConfig,
    /// Report parser state
    parser: ReportParser,
    /// Pending events to deliver to clients
    pending_events: VecDeque<InputEvent>,
    /// Last report data (for change detection)
    last_report: [u8; MAX_REPORT_SIZE],
    /// Is interrupt polling active
    polling_active: bool,
}

impl HidDevice {
    /// Create a new HID device
    pub fn new(config: HidDeviceConfig) -> Self {
        let parser = match config.device_type {
            HidDeviceType::Keyboard => ReportParser::Keyboard(BootKeyboardState::new()),
            HidDeviceType::Mouse => ReportParser::Mouse(BootMouseState::new()),
            HidDeviceType::Unknown => ReportParser::None,
        };

        Self {
            config,
            parser,
            pending_events: VecDeque::with_capacity(MAX_PENDING_EVENTS),
            last_report: [0; MAX_REPORT_SIZE],
            polling_active: false,
        }
    }

    /// Process an incoming HID report.
    ///
    /// Parses the report and generates InputEvent entries.
    /// Returns the number of new events generated.
    pub fn process_report(&mut self, report: &[u8], timestamp_ns: u64) -> usize {
        // Skip if report is identical to last one
        let len = report.len().min(MAX_REPORT_SIZE);
        if &report[..len] == &self.last_report[..len] {
            return 0;
        }

        // Update last report
        self.last_report[..len].copy_from_slice(&report[..len]);

        // Parse report based on device type
        let mut events = [InputEvent::default(); 16];
        let count = match &mut self.parser {
            ReportParser::Keyboard(state) => {
                if let Some(kbd_report) = BootKeyboardReport::from_bytes(report) {
                    state.process_report(&kbd_report, timestamp_ns, &mut events)
                } else {
                    0
                }
            }
            ReportParser::Mouse(state) => {
                if let Some(mouse_report) = BootMouseReport::from_bytes(report) {
                    state.process_report(&mouse_report, timestamp_ns, &mut events)
                } else {
                    0
                }
            }
            ReportParser::None => 0,
        };

        // Add events to pending queue
        for event in events.iter().take(count) {
            if self.pending_events.len() < MAX_PENDING_EVENTS {
                self.pending_events.push_back(*event);
            }
        }

        // Add sync event if any events were generated
        if count > 0 && self.pending_events.len() < MAX_PENDING_EVENTS {
            self.pending_events.push_back(InputEvent::sync(timestamp_ns));
        }

        count
    }

    /// Get pending events, up to the specified count.
    ///
    /// Events are removed from the queue as they are returned.
    pub fn drain_events(&mut self, max_count: usize) -> Vec<InputEvent> {
        let count = self.pending_events.len().min(max_count);
        self.pending_events.drain(..count).collect()
    }

    /// Check if there are pending events
    pub fn has_pending_events(&self) -> bool {
        !self.pending_events.is_empty()
    }

    /// Get the number of pending events
    pub fn pending_event_count(&self) -> usize {
        self.pending_events.len()
    }

    /// Set polling state
    pub fn set_polling(&mut self, active: bool) {
        self.polling_active = active;
    }

    /// Check if polling is active
    pub fn is_polling(&self) -> bool {
        self.polling_active
    }

    /// Get device address
    pub fn device_addr(&self) -> u8 {
        self.config.device_addr
    }

    /// Get interface number
    pub fn interface(&self) -> u8 {
        self.config.interface
    }

    /// Get endpoint address
    pub fn endpoint(&self) -> u8 {
        self.config.endpoint_in
    }
}

/// HID device manager.
///
/// Manages multiple HID devices and routes reports to the appropriate device.
pub struct HidDeviceManager {
    /// List of active HID devices
    devices: Vec<HidDevice>,
}

impl HidDeviceManager {
    /// Create a new device manager
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Add a new HID device
    pub fn add_device(&mut self, config: HidDeviceConfig) -> usize {
        let device = HidDevice::new(config);
        self.devices.push(device);
        self.devices.len() - 1
    }

    /// Remove a device by index
    pub fn remove_device(&mut self, index: usize) -> Option<HidDevice> {
        if index < self.devices.len() {
            Some(self.devices.remove(index))
        } else {
            None
        }
    }

    /// Find device by USB address and endpoint
    pub fn find_device(&self, device_addr: u8, endpoint: u8) -> Option<usize> {
        self.devices
            .iter()
            .position(|d| d.config.device_addr == device_addr && d.config.endpoint_in == endpoint)
    }

    /// Get device by index
    pub fn get_device(&self, index: usize) -> Option<&HidDevice> {
        self.devices.get(index)
    }

    /// Get mutable device by index
    pub fn get_device_mut(&mut self, index: usize) -> Option<&mut HidDevice> {
        self.devices.get_mut(index)
    }

    /// Get device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Iterate over all devices
    pub fn devices(&self) -> impl Iterator<Item = &HidDevice> {
        self.devices.iter()
    }

    /// Iterate over all devices mutably
    pub fn devices_mut(&mut self) -> impl Iterator<Item = &mut HidDevice> {
        self.devices.iter_mut()
    }

    /// Process a report for a device.
    ///
    /// Returns the device index and event count if the device was found.
    pub fn process_report(
        &mut self,
        device_addr: u8,
        endpoint: u8,
        report: &[u8],
        timestamp_ns: u64,
    ) -> Option<(usize, usize)> {
        if let Some(idx) = self.find_device(device_addr, endpoint) {
            let count = self.devices[idx].process_report(report, timestamp_ns);
            Some((idx, count))
        } else {
            None
        }
    }

    /// Check if any device has pending events
    pub fn has_pending_events(&self) -> bool {
        self.devices.iter().any(|d| d.has_pending_events())
    }

    /// Get total pending event count across all devices
    pub fn total_pending_events(&self) -> usize {
        self.devices.iter().map(|d| d.pending_event_count()).sum()
    }
}

impl Default for HidDeviceManager {
    fn default() -> Self {
        Self::new()
    }
}
