//! Boot protocol mouse report parser.
//!
//! Parses 3-4 byte boot protocol mouse reports and generates
//! InputEvent sequences for button and movement events.

use crate::input_event::{InputEvent, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, REL_WHEEL, REL_X, REL_Y};

/// Boot protocol mouse report (3-4 bytes).
///
/// Format:
/// - Byte 0: Button bitmap (bit 0=left, bit 1=right, bit 2=middle)
/// - Byte 1: X displacement (signed 8-bit)
/// - Byte 2: Y displacement (signed 8-bit)
/// - Byte 3: Wheel displacement (signed 8-bit, optional)
#[derive(Clone, Copy, Default)]
pub struct BootMouseReport {
    pub buttons: u8,
    pub x: i8,
    pub y: i8,
    pub wheel: i8,
}

impl BootMouseReport {
    /// Parse from raw bytes (minimum 3 bytes, optionally 4)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        Some(Self {
            buttons: bytes[0],
            x: bytes[1] as i8,
            y: bytes[2] as i8,
            wheel: if bytes.len() >= 4 {
                bytes[3] as i8
            } else {
                0
            },
        })
    }

    /// Check if left button is pressed
    pub const fn left_button(&self) -> bool {
        (self.buttons & 0x01) != 0
    }

    /// Check if right button is pressed
    pub const fn right_button(&self) -> bool {
        (self.buttons & 0x02) != 0
    }

    /// Check if middle button is pressed
    pub const fn middle_button(&self) -> bool {
        (self.buttons & 0x04) != 0
    }
}

/// Button bit definitions
mod button {
    pub const LEFT: u8 = 0x01;
    pub const RIGHT: u8 = 0x02;
    pub const MIDDLE: u8 = 0x04;
}

/// Boot mouse state tracker.
///
/// Tracks the previous button state to detect press and release transitions.
pub struct BootMouseState {
    /// Previous button state for delta comparison
    prev_buttons: u8,
}

impl BootMouseState {
    /// Create a new mouse state tracker
    pub const fn new() -> Self {
        Self { prev_buttons: 0 }
    }

    /// Process a new mouse report and emit events.
    ///
    /// Returns the number of events written to the buffer.
    pub fn process_report(
        &mut self,
        report: &BootMouseReport,
        timestamp_ns: u64,
        events: &mut [InputEvent],
    ) -> usize {
        let mut count = 0;

        // Check button changes
        let button_defs = [
            (button::LEFT, BTN_LEFT),
            (button::RIGHT, BTN_RIGHT),
            (button::MIDDLE, BTN_MIDDLE),
        ];

        for &(bit, code) in &button_defs {
            let was_pressed = (self.prev_buttons & bit) != 0;
            let is_pressed = (report.buttons & bit) != 0;

            if is_pressed && !was_pressed {
                // Button pressed
                if count < events.len() {
                    events[count] = InputEvent::key_press(code, timestamp_ns);
                    count += 1;
                }
            } else if !is_pressed && was_pressed {
                // Button released
                if count < events.len() {
                    events[count] = InputEvent::key_release(code, timestamp_ns);
                    count += 1;
                }
            }
        }

        // Emit movement events (only if non-zero)
        if report.x != 0 && count < events.len() {
            events[count] = InputEvent::rel_move(REL_X, report.x as i32, timestamp_ns);
            count += 1;
        }

        if report.y != 0 && count < events.len() {
            events[count] = InputEvent::rel_move(REL_Y, report.y as i32, timestamp_ns);
            count += 1;
        }

        if report.wheel != 0 && count < events.len() {
            events[count] = InputEvent::rel_move(REL_WHEEL, report.wheel as i32, timestamp_ns);
            count += 1;
        }

        // Update state
        self.prev_buttons = report.buttons;

        count
    }
}

impl Default for BootMouseState {
    fn default() -> Self {
        Self::new()
    }
}
