//! Boot protocol keyboard report parser.
//!
//! Parses 8-byte boot protocol keyboard reports and generates
//! InputEvent sequences for key press/release events.

use crate::input_event::{
    hid_to_keycode, modifier, modifier_to_keycode, InputEvent, KEY_RESERVED,
};

/// Maximum number of simultaneous keys in boot protocol
const MAX_KEYS: usize = 6;

/// Boot protocol keyboard report (8 bytes).
///
/// Format:
/// - Byte 0: Modifier keys (Ctrl, Shift, Alt, Meta for left and right)
/// - Byte 1: Reserved (OEM use)
/// - Bytes 2-7: Up to 6 key codes (0x04-0xE7)
#[derive(Clone, Copy, Default)]
pub struct BootKeyboardReport {
    pub modifiers: u8,
    pub reserved: u8,
    pub keys: [u8; MAX_KEYS],
}

impl BootKeyboardReport {
    /// Parse from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        Some(Self {
            modifiers: bytes[0],
            reserved: bytes[1],
            keys: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]],
        })
    }

    /// Check if a specific modifier is pressed
    pub const fn has_modifier(&self, bit: u8) -> bool {
        (self.modifiers & bit) != 0
    }

    /// Check for rollover error (phantom keys)
    pub const fn is_rollover(&self) -> bool {
        // When too many keys are pressed, the keyboard sends 0x01 in all slots
        self.keys[0] == 0x01
    }

    /// Iterate over pressed key codes (non-zero, excluding rollover)
    pub fn pressed_keys(&self) -> impl Iterator<Item = u8> + '_ {
        self.keys
            .iter()
            .copied()
            .filter(|&k| k != 0 && k != 0x01)
    }
}

/// Boot keyboard state tracker.
///
/// Tracks the previous report to detect key press and release transitions.
pub struct BootKeyboardState {
    /// Previous report for delta comparison
    prev_report: BootKeyboardReport,
}

impl BootKeyboardState {
    /// Create a new keyboard state tracker
    pub const fn new() -> Self {
        Self {
            prev_report: BootKeyboardReport {
                modifiers: 0,
                reserved: 0,
                keys: [0; MAX_KEYS],
            },
        }
    }

    /// Process a new keyboard report and emit events.
    ///
    /// Returns an iterator of InputEvent for all state changes between
    /// the previous report and this one.
    pub fn process_report<'a>(
        &'a mut self,
        report: &'a BootKeyboardReport,
        timestamp_ns: u64,
        events: &mut [InputEvent],
    ) -> usize {
        if report.is_rollover() {
            // Ignore rollover reports
            return 0;
        }

        let mut count = 0;

        // Check modifier changes
        let modifier_bits = [
            modifier::LEFT_CTRL,
            modifier::LEFT_SHIFT,
            modifier::LEFT_ALT,
            modifier::LEFT_META,
            modifier::RIGHT_CTRL,
            modifier::RIGHT_SHIFT,
            modifier::RIGHT_ALT,
            modifier::RIGHT_META,
        ];

        for &bit in &modifier_bits {
            let was_pressed = (self.prev_report.modifiers & bit) != 0;
            let is_pressed = (report.modifiers & bit) != 0;

            if is_pressed && !was_pressed {
                // Modifier pressed
                if count < events.len() {
                    let keycode = modifier_to_keycode(bit);
                    events[count] = InputEvent::key_press(keycode, timestamp_ns);
                    count += 1;
                }
            } else if !is_pressed && was_pressed {
                // Modifier released
                if count < events.len() {
                    let keycode = modifier_to_keycode(bit);
                    events[count] = InputEvent::key_release(keycode, timestamp_ns);
                    count += 1;
                }
            }
        }

        // Check for released keys (in prev but not in current)
        for &prev_key in &self.prev_report.keys {
            if prev_key == 0 || prev_key == 0x01 {
                continue;
            }
            let still_pressed = report.keys.iter().any(|&k| k == prev_key);
            if !still_pressed {
                if count < events.len() {
                    let keycode = hid_to_keycode(prev_key);
                    if keycode != KEY_RESERVED {
                        events[count] = InputEvent::key_release(keycode, timestamp_ns);
                        count += 1;
                    }
                }
            }
        }

        // Check for newly pressed keys (in current but not in prev)
        for &curr_key in &report.keys {
            if curr_key == 0 || curr_key == 0x01 {
                continue;
            }
            let was_pressed = self.prev_report.keys.iter().any(|&k| k == curr_key);
            if !was_pressed {
                if count < events.len() {
                    let keycode = hid_to_keycode(curr_key);
                    if keycode != KEY_RESERVED {
                        events[count] = InputEvent::key_press(keycode, timestamp_ns);
                        count += 1;
                    }
                }
            }
        }

        // Update state
        self.prev_report = *report;

        count
    }
}

impl Default for BootKeyboardState {
    fn default() -> Self {
        Self::new()
    }
}
