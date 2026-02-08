//! Input event types and key codes for HID driver.
//!
//! Defines the InputEvent structure and associated constants for
//! keyboard and mouse input events. Key codes follow Linux evdev
//! conventions for compatibility.

/// Event type classification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    /// Synchronisation event (marks end of event batch)
    Syn = 0x00,
    /// Key press/release event
    Key = 0x01,
    /// Relative axis movement (mouse)
    Rel = 0x02,
    /// Absolute axis position (touchscreen, tablet)
    Abs = 0x03,
}

impl EventType {
    /// Convert from raw value
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Syn),
            0x01 => Some(Self::Key),
            0x02 => Some(Self::Rel),
            0x03 => Some(Self::Abs),
            _ => None,
        }
    }
}

/// Input event structure delivered to clients.
///
/// Designed to be ABI-compatible with Linux's input_event when packed.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct InputEvent {
    /// Timestamp in nanoseconds (from system monotonic clock)
    pub timestamp_ns: u64,
    /// Event type
    pub event_type: u8,
    /// Reserved for alignment
    pub _reserved: u8,
    /// Event code (key code, axis, etc.)
    pub code: u16,
    /// Event value (1=press, 0=release, or axis value)
    pub value: i32,
}

impl InputEvent {
    /// Create a new input event
    pub const fn new(event_type: EventType, code: u16, value: i32, timestamp_ns: u64) -> Self {
        Self {
            timestamp_ns,
            event_type: event_type as u8,
            _reserved: 0,
            code,
            value,
        }
    }

    /// Create a key press event
    pub const fn key_press(code: u16, timestamp_ns: u64) -> Self {
        Self::new(EventType::Key, code, 1, timestamp_ns)
    }

    /// Create a key release event
    pub const fn key_release(code: u16, timestamp_ns: u64) -> Self {
        Self::new(EventType::Key, code, 0, timestamp_ns)
    }

    /// Create a relative movement event
    pub const fn rel_move(axis: u16, delta: i32, timestamp_ns: u64) -> Self {
        Self::new(EventType::Rel, axis, delta, timestamp_ns)
    }

    /// Create a sync event (marks end of event batch)
    pub const fn sync(timestamp_ns: u64) -> Self {
        Self::new(EventType::Syn, SYN_REPORT, 0, timestamp_ns)
    }

    /// Get the event type
    pub fn event_type(&self) -> Option<EventType> {
        EventType::from_u8(self.event_type)
    }

    /// Pack the event into two u64 values for IPC transfer.
    ///
    /// Returns (word0, word1) where:
    /// - word0: timestamp_ns
    /// - word1: event_type | (_reserved << 8) | (code << 16) | (value << 32)
    pub fn pack(&self) -> (u64, u64) {
        let word0 = self.timestamp_ns;
        let word1 = (self.event_type as u64)
            | ((self._reserved as u64) << 8)
            | ((self.code as u64) << 16)
            | ((self.value as u64) << 32);
        (word0, word1)
    }
}

// -- Synchronisation codes

/// Report sync (end of event batch)
pub const SYN_REPORT: u16 = 0;

// -- Relative axis codes

/// X axis (horizontal movement)
pub const REL_X: u16 = 0x00;
/// Y axis (vertical movement)
pub const REL_Y: u16 = 0x01;
/// Wheel (vertical scroll)
pub const REL_WHEEL: u16 = 0x08;
/// Horizontal wheel
pub const REL_HWHEEL: u16 = 0x06;

// -- Button codes

/// Left mouse button
pub const BTN_LEFT: u16 = 0x110;
/// Right mouse button
pub const BTN_RIGHT: u16 = 0x111;
/// Middle mouse button
pub const BTN_MIDDLE: u16 = 0x112;
/// Side button 1
pub const BTN_SIDE: u16 = 0x113;
/// Side button 2
pub const BTN_EXTRA: u16 = 0x114;

// -- Key codes (Linux evdev compatible)
// Only commonly used keys are defined here

pub const KEY_RESERVED: u16 = 0;
pub const KEY_ESC: u16 = 1;
pub const KEY_1: u16 = 2;
pub const KEY_2: u16 = 3;
pub const KEY_3: u16 = 4;
pub const KEY_4: u16 = 5;
pub const KEY_5: u16 = 6;
pub const KEY_6: u16 = 7;
pub const KEY_7: u16 = 8;
pub const KEY_8: u16 = 9;
pub const KEY_9: u16 = 10;
pub const KEY_0: u16 = 11;
pub const KEY_MINUS: u16 = 12;
pub const KEY_EQUAL: u16 = 13;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_Q: u16 = 16;
pub const KEY_W: u16 = 17;
pub const KEY_E: u16 = 18;
pub const KEY_R: u16 = 19;
pub const KEY_T: u16 = 20;
pub const KEY_Y: u16 = 21;
pub const KEY_U: u16 = 22;
pub const KEY_I: u16 = 23;
pub const KEY_O: u16 = 24;
pub const KEY_P: u16 = 25;
pub const KEY_LEFTBRACE: u16 = 26;
pub const KEY_RIGHTBRACE: u16 = 27;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_A: u16 = 30;
pub const KEY_S: u16 = 31;
pub const KEY_D: u16 = 32;
pub const KEY_F: u16 = 33;
pub const KEY_G: u16 = 34;
pub const KEY_H: u16 = 35;
pub const KEY_J: u16 = 36;
pub const KEY_K: u16 = 37;
pub const KEY_L: u16 = 38;
pub const KEY_SEMICOLON: u16 = 39;
pub const KEY_APOSTROPHE: u16 = 40;
pub const KEY_GRAVE: u16 = 41;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_BACKSLASH: u16 = 43;
pub const KEY_Z: u16 = 44;
pub const KEY_X: u16 = 45;
pub const KEY_C: u16 = 46;
pub const KEY_V: u16 = 47;
pub const KEY_B: u16 = 48;
pub const KEY_N: u16 = 49;
pub const KEY_M: u16 = 50;
pub const KEY_COMMA: u16 = 51;
pub const KEY_DOT: u16 = 52;
pub const KEY_SLASH: u16 = 53;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_KPASTERISK: u16 = 55;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_F1: u16 = 59;
pub const KEY_F2: u16 = 60;
pub const KEY_F3: u16 = 61;
pub const KEY_F4: u16 = 62;
pub const KEY_F5: u16 = 63;
pub const KEY_F6: u16 = 64;
pub const KEY_F7: u16 = 65;
pub const KEY_F8: u16 = 66;
pub const KEY_F9: u16 = 67;
pub const KEY_F10: u16 = 68;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const KEY_KP7: u16 = 71;
pub const KEY_KP8: u16 = 72;
pub const KEY_KP9: u16 = 73;
pub const KEY_KPMINUS: u16 = 74;
pub const KEY_KP4: u16 = 75;
pub const KEY_KP5: u16 = 76;
pub const KEY_KP6: u16 = 77;
pub const KEY_KPPLUS: u16 = 78;
pub const KEY_KP1: u16 = 79;
pub const KEY_KP2: u16 = 80;
pub const KEY_KP3: u16 = 81;
pub const KEY_KP0: u16 = 82;
pub const KEY_KPDOT: u16 = 83;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_KPSLASH: u16 = 98;
pub const KEY_SYSRQ: u16 = 99;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_HOME: u16 = 102;
pub const KEY_UP: u16 = 103;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_END: u16 = 107;
pub const KEY_DOWN: u16 = 108;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_INSERT: u16 = 110;
pub const KEY_DELETE: u16 = 111;
pub const KEY_PAUSE: u16 = 119;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;
pub const KEY_COMPOSE: u16 = 127;

/// Convert USB HID usage ID (keyboard page) to Linux key code.
///
/// USB HID usage IDs are defined in the USB HID Usage Tables specification.
/// This table maps the common keyboard usages to Linux evdev key codes.
pub fn hid_to_keycode(usage: u8) -> u16 {
    // USB HID keyboard usage ID to Linux key code mapping
    // Based on USB HID Usage Tables 1.4, section 10 (Keyboard/Keypad Page)
    #[rustfmt::skip]
    const HID_TO_KEY: [u16; 256] = [
        KEY_RESERVED,   // 0x00 Reserved
        KEY_RESERVED,   // 0x01 ErrorRollOver
        KEY_RESERVED,   // 0x02 POSTFail
        KEY_RESERVED,   // 0x03 ErrorUndefined
        KEY_A,          // 0x04 a/A
        KEY_B,          // 0x05 b/B
        KEY_C,          // 0x06 c/C
        KEY_D,          // 0x07 d/D
        KEY_E,          // 0x08 e/E
        KEY_F,          // 0x09 f/F
        KEY_G,          // 0x0A g/G
        KEY_H,          // 0x0B h/H
        KEY_I,          // 0x0C i/I
        KEY_J,          // 0x0D j/J
        KEY_K,          // 0x0E k/K
        KEY_L,          // 0x0F l/L
        KEY_M,          // 0x10 m/M
        KEY_N,          // 0x11 n/N
        KEY_O,          // 0x12 o/O
        KEY_P,          // 0x13 p/P
        KEY_Q,          // 0x14 q/Q
        KEY_R,          // 0x15 r/R
        KEY_S,          // 0x16 s/S
        KEY_T,          // 0x17 t/T
        KEY_U,          // 0x18 u/U
        KEY_V,          // 0x19 v/V
        KEY_W,          // 0x1A w/W
        KEY_X,          // 0x1B x/X
        KEY_Y,          // 0x1C y/Y
        KEY_Z,          // 0x1D z/Z
        KEY_1,          // 0x1E 1/!
        KEY_2,          // 0x1F 2/@
        KEY_3,          // 0x20 3/#
        KEY_4,          // 0x21 4/$
        KEY_5,          // 0x22 5/%
        KEY_6,          // 0x23 6/^
        KEY_7,          // 0x24 7/&
        KEY_8,          // 0x25 8/*
        KEY_9,          // 0x26 9/(
        KEY_0,          // 0x27 0/)
        KEY_ENTER,      // 0x28 Enter
        KEY_ESC,        // 0x29 Escape
        KEY_BACKSPACE,  // 0x2A Backspace
        KEY_TAB,        // 0x2B Tab
        KEY_SPACE,      // 0x2C Space
        KEY_MINUS,      // 0x2D -/_
        KEY_EQUAL,      // 0x2E =/+
        KEY_LEFTBRACE,  // 0x2F [/{
        KEY_RIGHTBRACE, // 0x30 ]/}
        KEY_BACKSLASH,  // 0x31 \/|
        KEY_BACKSLASH,  // 0x32 Non-US #/~
        KEY_SEMICOLON,  // 0x33 ;/:
        KEY_APOSTROPHE, // 0x34 '/"
        KEY_GRAVE,      // 0x35 `/~
        KEY_COMMA,      // 0x36 ,/<
        KEY_DOT,        // 0x37 ./>
        KEY_SLASH,      // 0x38 //?
        KEY_CAPSLOCK,   // 0x39 Caps Lock
        KEY_F1,         // 0x3A F1
        KEY_F2,         // 0x3B F2
        KEY_F3,         // 0x3C F3
        KEY_F4,         // 0x3D F4
        KEY_F5,         // 0x3E F5
        KEY_F6,         // 0x3F F6
        KEY_F7,         // 0x40 F7
        KEY_F8,         // 0x41 F8
        KEY_F9,         // 0x42 F9
        KEY_F10,        // 0x43 F10
        KEY_F11,        // 0x44 F11
        KEY_F12,        // 0x45 F12
        KEY_SYSRQ,      // 0x46 PrintScreen
        KEY_SCROLLLOCK, // 0x47 Scroll Lock
        KEY_PAUSE,      // 0x48 Pause
        KEY_INSERT,     // 0x49 Insert
        KEY_HOME,       // 0x4A Home
        KEY_PAGEUP,     // 0x4B PageUp
        KEY_DELETE,     // 0x4C Delete Forward
        KEY_END,        // 0x4D End
        KEY_PAGEDOWN,   // 0x4E PageDown
        KEY_RIGHT,      // 0x4F Right Arrow
        KEY_LEFT,       // 0x50 Left Arrow
        KEY_DOWN,       // 0x51 Down Arrow
        KEY_UP,         // 0x52 Up Arrow
        KEY_NUMLOCK,    // 0x53 Num Lock
        KEY_KPSLASH,    // 0x54 Keypad /
        KEY_KPASTERISK, // 0x55 Keypad *
        KEY_KPMINUS,    // 0x56 Keypad -
        KEY_KPPLUS,     // 0x57 Keypad +
        KEY_KPENTER,    // 0x58 Keypad Enter
        KEY_KP1,        // 0x59 Keypad 1
        KEY_KP2,        // 0x5A Keypad 2
        KEY_KP3,        // 0x5B Keypad 3
        KEY_KP4,        // 0x5C Keypad 4
        KEY_KP5,        // 0x5D Keypad 5
        KEY_KP6,        // 0x5E Keypad 6
        KEY_KP7,        // 0x5F Keypad 7
        KEY_KP8,        // 0x60 Keypad 8
        KEY_KP9,        // 0x61 Keypad 9
        KEY_KP0,        // 0x62 Keypad 0
        KEY_KPDOT,      // 0x63 Keypad .
        KEY_BACKSLASH,  // 0x64 Non-US \/|
        KEY_COMPOSE,    // 0x65 Application
        KEY_RESERVED,   // 0x66 Power
        KEY_RESERVED,   // 0x67 Keypad =
        // F13-F24 and other extended keys
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x68-0x6B
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x6C-0x6F
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x70-0x73
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x74-0x77
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x78-0x7B
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x7C-0x7F
        // Remaining entries (0x80-0xFF)
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x80-0x83
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x84-0x87
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x88-0x8B
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x8C-0x8F
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x90-0x93
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x94-0x97
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x98-0x9B
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0x9C-0x9F
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xA0-0xA3
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xA4-0xA7
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xA8-0xAB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xAC-0xAF
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xB0-0xB3
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xB4-0xB7
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xB8-0xBB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xBC-0xBF
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xC0-0xC3
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xC4-0xC7
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xC8-0xCB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xCC-0xCF
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xD0-0xD3
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xD4-0xD7
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xD8-0xDB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xDC-0xDF
        // Modifier keys (0xE0-0xE7)
        KEY_LEFTCTRL,   // 0xE0 Left Control
        KEY_LEFTSHIFT,  // 0xE1 Left Shift
        KEY_LEFTALT,    // 0xE2 Left Alt
        KEY_LEFTMETA,   // 0xE3 Left GUI (Windows/Command)
        KEY_RIGHTCTRL,  // 0xE4 Right Control
        KEY_RIGHTSHIFT, // 0xE5 Right Shift
        KEY_RIGHTALT,   // 0xE6 Right Alt
        KEY_RIGHTMETA,  // 0xE7 Right GUI
        // Remaining entries (0xE8-0xFF)
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xE8-0xEB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xEC-0xEF
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xF0-0xF3
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xF4-0xF7
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xF8-0xFB
        KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, KEY_RESERVED, // 0xFC-0xFF
    ];

    HID_TO_KEY[usage as usize]
}

/// Modifier key bits (as they appear in boot protocol byte 0)
pub mod modifier {
    pub const LEFT_CTRL: u8 = 1 << 0;
    pub const LEFT_SHIFT: u8 = 1 << 1;
    pub const LEFT_ALT: u8 = 1 << 2;
    pub const LEFT_META: u8 = 1 << 3;
    pub const RIGHT_CTRL: u8 = 1 << 4;
    pub const RIGHT_SHIFT: u8 = 1 << 5;
    pub const RIGHT_ALT: u8 = 1 << 6;
    pub const RIGHT_META: u8 = 1 << 7;
}

/// Convert modifier bit to key code
pub fn modifier_to_keycode(modifier_bit: u8) -> u16 {
    match modifier_bit {
        modifier::LEFT_CTRL => KEY_LEFTCTRL,
        modifier::LEFT_SHIFT => KEY_LEFTSHIFT,
        modifier::LEFT_ALT => KEY_LEFTALT,
        modifier::LEFT_META => KEY_LEFTMETA,
        modifier::RIGHT_CTRL => KEY_RIGHTCTRL,
        modifier::RIGHT_SHIFT => KEY_RIGHTSHIFT,
        modifier::RIGHT_ALT => KEY_RIGHTALT,
        modifier::RIGHT_META => KEY_RIGHTMETA,
        _ => KEY_RESERVED,
    }
}
