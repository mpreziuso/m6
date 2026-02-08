//! M6 Shell
//!
//! Interactive command shell for M6 userspace with keyboard input
//! via the HID driver.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use core::time::Duration;
use std::ipc::{ipc_set_recv_slots, Endpoint, IpcBuffer};
use std::{print, println, thread, String, Vec};

// -- Capability slots passed by init

/// Device-mgr registry endpoint slot (passed by init)
const REGISTRY_EP_SLOT: u64 = 10;

// -- Device-mgr IPC protocol

mod devmgr_ipc {
    /// Ensure a device/service driver is running
    pub const ENSURE: u64 = 0x0001;
    /// Class ID for USB HID driver
    pub const CLASS_USB_HID: u64 = 0x1001;
    /// Response: success
    pub const OK: u64 = 0;
}

// -- HID driver IPC protocol

mod hid_ipc {
    pub const SUBSCRIBE: u64 = 0x0001;
    pub const GET_EVENTS: u64 = 0x0003;
    pub const POLL_EVENTS: u64 = 0x0004;

    pub const OK: u64 = 0;

    pub mod device_type {
        pub const KEYBOARD: u64 = 1 << 0;
    }
}

// -- Key codes (Linux evdev compatible)

mod key {
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
    pub const KEY_SPACE: u16 = 57;
}

// -- Input event structure (matches HID driver's format)

#[repr(C)]
struct InputEvent {
    timestamp_ns: u64,
    event_type: u8,
    _reserved: u8,
    code: u16,
    value: i32,
}

impl InputEvent {
    /// Unpack from two u64 values (packed in IPC message)
    fn unpack(word0: u64, word1: u64) -> Self {
        Self {
            timestamp_ns: word0,
            event_type: (word1 & 0xFF) as u8,
            _reserved: ((word1 >> 8) & 0xFF) as u8,
            code: ((word1 >> 16) & 0xFFFF) as u16,
            value: (word1 >> 32) as i32,
        }
    }

    fn is_key_press(&self) -> bool {
        self.event_type == 1 && self.value == 1
    }
}

// -- Keyboard state

struct KeyboardState {
    shift_held: bool,
    caps_lock: bool,
}

impl KeyboardState {
    fn new() -> Self {
        Self {
            shift_held: false,
            caps_lock: false,
        }
    }

    fn update(&mut self, code: u16, pressed: bool) {
        if code == key::KEY_LEFTSHIFT || code == key::KEY_RIGHTSHIFT {
            self.shift_held = pressed;
        }
        // Note: caps lock toggle would go here at code 58
    }

    fn shift_active(&self) -> bool {
        self.shift_held ^ self.caps_lock
    }
}

/// Convert key code to character based on keyboard state
fn keycode_to_char(code: u16, kb_state: &KeyboardState) -> Option<char> {
    let shift = kb_state.shift_active();

    match code {
        key::KEY_A => Some(if shift { 'A' } else { 'a' }),
        key::KEY_B => Some(if shift { 'B' } else { 'b' }),
        key::KEY_C => Some(if shift { 'C' } else { 'c' }),
        key::KEY_D => Some(if shift { 'D' } else { 'd' }),
        key::KEY_E => Some(if shift { 'E' } else { 'e' }),
        key::KEY_F => Some(if shift { 'F' } else { 'f' }),
        key::KEY_G => Some(if shift { 'G' } else { 'g' }),
        key::KEY_H => Some(if shift { 'H' } else { 'h' }),
        key::KEY_I => Some(if shift { 'I' } else { 'i' }),
        key::KEY_J => Some(if shift { 'J' } else { 'j' }),
        key::KEY_K => Some(if shift { 'K' } else { 'k' }),
        key::KEY_L => Some(if shift { 'L' } else { 'l' }),
        key::KEY_M => Some(if shift { 'M' } else { 'm' }),
        key::KEY_N => Some(if shift { 'N' } else { 'n' }),
        key::KEY_O => Some(if shift { 'O' } else { 'o' }),
        key::KEY_P => Some(if shift { 'P' } else { 'p' }),
        key::KEY_Q => Some(if shift { 'Q' } else { 'q' }),
        key::KEY_R => Some(if shift { 'R' } else { 'r' }),
        key::KEY_S => Some(if shift { 'S' } else { 's' }),
        key::KEY_T => Some(if shift { 'T' } else { 't' }),
        key::KEY_U => Some(if shift { 'U' } else { 'u' }),
        key::KEY_V => Some(if shift { 'V' } else { 'v' }),
        key::KEY_W => Some(if shift { 'W' } else { 'w' }),
        key::KEY_X => Some(if shift { 'X' } else { 'x' }),
        key::KEY_Y => Some(if shift { 'Y' } else { 'y' }),
        key::KEY_Z => Some(if shift { 'Z' } else { 'z' }),

        key::KEY_1 => Some(if shift { '!' } else { '1' }),
        key::KEY_2 => Some(if shift { '@' } else { '2' }),
        key::KEY_3 => Some(if shift { '#' } else { '3' }),
        key::KEY_4 => Some(if shift { '$' } else { '4' }),
        key::KEY_5 => Some(if shift { '%' } else { '5' }),
        key::KEY_6 => Some(if shift { '^' } else { '6' }),
        key::KEY_7 => Some(if shift { '&' } else { '7' }),
        key::KEY_8 => Some(if shift { '*' } else { '8' }),
        key::KEY_9 => Some(if shift { '(' } else { '9' }),
        key::KEY_0 => Some(if shift { ')' } else { '0' }),

        key::KEY_SPACE => Some(' '),
        key::KEY_ENTER => Some('\n'),
        key::KEY_TAB => Some('\t'),
        key::KEY_BACKSPACE => Some('\x08'),

        key::KEY_MINUS => Some(if shift { '_' } else { '-' }),
        key::KEY_EQUAL => Some(if shift { '+' } else { '=' }),
        key::KEY_LEFTBRACE => Some(if shift { '{' } else { '[' }),
        key::KEY_RIGHTBRACE => Some(if shift { '}' } else { ']' }),
        key::KEY_BACKSLASH => Some(if shift { '|' } else { '\\' }),
        key::KEY_SEMICOLON => Some(if shift { ':' } else { ';' }),
        key::KEY_APOSTROPHE => Some(if shift { '"' } else { '\'' }),
        key::KEY_GRAVE => Some(if shift { '~' } else { '`' }),
        key::KEY_COMMA => Some(if shift { '<' } else { ',' }),
        key::KEY_DOT => Some(if shift { '>' } else { '.' }),
        key::KEY_SLASH => Some(if shift { '?' } else { '/' }),

        _ => None,
    }
}

/// Helper to create CPtr from slot
fn slot_to_cptr(slot: u64, radix: u8) -> u64 {
    slot << (64 - radix as u64)
}

/// Slot to receive the HID endpoint capability
const HID_EP_SLOT: u64 = 11;

/// Try to get HID driver endpoint via device-mgr ENSURE
fn try_get_hid_endpoint(cnode_radix: u8) -> Option<Endpoint> {
    let cptr = |slot: u64| slot_to_cptr(slot, cnode_radix);
    let registry_ep = Endpoint::from_cptr(cptr(REGISTRY_EP_SLOT));

    // Set up receive slot for capability transfer
    // Note: ipc_set_recv_slots expects slot NUMBERS, not CPtrs
    // SAFETY: IPC buffer is mapped at the standard userspace address
    unsafe {
        ipc_set_recv_slots(&[HID_EP_SLOT]);
    }

    // Send ENSURE request for USB HID class
    // The device-mgr will spawn the HID driver if not running
    // and return its endpoint via capability transfer
    let result = registry_ep
        .call(devmgr_ipc::ENSURE, [devmgr_ipc::CLASS_USB_HID, 0, 0, 0])
        .ok()?;

    if result.label == devmgr_ipc::OK {
        // Check if capability was received
        // SAFETY: IPC buffer is mapped
        let ipc_buf = unsafe { IpcBuffer::get() };
        if ipc_buf.recv_extra_caps > 0 {
            println!("Received HID endpoint capability");
        } else {
            println!("Warning: ENSURE succeeded but no cap received");
        }

        // The HID endpoint capability should now be in HID_EP_SLOT
        Some(Endpoint::from_cptr(cptr(HID_EP_SLOT)))
    } else {
        println!("ENSURE failed with code: {}", result.label);
        None
    }
}

/// Subscribe to keyboard events from HID driver
fn subscribe_keyboard(hid_ep: &Endpoint) -> Option<u64> {
    let result = hid_ep
        .call(hid_ipc::SUBSCRIBE, [hid_ipc::device_type::KEYBOARD, 0, 0, 0])
        .ok()?;

    // Response format: label = OK | (sub_id << 16)
    if (result.label & 0xFFFF) == hid_ipc::OK {
        Some(result.label >> 16)
    } else {
        None
    }
}

/// Poll for keyboard events
fn poll_keyboard_events(hid_ep: &Endpoint, sub_id: u64) -> Vec<InputEvent> {
    let mut events = Vec::new();

    // Poll for available events
    // Response format: label = OK | (count << 16)
    let result = match hid_ep.call(hid_ipc::POLL_EVENTS, [sub_id, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => return events,
    };

    // Check response code and extract count from upper bits
    if (result.label & 0xFFFF) != hid_ipc::OK {
        return events;
    }
    let count = (result.label >> 16) as usize;
    if count == 0 {
        return events;
    }

    // Get events (up to 2 per call due to IPC buffer limits)
    // Response format: label = (count << 16) | OK, events packed in msg[]
    let result = match hid_ep.call(hid_ipc::GET_EVENTS, [sub_id, 2, 0, 0]) {
        Ok(r) => r,
        Err(_) => return events,
    };

    let returned = (result.label >> 16) as usize;
    if returned >= 1 {
        events.push(InputEvent::unpack(result.msg[0], result.msg[1]));
    }
    if returned >= 2 {
        events.push(InputEvent::unpack(result.msg[2], result.msg[3]));
    }

    events
}

/// Execute a shell command
fn execute_command(cmd: &str) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    match parts[0] {
        "help" => {
            println!("Available commands:");
            println!("  help     - Show this help");
            println!("  echo     - Print arguments");
            println!("  clear    - Clear screen");
            println!("  version  - Show M6 version");
        }
        "echo" => {
            let args = parts[1..].join(" ");
            println!("{}", args);
        }
        "clear" => {
            // ANSI escape sequence to clear screen
            print!("\x1b[2J\x1b[H");
        }
        "version" => {
            println!("M6 Microkernel OS v0.1.0");
            println!("Shell v0.1");
        }
        _ => {
            println!("Unknown command: {}", parts[0]);
            println!("Type 'help' for available commands");
        }
    }
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    // Print banner
    println!("\n\x1b[36m=== M6 Shell v0.1 ===\x1b[0m");
    println!("Shell running in userspace (m6-std runtime)");

    // Get CNode radix from startup argument (passed by init via x0)
    let cnode_radix = std::rt::startup_arg() as u8;
    if cnode_radix == 0 {
        // Fallback to default if not provided
        println!("Warning: CNode radix not provided, defaulting to 10");
    }
    let cnode_radix = if cnode_radix == 0 { 10u8 } else { cnode_radix };

    // Try to get HID driver endpoint
    let hid_ep = try_get_hid_endpoint(cnode_radix);

    if hid_ep.is_none() {
        println!("No HID driver available - running in display-only mode");
        println!("(Keyboard input not supported)\n");
        print!("\x1b[32mm6>\x1b[0m ");

        // Idle loop without input
        loop {
            thread::sleep(Duration::from_millis(100));
        }
    }

    let hid_ep = hid_ep.unwrap();
    println!("HID driver connected");

    // Subscribe to keyboard events
    let sub_id = match subscribe_keyboard(&hid_ep) {
        Some(id) => {
            println!("Subscribed to keyboard events (id={})", id);
            id
        }
        None => {
            println!("Failed to subscribe to keyboard events");
            println!("Running in display-only mode\n");
            print!("\x1b[32mm6>\x1b[0m ");

            loop {
                thread::sleep(Duration::from_millis(100));
            }
        }
    };

    println!("Type 'help' for available commands\n");
    print!("\x1b[32mm6>\x1b[0m ");

    let mut line = String::new();
    let mut kb_state = KeyboardState::new();

    // Input loop
    loop {
        let events = poll_keyboard_events(&hid_ep, sub_id);

        for event in events {
            // Update modifier state
            let pressed = event.value == 1;
            kb_state.update(event.code, pressed);

            // Only process key presses (not releases)
            if !event.is_key_press() {
                continue;
            }

            if let Some(ch) = keycode_to_char(event.code, &kb_state) {
                match ch {
                    '\n' => {
                        println!();
                        execute_command(&line);
                        line.clear();
                        print!("\x1b[32mm6>\x1b[0m ");
                    }
                    '\x08' => {
                        // Backspace
                        if !line.is_empty() {
                            line.pop();
                            // Move cursor back, overwrite with space, move back again
                            print!("\x08 \x08");
                        }
                    }
                    _ => {
                        line.push(ch);
                        print!("{}", ch);
                    }
                }
            }
        }

        thread::yield_now();
    }
}
