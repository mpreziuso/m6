//! M6 Shell
//!
//! Interactive command shell with quoted argument tokenisation and
//! external binary spawning from the initrd.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use core::time::Duration;
use std::ipc::{Endpoint, IpcBuffer, Notification, ipc_set_recv_slots, ipc_set_send_caps};
use std::{String, Vec, print, println, thread};

use m6_cap::ObjectType;
use m6_system::{invoke, slot_to_cptr};
use m6_system::process::{MapRights, SpawnConfig, ensure_child_page_tables, map_data_to_child,
                          spawn_process};

// -- Constants

const CNODE_RADIX: u8 = 12;

const REGISTRY_EP_SLOT: u64 = 10;
const HID_EP_SLOT: u64 = 11;
const FAT32_EP_SLOT: u64 = 12;
const ASID_POOL_SLOT: u64 = 13;
const MEM_SERVER_SLOT: u64 = 14;
const UNTYPED_SLOT: u64 = 15;
const FIRST_FREE_SLOT: u64 = 16;

const SHELL_INITRD_ADDR: u64 = m6_system::SHELL_INITRD_ADDR;
const ARGS_PAGE_ADDR: u64 = 0x3FFF_E000;

fn cptr(slot: u64) -> u64 {
    slot_to_cptr(slot, CNODE_RADIX)
}

// -- Shell context

struct ShellContext {
    next_slot: u64,
    ram_untyped: u64,
    initrd: &'static [u8],
    fat32_ep: Option<Endpoint>,
}

// -- Device-mgr IPC protocol

mod devmgr_ipc {
    pub const ENSURE: u64 = 0x0001;
    pub const CLASS_USB_HID: u64 = 0x1001;
    pub const CLASS_FAT32: u64 = 0x2001;
    pub const OK: u64 = 0;
}

// -- FAT32 service IPC protocol

mod fat32_ipc {
    pub const FORMAT: u64 = 0x0500;
    pub const OPENDIR: u64 = 0x0303;
    pub const READDIR: u64 = 0x0302;
    pub const CLOSEDIR: u64 = 0x0304;
    pub const OK: u64 = 0;
    pub const ERR_END_OF_DIR: u64 = 13;
    pub const ATTR_DIR: u8 = 0x10;
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
        Self { shift_held: false, caps_lock: false }
    }

    fn update(&mut self, code: u16, pressed: bool) {
        if code == key::KEY_LEFTSHIFT || code == key::KEY_RIGHTSHIFT {
            self.shift_held = pressed;
        }
    }

    fn shift_active(&self) -> bool {
        self.shift_held ^ self.caps_lock
    }
}

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

// -- Yield-based delay

fn yield_delay(duration: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        thread::yield_now();
    }
}

// -- Tokeniser

mod tokenizer {
    use core::prelude::rust_2024::derive;
    use std::{String, Vec};

    #[derive(Debug, PartialEq)]
    pub enum TokenError {
        UnclosedQuote,
        UnclosedEscape,
    }

    enum State {
        Normal,
        Escape,
        SingleQuote,
        DoubleQuote,
        DoubleEscape,
    }

    pub fn tokenize(input: &str) -> Result<Vec<String>, TokenError> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut state = State::Normal;

        for ch in input.chars() {
            match state {
                State::Normal => match ch {
                    '\\' => state = State::Escape,
                    '\'' => state = State::SingleQuote,
                    '"' => state = State::DoubleQuote,
                    c if c.is_whitespace() => {
                        if !current.is_empty() {
                            tokens.push(core::mem::take(&mut current));
                        }
                    }
                    c => current.push(c),
                },
                State::Escape => {
                    current.push(ch);
                    state = State::Normal;
                }
                State::SingleQuote => match ch {
                    '\'' => state = State::Normal,
                    c => current.push(c),
                },
                State::DoubleQuote => match ch {
                    '"' => state = State::Normal,
                    '\\' => state = State::DoubleEscape,
                    c => current.push(c),
                },
                State::DoubleEscape => {
                    match ch {
                        '"' | '\\' => current.push(ch),
                        c => {
                            current.push('\\');
                            current.push(c);
                        }
                    }
                    state = State::DoubleQuote;
                }
            }
        }

        match state {
            State::Normal => {
                if !current.is_empty() {
                    tokens.push(current);
                }
                Ok(tokens)
            }
            State::Escape => Err(TokenError::UnclosedEscape),
            State::SingleQuote | State::DoubleQuote | State::DoubleEscape => {
                Err(TokenError::UnclosedQuote)
            }
        }
    }
}

// -- HID/FAT32 helpers

fn try_get_hid_endpoint() -> Option<Endpoint> {
    let registry_ep = Endpoint::from_cptr(cptr(REGISTRY_EP_SLOT));

    // SAFETY: IPC buffer is mapped at the standard userspace address
    unsafe { ipc_set_recv_slots(&[HID_EP_SLOT]); }

    let result = registry_ep
        .call(devmgr_ipc::ENSURE, [devmgr_ipc::CLASS_USB_HID, 0, 0, 0])
        .ok()?;
    println!("[shell] Got HID ENSURE reply: label={:#x}", result.label);

    if result.label == devmgr_ipc::OK {
        // SAFETY: IPC buffer is mapped
        let ipc_buf = unsafe { IpcBuffer::get() };
        if ipc_buf.recv_extra_caps > 0 {
            println!("Received HID endpoint capability");
        } else {
            println!("Warning: ENSURE succeeded but no cap received");
        }
        Some(Endpoint::from_cptr(cptr(HID_EP_SLOT)))
    } else {
        println!("ENSURE failed with code: {}", result.label);
        None
    }
}

fn try_get_fat32_endpoint() -> Option<Endpoint> {
    let registry_ep = Endpoint::from_cptr(cptr(REGISTRY_EP_SLOT));

    // SAFETY: IPC buffer is mapped at the standard userspace address
    unsafe { ipc_set_recv_slots(&[FAT32_EP_SLOT]); }

    let result = registry_ep
        .call(devmgr_ipc::ENSURE, [devmgr_ipc::CLASS_FAT32, 0, 0, 0])
        .ok()?;

    if result.label == devmgr_ipc::OK {
        Some(Endpoint::from_cptr(cptr(FAT32_EP_SLOT)))
    } else {
        None
    }
}

fn get_fat32_ep(ctx: &mut ShellContext) -> Option<Endpoint> {
    if let Some(ep) = ctx.fat32_ep {
        return Some(ep);
    }
    let ep = try_get_fat32_endpoint()?;
    ctx.fat32_ep = Some(ep);
    Some(ep)
}

fn subscribe_keyboard(hid_ep: &Endpoint) -> Option<u64> {
    let result = hid_ep
        .call(hid_ipc::SUBSCRIBE, [hid_ipc::device_type::KEYBOARD, 0, 0, 0])
        .ok()?;

    if (result.label & 0xFFFF) == hid_ipc::OK {
        Some(result.label >> 16)
    } else {
        None
    }
}

fn poll_keyboard_events(hid_ep: &Endpoint, sub_id: u64) -> Vec<InputEvent> {
    let mut events = Vec::new();

    let result = match hid_ep.call(hid_ipc::POLL_EVENTS, [sub_id, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => return events,
    };

    if (result.label & 0xFFFF) != hid_ipc::OK {
        return events;
    }
    let count = (result.label >> 16) as usize;
    if count == 0 {
        return events;
    }

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

// -- Built-in commands

fn builtin_help() {
    println!("Available commands:");
    println!("  help         - Show this help");
    println!("  version      - Show M6 version");
    println!("  ls           - List root directory (FAT32 NVMe)");
    println!("  mkfs         - Format NVMe drive as FAT32");
    println!("  echo [args]  - Print arguments");
    println!("  clear        - Clear screen");
    println!("  exit [N]     - Exit with code N (default 0)");
    println!("  <name>       - Execute binary from initrd");
}

fn builtin_version() {
    println!("M6 Microkernel OS v0.1.0");
    println!("Shell v0.2");
}

fn cmd_ls(ctx: &mut ShellContext) {
    let fat32_ep = match get_fat32_ep(ctx) {
        Some(ep) => ep,
        None => {
            println!("ls: FAT32 service unavailable");
            return;
        }
    };

    let open_result = match fat32_ep.call(fat32_ipc::OPENDIR, [0, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => {
            println!("ls: OPENDIR failed");
            return;
        }
    };

    if open_result.label & 0xFFFF != fat32_ipc::OK {
        println!("ls: OPENDIR error {}", open_result.label & 0xFFFF);
        return;
    }

    let handle = open_result.label >> 16;

    loop {
        let r = match fat32_ep.call(fat32_ipc::READDIR, [handle, 0, 0, 0]) {
            Ok(r) => r,
            Err(_) => break,
        };

        if r.label & 0xFFFF == fat32_ipc::ERR_END_OF_DIR {
            break;
        }
        if r.label & 0xFFFF != fat32_ipc::OK {
            break;
        }

        let name_len = ((r.label >> 16) & 0xFF) as usize;
        let attr = ((r.label >> 32) & 0xFF) as u8;
        let size = r.msg[0];
        let m1 = r.msg[1];
        let m2 = r.msg[2];

        let mut name_buf = [0u8; 13];
        for i in 0..8usize.min(name_len) {
            name_buf[i] = ((m1 >> (i * 8)) & 0xFF) as u8;
        }
        for i in 0..5usize.min(name_len.saturating_sub(8)) {
            name_buf[8 + i] = ((m2 >> (i * 8)) & 0xFF) as u8;
        }

        let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("?");

        if attr & fat32_ipc::ATTR_DIR != 0 {
            println!("{}/\t<DIR>", name);
        } else {
            println!("{}\t{} bytes", name, size);
        }
    }

    let _ = fat32_ep.call(fat32_ipc::CLOSEDIR, [handle, 0, 0, 0]);
}

fn cmd_mkfs(ctx: &mut ShellContext) {
    let fat32_ep = match get_fat32_ep(ctx) {
        Some(ep) => ep,
        None => {
            println!("mkfs: FAT32 service unavailable");
            return;
        }
    };

    let result = match fat32_ep.call(fat32_ipc::FORMAT, [0, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => {
            println!("mkfs: IPC error");
            return;
        }
    };

    if result.label & 0xFFFF == fat32_ipc::OK {
        println!("FAT32 format complete.");
    } else {
        println!("mkfs: format failed (error {})", result.label & 0xFFFF);
    }
}

// -- External command spawning

/// Build an argv page: argc (u64) at offset 0, then N pointer u64s, then null-terminated strings.
/// Returns empty Vec when no args (not worth mapping a page).
fn build_argv_page(program: &str, args: &[String]) -> Vec<u8> {
    if args.is_empty() {
        return Vec::new();
    }

    // argv[0] = program name, argv[1..] = user-supplied args
    let all_args: Vec<&str> = core::iter::once(program)
        .chain(args.iter().map(|s| s.as_str()))
        .collect();

    let argc = all_args.len() as u64;
    let header_size = 8 + 8 * all_args.len(); // argc u64 + N pointer u64s

    // Collect string data and remember offsets within the string section
    let mut string_offsets: Vec<usize> = Vec::new();
    let mut string_data: Vec<u8> = Vec::new();
    for s in &all_args {
        string_offsets.push(string_data.len());
        string_data.extend_from_slice(s.as_bytes());
        string_data.push(0); // null terminator
    }

    let total = header_size + string_data.len();
    let page_size = total.div_ceil(4096) * 4096;
    let mut page: Vec<u8> = Vec::new();
    page.resize(page_size, 0u8);

    // Write argc
    page[0..8].copy_from_slice(&argc.to_le_bytes());

    // Write pointers (absolute VAs in child's address space)
    for (i, &str_off) in string_offsets.iter().enumerate() {
        let ptr = ARGS_PAGE_ADDR + (header_size + str_off) as u64;
        let slot = 8 + i * 8;
        page[slot..slot + 8].copy_from_slice(&ptr.to_le_bytes());
    }

    // Write string data
    page[header_size..header_size + string_data.len()].copy_from_slice(&string_data);

    page
}

/// Request a fresh RAM untyped from init's memory server.
/// On success, stores the new untyped in ctx.ram_untyped and returns true.
fn request_memory(ctx: &mut ShellContext) -> bool {
    let recv_slot = ctx.next_slot;
    ctx.next_slot += 1;
    // SAFETY: IPC buffer is always mapped for userspace processes
    unsafe { ipc_set_recv_slots(&[recv_slot]); }
    let mem_ep = Endpoint::from_cptr(cptr(MEM_SERVER_SLOT));
    match mem_ep.call(0, [0, 0, 0, 0]) {
        Ok(r) if r.label == 0 => {
            ctx.ram_untyped = recv_slot;
            true
        }
        _ => {
            ctx.next_slot -= 1;
            false
        }
    }
}

fn spawn_external(program: &str, args: &[String], ctx: &mut ShellContext) {
    // 1. Find ELF in initrd
    let Some(elf_data) = m6_system::find_in_initrd(ctx.initrd, program) else {
        println!("{}: command not found", program);
        return;
    };

    // 2. Allocate exit notification slot
    let notif_slot = ctx.next_slot;
    ctx.next_slot += 1;
    if invoke::retype(
        cptr(ctx.ram_untyped),
        ObjectType::Notification as u64,
        0,
        cptr(0), // root CNode self-ref at slot 0
        notif_slot,
        1,
    )
    .is_err()
    {
        ctx.next_slot -= 1;
        println!("{}: out of resources", program);
        return;
    }

    // 3. Build argv page
    let argv_data = build_argv_page(program, args);

    // 4. Spawn with resume: false so we can map argv and bind notification first.
    //    On memory failure, request a fresh untyped from init and retry once.
    let spawn_start = ctx.next_slot;
    let result = loop {
        let config = SpawnConfig {
            elf_data,
            root_cnode: 0,           // slot 0 = self-ref CNode
            cnode_radix: CNODE_RADIX,
            ram_untyped: ctx.ram_untyped,
            asid_pool: ASID_POOL_SLOT,
            next_free_slot: ctx.next_slot,
            initial_caps: &[],
            x0: if args.is_empty() { 0 } else { ARGS_PAGE_ADDR },
            resume: false,
        };
        match spawn_process(&config) {
            Ok(r) => break r,
            Err(_) => {
                // Skip past any partially-allocated slots from the failed attempt
                ctx.next_slot = spawn_start + 64;
                if request_memory(ctx) {
                    continue;
                }
                println!("{}: spawn failed (out of memory)", program);
                return;
            }
        }
    };
    ctx.next_slot = result.next_free_slot;

    // 5. Map argv page into child's VSpace
    if !argv_data.is_empty() {
        let _ = ensure_child_page_tables(
            0,
            CNODE_RADIX,
            result.vspace_slot,
            ctx.ram_untyped,
            &mut ctx.next_slot,
            ARGS_PAGE_ADDR,
            ARGS_PAGE_ADDR + 4096,
        );
        let _ = map_data_to_child(
            0,
            CNODE_RADIX,
            result.vspace_slot,
            ctx.ram_untyped,
            &mut ctx.next_slot,
            ARGS_PAGE_ADDR,
            &argv_data,
            MapRights::R,
        );
    }

    // 6. Bind exit notification to child TCB, then resume
    let notif_cptr = cptr(notif_slot);
    let tcb_cptr = cptr(result.tcb_slot);
    let _ = invoke::tcb_bind_notification(tcb_cptr, notif_cptr);
    let _ = invoke::tcb_resume(tcb_cptr);

    // 7. Block until child exits — the kernel signals the notification on tcb_exit
    let _ = invoke::wait(notif_cptr);
}

// -- Command dispatch

fn execute_line(tokens: &[String], ctx: &mut ShellContext) {
    if tokens.is_empty() {
        return;
    }
    match tokens[0].as_str() {
        "echo" => println!("{}", tokens[1..].join(" ")),
        "clear" => print!("\x1b[2J\x1b[H"),
        "help" => builtin_help(),
        "version" => builtin_version(),
        "exit" | "quit" => {
            let code = tokens.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
            std::process::exit(code);
        }
        "ls" => cmd_ls(ctx),
        "mkfs" => cmd_mkfs(ctx),
        name => spawn_external(name, &tokens[1..], ctx),
    }
}

// -- Entry point

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("\n\x1b[36m=== M6 Shell v0.2 ===\x1b[0m");

    let initrd_size = std::rt::startup_arg() as usize;

    // SAFETY: init mapped the initrd at SHELL_INITRD_ADDR before resuming us
    let initrd: &'static [u8] = if initrd_size > 0 {
        unsafe {
            core::slice::from_raw_parts(SHELL_INITRD_ADDR as *const u8, initrd_size)
        }
    } else {
        &[]
    };

    let mut ctx = ShellContext {
        next_slot: FIRST_FREE_SLOT,
        ram_untyped: UNTYPED_SLOT,
        initrd,
        fat32_ep: None,
    };

    let hid_ep = try_get_hid_endpoint();

    if hid_ep.is_none() {
        println!("No HID driver available - running in display-only mode\n");
        print!("\x1b[32mm6>\x1b[0m ");
        loop {
            yield_delay(Duration::from_millis(500));
        }
    }

    let hid_ep = hid_ep.unwrap();
    println!("HID driver connected");

    let input_notif = match Notification::create() {
        Ok(n) => n,
        Err(_) => {
            println!("Failed to create input notification");
            loop {
                yield_delay(Duration::from_millis(500));
            }
        }
    };

    // Transfer notification to HID driver during subscribe
    // SAFETY: IPC buffer is mapped and accessible
    unsafe { ipc_set_send_caps(&[input_notif.cptr()]); }

    let sub_id = match subscribe_keyboard(&hid_ep) {
        Some(id) => {
            // SAFETY: IPC buffer is mapped and accessible
            unsafe { IpcBuffer::get_mut().extra_caps = 0; }
            id
        }
        None => {
            // SAFETY: IPC buffer is mapped and accessible
            unsafe { IpcBuffer::get_mut().extra_caps = 0; }
            println!("Failed to subscribe to keyboard events\n");
            print!("\x1b[32mm6>\x1b[0m ");
            loop {
                yield_delay(Duration::from_millis(500));
            }
        }
    };

    println!("Type 'help' for available commands\n");
    print!("\x1b[32mm6>\x1b[0m ");

    let mut line = String::new();
    let mut kb_state = KeyboardState::new();

    let poll_interval = Duration::from_millis(16);
    loop {
        yield_delay(poll_interval);

        loop {
            let events = poll_keyboard_events(&hid_ep, sub_id);
            if events.is_empty() {
                break;
            }

            for event in events {
                let pressed = event.value == 1;
                kb_state.update(event.code, pressed);

                if !event.is_key_press() {
                    continue;
                }

                if let Some(ch) = keycode_to_char(event.code, &kb_state) {
                    match ch {
                        '\n' => {
                            println!();
                            match tokenizer::tokenize(&line) {
                                Ok(tokens) => execute_line(&tokens, &mut ctx),
                                Err(tokenizer::TokenError::UnclosedQuote) => {
                                    println!("syntax error: unclosed quote");
                                }
                                Err(tokenizer::TokenError::UnclosedEscape) => {
                                    println!("syntax error: trailing backslash");
                                }
                            }
                            line.clear();
                            print!("\x1b[32mm6>\x1b[0m ");
                        }
                        '\x08' => {
                            if !line.is_empty() {
                                line.pop();
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
        }
    }
}
