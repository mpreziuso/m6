//! M6 cat
//!
//! Read a file from the FAT32 filesystem and print its contents to stdout.
//! Supports FAT32 8.3 filenames (up to 12 characters).

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::ipc::{Endpoint, call, ipc_set_recv_slots};
use std::{print, println};

const CNODE_RADIX: u8 = 12;
const REGISTRY_EP_SLOT: u64 = 10;
const FAT32_EP_SLOT: u64 = 12;

fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX as u64)
}

mod devmgr_ipc {
    pub const ENSURE: u64 = 0x0001;
    pub const CLASS_FAT32: u64 = 0x2001;
    pub const OK: u64 = 0;
}

mod fat32_ipc {
    pub const OPEN: u64 = 0x0200;
    pub const CLOSE: u64 = 0x0201;
    pub const READ: u64 = 0x0202;
    pub const OK: u64 = 0;
    pub const O_RDONLY: u64 = 0x0001;
}

fn get_fat32_ep() -> Option<Endpoint> {
    let registry_ep = Endpoint::from_cptr(cptr(REGISTRY_EP_SLOT));
    // SAFETY: IPC buffer is mapped at the standard userspace address
    unsafe {
        ipc_set_recv_slots(&[FAT32_EP_SLOT]);
    }
    let result = registry_ep
        .call(devmgr_ipc::ENSURE, [devmgr_ipc::CLASS_FAT32, 0, 0, 0])
        .ok()?;
    if result.label == devmgr_ipc::OK {
        Some(Endpoint::from_cptr(cptr(FAT32_EP_SLOT)))
    } else {
        None
    }
}

/// Pack up to 16 bytes of a path into two u64s, little-endian.
fn pack_path(path: &[u8]) -> (u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    for (i, &b) in path.iter().enumerate().take(8) {
        w0 |= (b as u64) << (i * 8);
    }
    for (i, &b) in path.iter().skip(8).enumerate().take(8) {
        w1 |= (b as u64) << (i * 8);
    }
    (w0, w1)
}

/// Unpack up to 24 bytes of inline data from three u64 reply words.
fn unpack_data(m0: u64, m1: u64, m2: u64, buf: &mut [u8]) {
    let n = buf.len().min(24);
    for (i, slot) in buf.iter_mut().enumerate().take(n.min(8)) {
        *slot = ((m0 >> (i * 8)) & 0xFF) as u8;
    }
    for (i, slot) in buf
        .iter_mut()
        .skip(8)
        .enumerate()
        .take(n.saturating_sub(8).min(8))
    {
        *slot = ((m1 >> (i * 8)) & 0xFF) as u8;
    }
    for (i, slot) in buf
        .iter_mut()
        .skip(16)
        .enumerate()
        .take(n.saturating_sub(16).min(8))
    {
        *slot = ((m2 >> (i * 8)) & 0xFF) as u8;
    }
}

/// Return argv[1] as a string slice, or None.
///
/// # Safety
///
/// startup_arg() must be 0 or a valid ARGS_PAGE_ADDR from the shell.
unsafe fn get_filename() -> Option<&'static str> {
    let args_ptr = std::rt::startup_arg();
    if args_ptr == 0 {
        return None;
    }
    // SAFETY: page mapped by shell with argc/argv layout
    let argc = unsafe { *(args_ptr as *const u64) };
    if argc < 2 {
        return None;
    }
    let ptr = unsafe { *((args_ptr + 16) as *const *const u8) };
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    Some(unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len)) })
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    // SAFETY: startup_arg() is 0 or valid ARGS_PAGE_ADDR from the shell
    let filename = match unsafe { get_filename() } {
        Some(s) => s,
        None => {
            println!("usage: cat <file>");
            return 1;
        }
    };

    let path_bytes = filename.as_bytes();
    if path_bytes.len() > 16 {
        println!("cat: filename too long (max 16 chars)");
        return 1;
    }

    let fat32_ep_cptr = match get_fat32_ep() {
        Some(ep) => ep.cptr(),
        None => {
            println!("cat: FAT32 service unavailable");
            return 1;
        }
    };

    // OPEN: msg0=path[0..7], msg1=path[8..15], msg2=flags|(path_len<<32)
    let (pw0, pw1) = pack_path(path_bytes);
    let flags_len = fat32_ipc::O_RDONLY | ((path_bytes.len() as u64) << 32);
    let open_result = match call(fat32_ep_cptr, fat32_ipc::OPEN, pw0, pw1, flags_len) {
        Ok(r) => r,
        Err(_) => {
            println!("cat: IPC error opening {}", filename);
            return 1;
        }
    };

    if open_result.label & 0xFFFF != fat32_ipc::OK {
        println!(
            "cat: {}: no such file (error {})",
            filename,
            open_result.label & 0xFFFF
        );
        return 1;
    }

    let handle = open_result.label >> 16;

    // READ loop — 24 bytes per call, inline in reply
    while let Ok(read_result) = call(fat32_ep_cptr, fat32_ipc::READ, handle, 24, 0) {
        if read_result.label & 0xFFFF != fat32_ipc::OK {
            break;
        }

        let bytes_read = ((read_result.label >> 16) & 0xFFFF) as usize;
        if bytes_read == 0 {
            break;
        }

        let mut buf = [0u8; 24];
        unpack_data(
            read_result.msg[0],
            read_result.msg[1],
            read_result.msg[2],
            &mut buf[..bytes_read],
        );

        match core::str::from_utf8(&buf[..bytes_read]) {
            Ok(s) => print!("{}", s),
            Err(_) => {
                for &b in &buf[..bytes_read] {
                    if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' {
                        print!("{}", b as char);
                    } else {
                        print!(".");
                    }
                }
            }
        }
    }

    let _ = call(fat32_ep_cptr, fat32_ipc::CLOSE, handle, 0, 0);
    0
}
