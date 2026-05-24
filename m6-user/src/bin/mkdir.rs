//! M6 mkdir
//!
//! Create a directory on the FAT32 filesystem.
//! Supports FAT32 8.3 directory names (up to 12 characters).

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::ipc::{Endpoint, call, ipc_set_recv_slots};
use std::println;

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
    pub const MKDIR: u64 = 0x0300;
    pub const OK: u64 = 0;
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

/// Return argv[1] as a string slice, or None.
///
/// # Safety
///
/// startup_arg() must be 0 or a valid ARGS_PAGE_ADDR from the shell.
unsafe fn get_dirname() -> Option<&'static str> {
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
    let dirname = match unsafe { get_dirname() } {
        Some(s) => s,
        None => {
            println!("usage: mkdir <dir>");
            return 1;
        }
    };

    let path_bytes = dirname.as_bytes();
    if path_bytes.len() > 16 {
        println!("mkdir: name too long (max 16 chars)");
        return 1;
    }

    let fat32_ep_cptr = match get_fat32_ep() {
        Some(ep) => ep.cptr(),
        None => {
            println!("mkdir: FAT32 service unavailable");
            return 1;
        }
    };

    // MKDIR: msg[0]=path[0..7], msg[1]=path[8..15], msg[2]=path_len
    let (pw0, pw1) = pack_path(path_bytes);
    let result = match call(
        fat32_ep_cptr,
        fat32_ipc::MKDIR,
        pw0,
        pw1,
        path_bytes.len() as u64,
    ) {
        Ok(r) => r,
        Err(_) => {
            println!("mkdir: IPC error");
            return 1;
        }
    };

    if result.label & 0xFFFF != fat32_ipc::OK {
        println!("mkdir: {}: error {}", dirname, result.label & 0xFFFF);
        return 1;
    }

    0
}
