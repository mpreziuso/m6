//! M6 cp
//!
//! Copy a file on the FAT32 filesystem.
//! Supports FAT32 8.3 filenames (up to 12 characters).

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
    pub const OPEN: u64 = 0x0200;
    pub const CLOSE: u64 = 0x0201;
    pub const READ: u64 = 0x0202;
    pub const WRITE: u64 = 0x0203;
    pub const OK: u64 = 0;
    pub const O_RDONLY: u64 = 0x0001;
    pub const O_WRONLY: u64 = 0x0002;
    pub const O_CREATE: u64 = 0x0100;
    pub const O_TRUNC: u64 = 0x0200;
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

/// Parse two arguments (argv[1] and argv[2]) from the startup args page.
///
/// # Safety
///
/// startup_arg() must be 0 or a valid ARGS_PAGE_ADDR from the shell.
unsafe fn get_args() -> Option<(&'static str, &'static str)> {
    let args_ptr = std::rt::startup_arg();
    if args_ptr == 0 {
        return None;
    }
    // SAFETY: page mapped by shell with argc/argv layout
    let argc = unsafe { *(args_ptr as *const u64) };
    if argc < 3 {
        return None;
    }

    let ptr1 = unsafe { *((args_ptr + 16) as *const *const u8) };
    let ptr2 = unsafe { *((args_ptr + 24) as *const *const u8) };
    if ptr1.is_null() || ptr2.is_null() {
        return None;
    }

    let mut len1 = 0usize;
    while unsafe { *ptr1.add(len1) } != 0 {
        len1 += 1;
    }
    let mut len2 = 0usize;
    while unsafe { *ptr2.add(len2) } != 0 {
        len2 += 1;
    }

    let s1 = unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr1, len1)) };
    let s2 = unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr2, len2)) };
    Some((s1, s2))
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    // SAFETY: startup_arg() is 0 or valid ARGS_PAGE_ADDR from the shell
    let (src, dst) = match unsafe { get_args() } {
        Some(pair) => pair,
        None => {
            println!("usage: cp <src> <dst>");
            return 1;
        }
    };

    let src_bytes = src.as_bytes();
    let dst_bytes = dst.as_bytes();
    if src_bytes.len() > 16 {
        println!("cp: source filename too long (max 16 chars)");
        return 1;
    }
    if dst_bytes.len() > 16 {
        println!("cp: destination filename too long (max 16 chars)");
        return 1;
    }

    let fat32_ep_cptr = match get_fat32_ep() {
        Some(ep) => ep.cptr(),
        None => {
            println!("cp: FAT32 service unavailable");
            return 1;
        }
    };

    // Open source file read-only
    let (pw0, pw1) = pack_path(src_bytes);
    let flags_len = fat32_ipc::O_RDONLY | ((src_bytes.len() as u64) << 32);
    let open_src = match call(fat32_ep_cptr, fat32_ipc::OPEN, pw0, pw1, flags_len) {
        Ok(r) => r,
        Err(_) => {
            println!("cp: IPC error opening {}", src);
            return 1;
        }
    };
    if open_src.label & 0xFFFF != fat32_ipc::OK {
        println!(
            "cp: {}: no such file (error {})",
            src,
            open_src.label & 0xFFFF
        );
        return 1;
    }
    let handle_src = open_src.label >> 16;

    // Open destination file for writing (create/truncate)
    let (pw0, pw1) = pack_path(dst_bytes);
    let flags_len = (fat32_ipc::O_WRONLY | fat32_ipc::O_CREATE | fat32_ipc::O_TRUNC)
        | ((dst_bytes.len() as u64) << 32);
    let open_dst = match call(fat32_ep_cptr, fat32_ipc::OPEN, pw0, pw1, flags_len) {
        Ok(r) => r,
        Err(_) => {
            let _ = call(fat32_ep_cptr, fat32_ipc::CLOSE, handle_src, 0, 0);
            println!("cp: IPC error opening {}", dst);
            return 1;
        }
    };
    if open_dst.label & 0xFFFF != fat32_ipc::OK {
        let _ = call(fat32_ep_cptr, fat32_ipc::CLOSE, handle_src, 0, 0);
        println!(
            "cp: {}: cannot create (error {})",
            dst,
            open_dst.label & 0xFFFF
        );
        return 1;
    }
    let handle_dst = open_dst.label >> 16;

    // Copy loop — 16 bytes per iteration (matches WRITE inline capacity)
    let mut failed = false;
    loop {
        let read_result = match call(fat32_ep_cptr, fat32_ipc::READ, handle_src, 16, 0) {
            Ok(r) => r,
            Err(_) => {
                failed = true;
                break;
            }
        };

        if read_result.label & 0xFFFF != fat32_ipc::OK {
            break;
        }

        let bytes_read = ((read_result.label >> 16) & 0xFFFF) as usize;
        if bytes_read == 0 {
            break;
        }

        // Data words from READ reply pass directly to WRITE
        let data_w0 = read_result.msg[0];
        let data_w1 = read_result.msg[1];
        let write_arg = handle_dst | ((bytes_read as u64) << 32);

        let write_result = match call(fat32_ep_cptr, fat32_ipc::WRITE, data_w0, data_w1, write_arg)
        {
            Ok(r) => r,
            Err(_) => {
                failed = true;
                break;
            }
        };

        if write_result.label & 0xFFFF != fat32_ipc::OK {
            println!("cp: write error {}", write_result.label & 0xFFFF);
            failed = true;
            break;
        }
    }

    let _ = call(fat32_ep_cptr, fat32_ipc::CLOSE, handle_src, 0, 0);
    let _ = call(fat32_ep_cptr, fat32_ipc::CLOSE, handle_dst, 0, 0);

    if failed { 1 } else { 0 }
}
