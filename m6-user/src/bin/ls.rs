//! M6 ls
//!
//! List the contents of the FAT32 root directory.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::ipc::{Endpoint, ipc_set_recv_slots};
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
    pub const OPENDIR: u64 = 0x0303;
    pub const READDIR: u64 = 0x0302;
    pub const CLOSEDIR: u64 = 0x0304;
    pub const OK: u64 = 0;
    pub const ERR_END_OF_DIR: u64 = 13;
    pub const ATTR_DIR: u8 = 0x10;
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

#[unsafe(no_mangle)]
fn main() -> i32 {
    let fat32_ep = match get_fat32_ep() {
        Some(ep) => ep,
        None => {
            println!("ls: FAT32 service unavailable");
            return 1;
        }
    };

    let open_result = match fat32_ep.call(fat32_ipc::OPENDIR, [0, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => {
            println!("ls: OPENDIR failed");
            return 1;
        }
    };

    if open_result.label & 0xFFFF != fat32_ipc::OK {
        println!("ls: OPENDIR error {}", open_result.label & 0xFFFF);
        return 1;
    }

    let handle = open_result.label >> 16;

    while let Ok(r) = fat32_ep.call(fat32_ipc::READDIR, [handle, 0, 0, 0]) {
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
        for (i, slot) in name_buf.iter_mut().enumerate().take(8usize.min(name_len)) {
            *slot = ((m1 >> (i * 8)) & 0xFF) as u8;
        }
        for (i, slot) in name_buf
            .iter_mut()
            .skip(8)
            .enumerate()
            .take(5usize.min(name_len.saturating_sub(8)))
        {
            *slot = ((m2 >> (i * 8)) & 0xFF) as u8;
        }

        let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("?");
        if attr & fat32_ipc::ATTR_DIR != 0 {
            println!("{}/\t<DIR>", name);
        } else {
            println!("{}\t{} bytes", name, size);
        }
    }

    let _ = fat32_ep.call(fat32_ipc::CLOSEDIR, [handle, 0, 0, 0]);
    0
}
