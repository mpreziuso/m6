//! mkfs-fat32 — format the NVMe drive as FAT32.
//!
//! Asks svc-fat32 (via device-mgr) to write FAT32 structures to the drive.
//! The drive is not mounted after formatting; the first filesystem operation
//! (e.g. ls) will trigger a lazy mount.

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::ipc::{ipc_set_recv_slots, Endpoint};
use std::println;

/// Slot holding the device-mgr registry endpoint (provided by init)
const REGISTRY_EP_SLOT: u64 = 10;
/// Slot into which we receive the FAT32 service endpoint
const FAT32_EP_SLOT: u64 = 12;

mod devmgr_ipc {
    pub const ENSURE: u64 = 0x0001;
    pub const CLASS_FAT32: u64 = 0x2001;
    pub const OK: u64 = 0;
}

mod fat32_ipc {
    pub const FORMAT: u64 = 0x0500;
    pub const OK: u64 = 0;
}

fn slot_to_cptr(slot: u64, radix: u8) -> u64 {
    slot << (64 - radix as u64)
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    let radix = std::rt::startup_arg() as u8;
    let radix = if radix == 0 { 10u8 } else { radix };
    let cptr = |slot: u64| slot_to_cptr(slot, radix);

    let registry_ep = Endpoint::from_cptr(cptr(REGISTRY_EP_SLOT));

    // Ask device-mgr to ensure svc-fat32 is running and hand us its endpoint.
    // SAFETY: IPC buffer is mapped at the standard userspace address.
    unsafe {
        ipc_set_recv_slots(&[FAT32_EP_SLOT]);
    }

    let result = match registry_ep.call(devmgr_ipc::ENSURE, [devmgr_ipc::CLASS_FAT32, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => {
            println!("mkfs-fat32: failed to contact device-mgr");
            return 1;
        }
    };

    if result.label != devmgr_ipc::OK {
        println!("mkfs-fat32: ENSURE failed ({})", result.label);
        return 1;
    }

    let fat32_ep = Endpoint::from_cptr(cptr(FAT32_EP_SLOT));

    // Request format.
    let result = match fat32_ep.call(fat32_ipc::FORMAT, [0, 0, 0, 0]) {
        Ok(r) => r,
        Err(_) => {
            println!("mkfs-fat32: IPC error calling FORMAT");
            return 1;
        }
    };

    if result.label & 0xFFFF == fat32_ipc::OK {
        println!("FAT32 format complete.");
        0
    } else {
        println!("mkfs-fat32: format failed (error {})", result.label & 0xFFFF);
        1
    }
}
