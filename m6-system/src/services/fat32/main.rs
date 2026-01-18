//! FAT32 Filesystem Service
//!
//! Userspace service providing FAT32 filesystem operations via IPC.
//! Uses embedded-sdmmc for filesystem implementation and communicates
//! with the virtio-blk driver for block I/O.
//!
//! Capabilities received at spawn:
//! - Slot 12: Service endpoint for client requests
//! - Slot 30: Endpoint to virtio-blk driver
//! - Slot 31: Frame for block I/O data transfer

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod block;
mod error;
mod handles;
mod ipc;

// I/O module for console output
#[path = "../../io.rs"]
mod io;

use embedded_sdmmc::{Mode, ShortFileName, TimeSource, Timestamp, VolumeIdx, VolumeManager};
use m6_syscall::invoke::{map_frame, recv, reply_recv, sched_yield};

use block::IpcBlockDevice;
use error::FsError;
use handles::{HandleTable, HandleType};
use ipc::{flags, request, response};

// -- Well-known capability slots
// The service's CSpace has radix 10 (1024 slots).
// CPtrs are formatted as: slot << (64 - radix) = slot << 54

const CNODE_RADIX: u8 = 10;

/// Convert slot number to CPtr.
#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

/// Root VSpace capability (slot 2)
const ROOT_VSPACE: u64 = cptr(2);
/// Service endpoint for clients (slot 12)
const SERVICE_EP: u64 = cptr(12);
/// Endpoint to virtio-blk driver (slot 30)
const BLK_EP: u64 = cptr(30);
/// Frame for block I/O data (slot 31)
const DATA_FRAME: u64 = cptr(31);
/// Frame slot number (not CPtr) for block I/O
const DATA_FRAME_SLOT: u64 = 31;

/// Virtual address for data frame
const DATA_VADDR: u64 = 0x8002_0000;
/// Virtual address for path/data buffer
const PATH_VADDR: u64 = 0x8003_0000;

/// Null time source (returns fixed timestamp)
struct NullTimeSource;

impl TimeSource for NullTimeSource {
    fn get_timestamp(&self) -> Timestamp {
        // Return a fixed timestamp (2024-01-01 00:00:00)
        Timestamp {
            year_since_1970: 54,
            zero_indexed_month: 0,
            zero_indexed_day: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
        }
    }
}

/// Entry point for FAT32 filesystem service.
///
/// # Safety
///
/// Must be called only once as the entry point. The spawner must have
/// provided the required capabilities in well-known slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    io::puts("\n\x1b[36m[svc-fat32] Starting FAT32 filesystem service\x1b[0m\n");

    // Map the data frame for block I/O
    match map_frame(ROOT_VSPACE, DATA_FRAME, DATA_VADDR, 0b011, 0) {
        Ok(_) => {
            io::puts("[svc-fat32] Mapped data frame at ");
            io::put_hex(DATA_VADDR);
            io::newline();
        }
        Err(e) => {
            io::puts("[svc-fat32] ERROR: Failed to map data frame: ");
            io::put_u64(e as u64);
            io::newline();
            loop {
                sched_yield();
            }
        }
    }

    // Initialise block device
    let mut block_dev = IpcBlockDevice::new(BLK_EP, DATA_FRAME_SLOT, DATA_VADDR);
    if let Err(e) = block_dev.init() {
        io::puts("[svc-fat32] ERROR: Failed to init block device: ");
        io::puts(match e {
            block::BlockError::IpcError => "IPC error",
            block::BlockError::IoError => "I/O error",
            block::BlockError::NotReady => "Not ready",
        });
        io::newline();
        loop {
            sched_yield();
        }
    }

    io::puts("[svc-fat32] Block device: ");
    io::put_u64(block_dev.block_count() / 2048); // Convert sectors to MiB
    io::puts(" MiB\n");

    // Create volume manager
    let mut volume_mgr = VolumeManager::new(block_dev, NullTimeSource);

    // Open the first volume (partition 0)
    let volume = match volume_mgr.open_volume(VolumeIdx(0)) {
        Ok(v) => v,
        Err(e) => {
            io::puts("[svc-fat32] ERROR: Failed to open volume: ");
            io::puts(match e {
                embedded_sdmmc::Error::FormatError(_) => "Format error",
                embedded_sdmmc::Error::NoSuchVolume => "No such volume",
                _ => "Unknown error",
            });
            io::newline();
            loop {
                sched_yield();
            }
        }
    };

    io::puts("[svc-fat32] Volume opened successfully\n");

    // Get raw volume handle for passing around
    let raw_volume = volume.to_raw_volume();

    // Open root directory
    let root_dir = match volume_mgr.open_root_dir(raw_volume) {
        Ok(d) => d,
        Err(e) => {
            io::puts("[svc-fat32] ERROR: Failed to open root dir: ");
            io::puts(match e {
                embedded_sdmmc::Error::TooManyOpenDirs => "Too many open dirs",
                _ => "Unknown error",
            });
            io::newline();
            loop {
                sched_yield();
            }
        }
    };

    io::puts("[svc-fat32] Root directory opened\n");
    io::puts("[svc-fat32] Entering service loop\n");

    // Enter the service loop
    service_loop(&mut volume_mgr, raw_volume, root_dir);
}

/// Type alias for our volume manager
type VolMgr = VolumeManager<IpcBlockDevice, NullTimeSource, 4, 4, 1>;

/// Main service loop - handles client IPC requests.
fn service_loop(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    root_dir: embedded_sdmmc::RawDirectory,
) -> ! {
    let mut handles = HandleTable::new();

    // Store root directory handle
    let _ = handles.alloc_dir(root_dir, 0);

    // First message
    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                let resp = handle_request(
                    volume_mgr,
                    volume,
                    &mut handles,
                    ipc_result.badge,
                    ipc_result.label,
                    &ipc_result.msg,
                );

                // Reply and wait for next message
                result = reply_recv(SERVICE_EP, resp, 0, 0, 0);
            }
            Err(e) => {
                io::puts("[svc-fat32] IPC error: ");
                io::put_u64(e as u64);
                io::newline();
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    handles: &mut HandleTable,
    badge: u64,
    label: u64,
    msg: &[u64; 4],
) -> u64 {
    match label & 0xFFFF {
        request::OPEN => handle_open(volume_mgr, volume, handles, badge, msg),
        request::CLOSE => handle_close(volume_mgr, handles, badge, msg),
        request::READ => handle_read(volume_mgr, handles, badge, msg),
        request::WRITE => handle_write(volume_mgr, handles, badge, msg),
        request::MKDIR => handle_mkdir(volume_mgr, volume, badge, msg),
        request::UNLINK => handle_unlink(volume_mgr, volume, badge, msg),
        request::STAT_FS => handle_stat_fs(),
        _ => response::ERR_INVALID,
    }
}

/// Read path from the data buffer at PATH_VADDR.
fn read_path(path_len: u64) -> Option<&'static str> {
    if path_len == 0 || path_len > 255 {
        return None;
    }

    // SAFETY: PATH_VADDR is our mapped frame
    let bytes = unsafe {
        let ptr = PATH_VADDR as *const u8;
        core::slice::from_raw_parts(ptr, path_len as usize)
    };

    core::str::from_utf8(bytes).ok()
}

/// Handle OPEN request.
fn handle_open(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let open_flags = msg[0];
    let path_len = msg[1];

    let path = match read_path(path_len) {
        Some(p) => p,
        None => return response::ERR_INVALID,
    };

    // Open root directory first
    let root_dir = match volume_mgr.open_root_dir(volume) {
        Ok(d) => d,
        Err(e) => return FsError::from_sdmmc(e).to_response(),
    };

    // Parse filename (simplified - only supports root directory files)
    let filename = match ShortFileName::create_from_str(path) {
        Ok(f) => f,
        Err(_) => {
            let _ = volume_mgr.close_dir(root_dir);
            return response::ERR_INVALID;
        }
    };

    // Determine open mode
    let mode = if (open_flags & flags::O_CREATE) != 0 {
        Mode::ReadWriteCreateOrTruncate
    } else if (open_flags & flags::O_WRONLY) != 0 || (open_flags & flags::O_RDWR) != 0 {
        Mode::ReadWriteAppend
    } else {
        Mode::ReadOnly
    };

    // Open the file
    let file = match volume_mgr.open_file_in_dir(root_dir, filename, mode) {
        Ok(f) => f,
        Err(e) => {
            let _ = volume_mgr.close_dir(root_dir);
            return FsError::from_sdmmc(e).to_response();
        }
    };

    let _ = volume_mgr.close_dir(root_dir);

    // Allocate handle
    match handles.alloc_file(file, badge) {
        Some(handle) => response::OK | ((handle as u64) << 16),
        None => {
            let _ = volume_mgr.close_file(file);
            response::ERR_TOO_MANY_OPEN
        }
    }
}

/// Handle CLOSE request.
fn handle_close(
    volume_mgr: &mut VolMgr,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let handle = msg[0] as u32;

    // Try to take file handle
    if let Some(raw_file) = handles.take_file(handle, badge) {
        let _ = volume_mgr.close_file(raw_file);
        return response::OK;
    }

    // Try to take directory handle
    if let Some(raw_dir) = handles.take_dir(handle, badge) {
        let _ = volume_mgr.close_dir(raw_dir);
        return response::OK;
    }

    response::ERR_HANDLE_INVALID
}

/// Handle READ request.
fn handle_read(
    volume_mgr: &mut VolMgr,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let handle = msg[0] as u32;
    let max_bytes = msg[1] as usize;

    // Get handle entry
    let entry = match handles.get(handle, badge) {
        Some(e) if e.handle_type == HandleType::File => e,
        _ => return response::ERR_HANDLE_INVALID,
    };

    let raw_file = match entry.raw_file {
        Some(f) => f,
        None => return response::ERR_HANDLE_INVALID,
    };

    // Read into buffer
    let read_len = max_bytes.min(4096);
    let buf = unsafe {
        let ptr = PATH_VADDR as *mut u8;
        core::slice::from_raw_parts_mut(ptr, read_len)
    };

    match volume_mgr.read(raw_file, buf) {
        Ok(bytes_read) => response::OK | ((bytes_read as u64) << 16),
        Err(e) => FsError::from_sdmmc(e).to_response(),
    }
}

/// Handle WRITE request.
fn handle_write(
    volume_mgr: &mut VolMgr,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let handle = msg[0] as u32;
    let byte_count = msg[1] as usize;

    // Get handle entry
    let entry = match handles.get(handle, badge) {
        Some(e) if e.handle_type == HandleType::File => e,
        _ => return response::ERR_HANDLE_INVALID,
    };

    let raw_file = match entry.raw_file {
        Some(f) => f,
        None => return response::ERR_HANDLE_INVALID,
    };

    // Read data from buffer
    let write_len = byte_count.min(4096);
    let buf = unsafe {
        let ptr = PATH_VADDR as *const u8;
        core::slice::from_raw_parts(ptr, write_len)
    };

    match volume_mgr.write(raw_file, buf) {
        Ok(()) => response::OK | ((write_len as u64) << 16),
        Err(e) => FsError::from_sdmmc(e).to_response(),
    }
}

/// Handle MKDIR request.
fn handle_mkdir(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let path_len = msg[0];

    let path = match read_path(path_len) {
        Some(p) => p,
        None => return response::ERR_INVALID,
    };

    // Open root directory
    let root_dir = match volume_mgr.open_root_dir(volume) {
        Ok(d) => d,
        Err(e) => return FsError::from_sdmmc(e).to_response(),
    };

    // Parse filename
    let dirname = match ShortFileName::create_from_str(path) {
        Ok(f) => f,
        Err(_) => {
            let _ = volume_mgr.close_dir(root_dir);
            return response::ERR_INVALID;
        }
    };

    // Create directory
    let result = match volume_mgr.make_dir_in_dir(root_dir, dirname) {
        Ok(_) => response::OK,
        Err(e) => FsError::from_sdmmc(e).to_response(),
    };

    let _ = volume_mgr.close_dir(root_dir);
    result
}

/// Handle UNLINK request.
fn handle_unlink(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let path_len = msg[0];

    let path = match read_path(path_len) {
        Some(p) => p,
        None => return response::ERR_INVALID,
    };

    // Open root directory
    let root_dir = match volume_mgr.open_root_dir(volume) {
        Ok(d) => d,
        Err(e) => return FsError::from_sdmmc(e).to_response(),
    };

    // Parse filename
    let filename = match ShortFileName::create_from_str(path) {
        Ok(f) => f,
        Err(_) => {
            let _ = volume_mgr.close_dir(root_dir);
            return response::ERR_INVALID;
        }
    };

    // Delete file
    let result = match volume_mgr.delete_file_in_dir(root_dir, filename) {
        Ok(_) => response::OK,
        Err(e) => FsError::from_sdmmc(e).to_response(),
    };

    let _ = volume_mgr.close_dir(root_dir);
    result
}

/// Handle STAT_FS request.
fn handle_stat_fs() -> u64 {
    // Return basic OK - detailed stats not easily available
    response::OK
}

// Panic handler is provided by m6-std
