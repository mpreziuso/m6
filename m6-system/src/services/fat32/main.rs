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
mod format;
mod handles;
mod ipc;

// I/O module for console output
#[path = "../../io.rs"]
mod io;

#[path = "../../logger.rs"]
mod logger;

use embedded_sdmmc::{Mode, ShortFileName, TimeSource, Timestamp, VolumeIdx, VolumeManager};
use m6_syscall::invoke::{map_frame, recv, reply_recv, sched_yield};

use block::IpcBlockDevice;
use error::FsError;
use handles::{DirCache, HandleTable, HandleType, MAX_DIR_ENTRIES};
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

/// Virtual address for block I/O data frame
const DATA_VADDR: u64 = 0x8002_0000;

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
    logger::init("svc-fat32");
    log::debug!("Starting FAT32 filesystem service");

    // Initialise the heap allocator (needed for Box in handle_opendir)
    rt::init_allocator();

    // Map the data frame for block I/O
    match map_frame(ROOT_VSPACE, DATA_FRAME, DATA_VADDR, 0b011, 0) {
        Ok(_) => {
            log::debug!("Mapped data frame at {:#x}", DATA_VADDR);
        }
        Err(e) => {
            log::error!("Failed to map data frame: {}", e as u64);
            loop {
                sched_yield();
            }
        }
    }

    // Initialise block device
    let mut block_dev = IpcBlockDevice::new(BLK_EP, DATA_FRAME, DATA_VADDR);
    if let Err(e) = block_dev.init() {
        log::error!(
            "Failed to init block device: {}",
            match e {
                block::BlockError::IpcError => "IPC error",
                block::BlockError::IoError => "I/O error",
                block::BlockError::NotReady => "Not ready",
            }
        );
        loop {
            sched_yield();
        }
    }

    log::debug!("Block device: {} MiB", block_dev.block_count() / 2048);

    // IpcBlockDevice is Copy — keep a copy for the formatter before moving into VolumeManager.
    let fmt_dev = block_dev;

    // Create volume manager (consumes a copy of block_dev; fmt_dev remains valid)
    let mut volume_mgr = VolumeManager::new(block_dev, NullTimeSource);

    // Skip initial mount — the service loop handles lazy mounting on first request.
    // This avoids a noisy "Invalid MBR signature" error when the drive is unformatted.
    log::debug!("Entering service loop");

    service_loop(&mut volume_mgr, None, fmt_dev);
}

/// Attempt to open the first FAT32 volume.  Returns the raw handle on success.
fn try_mount(volume_mgr: &mut VolMgr) -> Option<embedded_sdmmc::RawVolume> {
    match volume_mgr.open_volume(VolumeIdx(0)) {
        Ok(vol) => Some(vol.to_raw_volume()),
        Err(e) => {
            let desc = match e {
                embedded_sdmmc::Error::DeviceError(block::BlockError::IpcError) => "IPC error",
                embedded_sdmmc::Error::DeviceError(block::BlockError::IoError) => "I/O error",
                embedded_sdmmc::Error::DeviceError(block::BlockError::NotReady) => "Not ready",
                embedded_sdmmc::Error::FormatError(msg) => msg,
                embedded_sdmmc::Error::NoSuchVolume => "NoSuchVolume",
                embedded_sdmmc::Error::FilenameError(_) => "FilenameError",
                _ => "Other",
            };
            log::debug!("Mount: {}", desc);
            None
        }
    }
}

/// Type alias for our volume manager
type VolMgr = VolumeManager<IpcBlockDevice, NullTimeSource, 4, 4, 1>;

/// Main service loop — handles client IPC requests.
///
/// Supports FORMAT before the volume is mounted (lazy-mounting on first FS op).
fn service_loop(
    volume_mgr: &mut VolMgr,
    initial_volume: Option<embedded_sdmmc::RawVolume>,
    fmt_dev: IpcBlockDevice,
) -> ! {
    let mut handles = HandleTable::new();
    let mut raw_volume = initial_volume;

    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                let (resp, m0, m1, m2) = if ipc_result.label & 0xFFFF == request::FORMAT {
                    match format::format_volume(&fmt_dev) {
                        Ok(()) => {
                            // Rebuild the VolumeManager to discard any cached stale sectors
                            // from the pre-format state, so lazy mount succeeds on the next
                            // filesystem operation.
                            *volume_mgr = VolumeManager::new(fmt_dev, NullTimeSource);
                            raw_volume = None;
                            (response::OK, 0, 0, 0)
                        }
                        Err(_) => {
                            log::error!("Format failed");
                            (response::ERR_IO, 0, 0, 0)
                        }
                    }
                } else {
                    // Lazy mount: attempt on first FS operation after format or initial failure.
                    if raw_volume.is_none() {
                        raw_volume = try_mount(volume_mgr);
                        if raw_volume.is_some() {
                            log::debug!("Volume mounted (lazy)");
                        }
                    }
                    if let Some(vol) = raw_volume {
                        handle_request(
                            volume_mgr,
                            vol,
                            &mut handles,
                            ipc_result.badge,
                            ipc_result.label,
                            &ipc_result.msg,
                        )
                    } else {
                        (response::ERR_NOT_MOUNTED, 0, 0, 0)
                    }
                };

                result = reply_recv(SERVICE_EP, resp, m0, m1, m2);
            }
            Err(e) => {
                log::error!("IPC error: {}", e as u64);
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request.
/// Returns (label, m0, m1, m2) for reply_recv.
fn handle_request(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    handles: &mut HandleTable,
    badge: u64,
    label: u64,
    msg: &[u64; 4],
) -> (u64, u64, u64, u64) {
    match label & 0xFFFF {
        request::OPEN => (
            handle_open(volume_mgr, volume, handles, badge, msg),
            0,
            0,
            0,
        ),
        request::CLOSE => (handle_close(volume_mgr, handles, badge, msg), 0, 0, 0),
        request::READ => handle_read(volume_mgr, handles, badge, msg),
        request::WRITE => (handle_write(volume_mgr, handles, badge, msg), 0, 0, 0),
        request::MKDIR => (handle_mkdir(volume_mgr, volume, badge, msg), 0, 0, 0),
        request::UNLINK => (handle_unlink(volume_mgr, volume, badge, msg), 0, 0, 0),
        request::STAT_FS => (handle_stat_fs(), 0, 0, 0),
        request::OPENDIR => handle_opendir(volume_mgr, volume, handles, badge),
        request::READDIR => handle_readdir(handles, badge, msg),
        request::CLOSEDIR => (handle_closedir(handles, badge, msg), 0, 0, 0),
        _ => (response::ERR_INVALID, 0, 0, 0),
    }
}

/// Unpack an inline path from two message words (up to 16 bytes).
#[allow(clippy::needless_range_loop)]
fn unpack_path_inline(w0: u64, w1: u64, path_len: usize) -> Option<[u8; 16]> {
    if path_len == 0 || path_len > 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    for i in 0..8.min(path_len) {
        buf[i] = ((w0 >> (i * 8)) & 0xFF) as u8;
    }
    for i in 0..8.min(path_len.saturating_sub(8)) {
        buf[8 + i] = ((w1 >> (i * 8)) & 0xFF) as u8;
    }
    Some(buf)
}

/// Pack up to 24 bytes into three u64s for inline READ reply.
#[allow(clippy::needless_range_loop)]
fn pack_data_reply(buf: &[u8]) -> (u64, u64, u64) {
    let mut m0 = 0u64;
    let mut m1 = 0u64;
    let mut m2 = 0u64;
    for i in 0..8.min(buf.len()) {
        m0 |= (buf[i] as u64) << (i * 8);
    }
    for i in 0..8.min(buf.len().saturating_sub(8)) {
        m1 |= (buf[8 + i] as u64) << (i * 8);
    }
    for i in 0..8.min(buf.len().saturating_sub(16)) {
        m2 |= (buf[16 + i] as u64) << (i * 8);
    }
    (m0, m1, m2)
}

/// Handle OPEN request (inline path).
///
/// Message format:
/// - msg[0]: path bytes [0..7] packed little-endian
/// - msg[1]: path bytes [8..15] packed little-endian
/// - msg[2]: flags (low 32 bits) | path_len (high 32 bits)
///
/// Response label: `OK | (handle << 16)`
fn handle_open(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let open_flags = msg[2] & 0xFFFF_FFFF;
    let path_len = (msg[2] >> 32) as usize;

    let path_buf = match unpack_path_inline(msg[0], msg[1], path_len) {
        Some(b) => b,
        None => return response::ERR_INVALID,
    };
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return response::ERR_INVALID,
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

/// Handle READ request (inline data reply).
///
/// Message format:
/// - msg[0]: file handle
/// - msg[1]: max bytes to read (≤ 24)
///
/// Response: `OK | (bytes_read << 16)` with data packed into reply m0/m1/m2.
fn handle_read(
    volume_mgr: &mut VolMgr,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> (u64, u64, u64, u64) {
    let handle = msg[0] as u32;
    let max_bytes = (msg[1] as usize).min(24);

    let entry = match handles.get(handle, badge) {
        Some(e) if e.handle_type == HandleType::File => e,
        _ => return (response::ERR_HANDLE_INVALID, 0, 0, 0),
    };

    let raw_file = match entry.raw_file {
        Some(f) => f,
        None => return (response::ERR_HANDLE_INVALID, 0, 0, 0),
    };

    let mut buf = [0u8; 24];
    match volume_mgr.read(raw_file, &mut buf[..max_bytes]) {
        Ok(bytes_read) => {
            let (m0, m1, m2) = pack_data_reply(&buf[..bytes_read]);
            (response::OK | ((bytes_read as u64) << 16), m0, m1, m2)
        }
        Err(e) => (FsError::from_sdmmc(e).to_response(), 0, 0, 0),
    }
}

/// Handle WRITE request (inline data).
///
/// Message format:
/// - msg[0]: data bytes [0..7] packed little-endian
/// - msg[1]: data bytes [8..15] packed little-endian
/// - msg[2]: handle (low 32 bits) | byte_count (high 32 bits, ≤ 16)
///
/// Response: `OK | (bytes_written << 16)`
#[allow(clippy::needless_range_loop)]
fn handle_write(
    volume_mgr: &mut VolMgr,
    handles: &mut HandleTable,
    badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let handle = (msg[2] & 0xFFFF_FFFF) as u32;
    let byte_count = ((msg[2] >> 32) as usize).min(16);

    let entry = match handles.get(handle, badge) {
        Some(e) if e.handle_type == HandleType::File => e,
        _ => return response::ERR_HANDLE_INVALID,
    };

    let raw_file = match entry.raw_file {
        Some(f) => f,
        None => return response::ERR_HANDLE_INVALID,
    };

    // Unpack data from the two message words (up to 16 bytes)
    let mut buf = [0u8; 16];
    let w0_bytes = msg[0].to_le_bytes();
    let w1_bytes = msg[1].to_le_bytes();
    let copy0 = 8.min(byte_count);
    buf[..copy0].copy_from_slice(&w0_bytes[..copy0]);
    let copy1 = 8.min(byte_count.saturating_sub(8));
    buf[8..8 + copy1].copy_from_slice(&w1_bytes[..copy1]);

    match volume_mgr.write(raw_file, &buf[..byte_count]) {
        Ok(()) => response::OK | ((byte_count as u64) << 16),
        Err(e) => FsError::from_sdmmc(e).to_response(),
    }
}

/// Handle MKDIR request (inline path).
///
/// Message format:
/// - msg[0]: path bytes [0..7] packed little-endian
/// - msg[1]: path bytes [8..15] packed little-endian
/// - msg[2]: path_len (≤ 16)
///
/// Response: `OK` on success.
fn handle_mkdir(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let path_len = msg[2] as usize;

    let path_buf = match unpack_path_inline(msg[0], msg[1], path_len) {
        Some(b) => b,
        None => return response::ERR_INVALID,
    };
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return response::ERR_INVALID,
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

/// Handle UNLINK request (inline path).
///
/// Message format matches MKDIR: msg[0]/msg[1] = path bytes, msg[2] = path_len.
fn handle_unlink(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    _badge: u64,
    msg: &[u64; 4],
) -> u64 {
    let path_len = msg[2] as usize;

    let path_buf = match unpack_path_inline(msg[0], msg[1], path_len) {
        Some(b) => b,
        None => return response::ERR_INVALID,
    };
    let path = match core::str::from_utf8(&path_buf[..path_len]) {
        Ok(s) => s,
        Err(_) => return response::ERR_INVALID,
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

/// Format a ShortFileName into a buffer, returning the byte count.
fn format_short_name(sfn: &embedded_sdmmc::ShortFileName, buf: &mut [u8; 13]) -> u8 {
    let base = sfn.base_name();
    let ext = sfn.extension();
    let mut len = 0usize;
    for &b in base {
        if len < 8 {
            buf[len] = b;
            len += 1;
        }
    }
    if !ext.is_empty() {
        if len < 13 {
            buf[len] = b'.';
            len += 1;
        }
        for &b in ext {
            if len < 13 {
                buf[len] = b;
                len += 1;
            }
        }
    }
    len as u8
}

/// Handle OPENDIR request — always opens root directory.
///
/// Returns (OK | (handle << 16), 0, 0, 0) on success.
fn handle_opendir(
    volume_mgr: &mut VolMgr,
    volume: embedded_sdmmc::RawVolume,
    handles: &mut HandleTable,
    badge: u64,
) -> (u64, u64, u64, u64) {
    let raw_dir = match volume_mgr.open_root_dir(volume) {
        Ok(d) => d,
        Err(_) => return (response::ERR_IO, 0, 0, 0),
    };

    let mut cache = alloc::boxed::Box::new(DirCache::empty());

    let _ = volume_mgr.iterate_dir(raw_dir, |entry| {
        // Skip LFN fragments and volume labels
        if entry.attributes.is_lfn() || entry.attributes.is_volume() {
            return;
        }
        if cache.count < MAX_DIR_ENTRIES {
            let idx = cache.count;
            let mut name_buf = [0u8; 13];
            let name_len = format_short_name(&entry.name, &mut name_buf);
            // Reconstruct FAT attribute byte from public methods
            let mut attr = 0u8;
            if entry.attributes.is_read_only() {
                attr |= 0x01;
            }
            if entry.attributes.is_hidden() {
                attr |= 0x02;
            }
            if entry.attributes.is_system() {
                attr |= 0x04;
            }
            if entry.attributes.is_directory() {
                attr |= 0x10;
            }
            if entry.attributes.is_archive() {
                attr |= 0x20;
            }
            cache.entries[idx].name = name_buf;
            cache.entries[idx].name_len = name_len;
            cache.entries[idx].size = entry.size;
            cache.entries[idx].attr = attr;
            cache.count += 1;
        }
    });

    let _ = volume_mgr.close_dir(raw_dir);

    match handles.alloc_dir_cached(cache, badge) {
        Some(h) => (response::OK | ((h as u64) << 16), 0, 0, 0),
        None => (response::ERR_TOO_MANY_OPEN, 0, 0, 0),
    }
}

/// Handle READDIR request — returns the next cached directory entry.
///
/// Response label: OK | (name_len << 16) | (attr << 32)
/// m0: file size
/// m1: name bytes 0..8 packed little-endian
/// m2: name bytes 8..13 packed little-endian
fn handle_readdir(handles: &mut HandleTable, badge: u64, msg: &[u64; 4]) -> (u64, u64, u64, u64) {
    let handle = msg[0] as u32;
    let cache = match handles.get_dir_cache_mut(handle, badge) {
        Some(c) => c,
        None => return (response::ERR_HANDLE_INVALID, 0, 0, 0),
    };

    match cache.next() {
        Some(e) => {
            let name_len = e.name_len as u64;
            let attr = e.attr as u64;
            let label = response::OK | (name_len << 16) | (attr << 32);
            let m0 = e.size as u64;
            let mut m1 = 0u64;
            let mut m2 = 0u64;
            for i in 0..8usize.min(e.name_len as usize) {
                m1 |= (e.name[i] as u64) << (i * 8);
            }
            for i in 0..5usize.min((e.name_len as usize).saturating_sub(8)) {
                m2 |= (e.name[8 + i] as u64) << (i * 8);
            }
            (label, m0, m1, m2)
        }
        None => (response::ERR_END_OF_DIR, 0, 0, 0),
    }
}

/// Handle CLOSEDIR request.
fn handle_closedir(handles: &mut HandleTable, badge: u64, msg: &[u64; 4]) -> u64 {
    let handle = msg[0] as u32;
    if handles.close(handle, badge) {
        response::OK
    } else {
        response::ERR_HANDLE_INVALID
    }
}

// Panic handler is provided by m6-std
