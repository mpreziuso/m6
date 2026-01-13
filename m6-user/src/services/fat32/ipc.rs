//! IPC protocol definitions for FAT32 filesystem service.
//!
//! Defines request/response codes and message formats for
//! filesystem operations.

#![allow(dead_code)]

/// Request codes (in IPC message label)
pub mod request {
    // -- Filesystem operations

    /// Sync all pending writes to disk.
    pub const SYNC: u64 = 0x0102;

    /// Get filesystem statistics.
    /// Response: msg[0] = total_clusters, msg[1] = free_clusters
    pub const STAT_FS: u64 = 0x0103;

    // -- File operations

    /// Open a file.
    /// msg[0]: flags (O_RDONLY=1, O_WRONLY=2, O_RDWR=3, O_CREATE=0x100, O_TRUNC=0x200)
    /// msg[1]: path_len
    /// Requires frame capability with path string.
    /// Response: msg[0] = handle
    pub const OPEN: u64 = 0x0200;

    /// Close a file handle.
    /// msg[0]: handle
    pub const CLOSE: u64 = 0x0201;

    /// Read from a file.
    /// msg[0]: handle
    /// msg[1]: max_bytes
    /// Requires frame capability for data transfer.
    /// Response: msg[0] = bytes_read
    pub const READ: u64 = 0x0202;

    /// Write to a file.
    /// msg[0]: handle
    /// msg[1]: byte_count
    /// Requires frame capability with data.
    /// Response: msg[0] = bytes_written
    pub const WRITE: u64 = 0x0203;

    /// Seek within a file.
    /// msg[0]: handle
    /// msg[1]: offset (i64 as u64)
    /// msg[2]: whence (0=Start, 1=Current, 2=End)
    /// Response: msg[0] = new_position
    pub const SEEK: u64 = 0x0204;

    /// Truncate a file.
    /// msg[0]: handle
    pub const TRUNCATE: u64 = 0x0205;

    /// Get file metadata.
    /// msg[0]: path_len
    /// Requires frame capability with path string.
    /// Response: msg[0] = size, msg[1] = attributes
    pub const STAT: u64 = 0x0206;

    // -- Directory operations

    /// Create a directory.
    /// msg[0]: path_len
    /// Requires frame capability with path string.
    pub const MKDIR: u64 = 0x0300;

    /// Remove a directory.
    /// msg[0]: path_len
    /// Requires frame capability with path string.
    pub const RMDIR: u64 = 0x0301;

    /// Read next directory entry.
    /// msg[0]: dir_handle
    /// Requires frame capability for entry data.
    /// Response: OK if entry returned, ERR_END_OF_DIR if exhausted.
    pub const READDIR: u64 = 0x0302;

    /// Open a directory for iteration.
    /// msg[0]: path_len
    /// Requires frame capability with path string.
    /// Response: msg[0] = dir_handle
    pub const OPENDIR: u64 = 0x0303;

    /// Close a directory iterator.
    /// msg[0]: dir_handle
    pub const CLOSEDIR: u64 = 0x0304;

    // -- File management

    /// Delete a file.
    /// msg[0]: path_len
    /// Requires frame capability with path string.
    pub const UNLINK: u64 = 0x0400;

    /// Rename a file or directory.
    /// msg[0]: old_path_len
    /// msg[1]: new_path_len
    /// Requires frame capability with both paths (old path followed by new path).
    pub const RENAME: u64 = 0x0401;
}

/// Response codes (in IPC reply x0)
pub mod response {
    /// Operation completed successfully
    pub const OK: u64 = 0;
    /// I/O error
    pub const ERR_IO: u64 = 1;
    /// Invalid request or argument
    pub const ERR_INVALID: u64 = 2;
    /// File or directory not found
    pub const ERR_NOT_FOUND: u64 = 3;
    /// Permission denied
    pub const ERR_PERMISSION: u64 = 4;
    /// File or directory already exists
    pub const ERR_EXISTS: u64 = 5;
    /// Not a directory
    pub const ERR_NOT_DIR: u64 = 6;
    /// Is a directory (when file expected)
    pub const ERR_IS_DIR: u64 = 7;
    /// Directory not empty
    pub const ERR_NOT_EMPTY: u64 = 8;
    /// No space left on device
    pub const ERR_NO_SPACE: u64 = 9;
    /// Filename too long
    pub const ERR_NAME_TOO_LONG: u64 = 10;
    /// Invalid handle
    pub const ERR_HANDLE_INVALID: u64 = 11;
    /// Too many open files
    pub const ERR_TOO_MANY_OPEN: u64 = 12;
    /// End of directory (no more entries)
    pub const ERR_END_OF_DIR: u64 = 13;
    /// Filesystem not mounted
    pub const ERR_NOT_MOUNTED: u64 = 14;
    /// Read-only filesystem
    pub const ERR_READ_ONLY: u64 = 15;
}

/// Open flags
pub mod flags {
    /// Open for reading only
    pub const O_RDONLY: u64 = 0x0001;
    /// Open for writing only
    pub const O_WRONLY: u64 = 0x0002;
    /// Open for reading and writing
    pub const O_RDWR: u64 = 0x0003;
    /// Create file if it doesn't exist
    pub const O_CREATE: u64 = 0x0100;
    /// Truncate file to zero length
    pub const O_TRUNC: u64 = 0x0200;
    /// Append to end of file
    pub const O_APPEND: u64 = 0x0400;
}

/// Seek whence values
pub mod seek {
    /// Seek from start of file
    pub const SET: u64 = 0;
    /// Seek from current position
    pub const CUR: u64 = 1;
    /// Seek from end of file
    pub const END: u64 = 2;
}

/// Directory entry structure (written to shared frame)
#[repr(C)]
pub struct DirEntry {
    /// File size in bytes
    pub size: u64,
    /// File attributes (FAT attributes)
    pub attributes: u32,
    /// Name length in bytes
    pub name_len: u32,
    /// File name (variable length, follows this struct)
    pub name: [u8; 256],
}

/// File attributes
pub mod attr {
    /// Read-only file
    pub const READ_ONLY: u32 = 0x01;
    /// Hidden file
    pub const HIDDEN: u32 = 0x02;
    /// System file
    pub const SYSTEM: u32 = 0x04;
    /// Directory
    pub const DIRECTORY: u32 = 0x10;
    /// Archive (file has been modified)
    pub const ARCHIVE: u32 = 0x20;
}
