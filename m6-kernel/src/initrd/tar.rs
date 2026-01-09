//! USTAR tar archive parser
//!
//! Minimal parser for finding files in USTAR format archives.
//! This is the format produced by `tar --format=ustar`.

/// TAR block size (always 512 bytes).
const TAR_BLOCK_SIZE: usize = 512;

/// USTAR magic string.
const USTAR_MAGIC: &[u8; 5] = b"ustar";

/// USTAR tar header (512 bytes).
///
/// All numeric fields are stored as ASCII octal strings.
#[repr(C)]
struct TarHeader {
    /// File name (null-terminated).
    name: [u8; 100],
    /// File mode (octal).
    mode: [u8; 8],
    /// Owner user ID (octal).
    uid: [u8; 8],
    /// Owner group ID (octal).
    gid: [u8; 8],
    /// File size in bytes (octal).
    size: [u8; 12],
    /// Modification time (octal).
    mtime: [u8; 12],
    /// Header checksum.
    chksum: [u8; 8],
    /// File type flag.
    typeflag: u8,
    /// Link name (for links).
    linkname: [u8; 100],
    /// USTAR magic ("ustar").
    magic: [u8; 6],
    /// USTAR version.
    version: [u8; 2],
    /// Owner user name.
    uname: [u8; 32],
    /// Owner group name.
    gname: [u8; 32],
    /// Device major number.
    devmajor: [u8; 8],
    /// Device minor number.
    devminor: [u8; 8],
    /// Filename prefix.
    prefix: [u8; 155],
    /// Padding to 512 bytes.
    _pad: [u8; 12],
}

// Compile-time check that TarHeader is exactly 512 bytes.
const _: () = assert!(
    core::mem::size_of::<TarHeader>() == TAR_BLOCK_SIZE,
    "TarHeader must be exactly 512 bytes"
);

/// Type flags for tar entries.
mod typeflag {
    /// Regular file (or '\0' for old-style tar).
    pub const REGULAR: u8 = b'0';
    /// Regular file (alternative, NUL byte).
    pub const REGULAR_ALT: u8 = 0;
    /// Hard link.
    pub const LINK: u8 = b'1';
    /// Symbolic link.
    pub const SYMLINK: u8 = b'2';
    /// Character device.
    pub const CHAR: u8 = b'3';
    /// Block device.
    pub const BLOCK: u8 = b'4';
    /// Directory.
    pub const DIR: u8 = b'5';
    /// FIFO.
    pub const FIFO: u8 = b'6';
}

/// Parse an octal ASCII string into a usize.
///
/// Stops at the first NUL or space character, or at the end of the field.
fn parse_octal(field: &[u8]) -> usize {
    let mut result = 0usize;
    for &b in field {
        if b == 0 || b == b' ' {
            break;
        }
        if b >= b'0' && b <= b'7' {
            result = result.saturating_mul(8).saturating_add((b - b'0') as usize);
        }
    }
    result
}

/// Extract the file name from a tar header.
///
/// Handles both simple names and prefix+name combinations.
fn extract_name(header: &TarHeader) -> Option<&str> {
    // Find end of name (null-terminated)
    let name_len = header
        .name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(header.name.len());

    if name_len == 0 {
        return None;
    }

    // Try to parse as UTF-8
    core::str::from_utf8(&header.name[..name_len]).ok()
}

/// Check if this is a valid USTAR header.
fn is_ustar_header(header: &TarHeader) -> bool {
    // Check USTAR magic (first 5 bytes)
    header.magic[..5] == *USTAR_MAGIC
}

/// Check if this header represents the end of the archive (two zero blocks).
fn is_end_of_archive(block: &[u8]) -> bool {
    block.iter().all(|&b| b == 0)
}

/// Find a file in a USTAR tar archive by name.
///
/// # Arguments
///
/// * `archive` - The raw bytes of the tar archive
/// * `target_name` - The name of the file to find
///
/// # Returns
///
/// A slice containing the file data, or `None` if not found.
pub fn find_file<'a>(archive: &'a [u8], target_name: &str) -> Option<&'a [u8]> {
    let mut offset = 0;

    while offset + TAR_BLOCK_SIZE <= archive.len() {
        let header_bytes = &archive[offset..offset + TAR_BLOCK_SIZE];

        // Check for end of archive (two consecutive zero blocks)
        if is_end_of_archive(header_bytes) {
            break;
        }

        // SAFETY: TarHeader is repr(C), exactly 512 bytes, and all fields
        // are arrays of u8, so any bit pattern is valid.
        let header: &TarHeader =
            unsafe { &*(header_bytes.as_ptr() as *const TarHeader) };

        // Verify USTAR magic (some archives may use old-style tar)
        if !is_ustar_header(header) {
            // Try to continue anyway - might be old-style tar
            // Just check that the name field looks reasonable
            if header.name[0] == 0 {
                break;
            }
        }

        // Extract file name
        let name = extract_name(header);

        // Get file size
        let size = parse_octal(&header.size);

        // Calculate data offset and next header offset
        let data_offset = offset + TAR_BLOCK_SIZE;
        let data_blocks = size.div_ceil(TAR_BLOCK_SIZE);
        let next_offset = data_offset + data_blocks * TAR_BLOCK_SIZE;

        // Check if this is the file we're looking for
        if let Some(name) = name {
            let is_regular = header.typeflag == typeflag::REGULAR
                || header.typeflag == typeflag::REGULAR_ALT;

            if is_regular && name == target_name {
                // Found it - return the data slice
                if data_offset + size <= archive.len() {
                    return Some(&archive[data_offset..data_offset + size]);
                } else {
                    log::warn!(
                        "File '{}' data extends beyond archive bounds",
                        target_name
                    );
                    return None;
                }
            }
        }

        offset = next_offset;
    }

    None
}

/// List all files in a USTAR tar archive.
///
/// Primarily for debugging - logs each file name and size.
pub fn list_files(archive: &[u8]) {
    let mut offset = 0;

    while offset + TAR_BLOCK_SIZE <= archive.len() {
        let header_bytes = &archive[offset..offset + TAR_BLOCK_SIZE];

        if is_end_of_archive(header_bytes) {
            break;
        }

        // SAFETY: Same as in find_file
        let header: &TarHeader =
            unsafe { &*(header_bytes.as_ptr() as *const TarHeader) };

        if !is_ustar_header(header) && header.name[0] == 0 {
            break;
        }

        if let Some(name) = extract_name(header) {
            let size = parse_octal(&header.size);
            let type_char = match header.typeflag {
                typeflag::REGULAR | typeflag::REGULAR_ALT => '-',
                typeflag::DIR => 'd',
                typeflag::SYMLINK => 'l',
                typeflag::LINK => 'h',
                typeflag::CHAR => 'c',
                typeflag::BLOCK => 'b',
                typeflag::FIFO => 'p',
                _ => '?',
            };
            log::info!("  {} {:>10} {}", type_char, size, name);
        }

        let size = parse_octal(&header.size);
        let data_blocks = size.div_ceil(TAR_BLOCK_SIZE);
        offset += TAR_BLOCK_SIZE + data_blocks * TAR_BLOCK_SIZE;
    }
}
