//! Handle table for tracking open files and directories.
//!
//! Uses fixed-size storage to avoid dynamic allocation.

#![allow(dead_code)]

use alloc::boxed::Box;
use embedded_sdmmc::{RawDirectory, RawFile, RawVolume};

/// Maximum number of open handles
pub const MAX_HANDLES: usize = 16;

/// Maximum cached directory entries per open directory
pub const MAX_DIR_ENTRIES: usize = 32;

/// Handle types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandleType {
    /// Unused slot
    None,
    /// Open file handle
    File,
    /// Open directory handle (raw embedded_sdmmc)
    Directory,
    /// Cached directory handle (entries pre-loaded into memory)
    CachedDirectory,
    /// Open volume handle
    Volume,
}

/// A single cached directory entry (8.3 short name)
pub struct CachedDirEntry {
    /// Short name bytes (e.g. "HELLO.TXT")
    pub name: [u8; 13],
    /// Valid bytes in name
    pub name_len: u8,
    /// File size in bytes
    pub size: u32,
    /// FAT attributes byte
    pub attr: u8,
}

impl CachedDirEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; 13],
            name_len: 0,
            size: 0,
            attr: 0,
        }
    }
}

/// Pre-loaded snapshot of a directory's entries
pub struct DirCache {
    pub entries: [CachedDirEntry; MAX_DIR_ENTRIES],
    pub count: usize,
    pub cursor: usize,
}

impl DirCache {
    pub const fn empty() -> Self {
        // SAFETY: CachedDirEntry::empty() is const
        const EMPTY: CachedDirEntry = CachedDirEntry::empty();
        Self {
            entries: [EMPTY; MAX_DIR_ENTRIES],
            count: 0,
            cursor: 0,
        }
    }

    /// Return the next entry and advance the cursor, or None if exhausted.
    pub fn next(&mut self) -> Option<&CachedDirEntry> {
        if self.cursor < self.count {
            let entry = &self.entries[self.cursor];
            self.cursor += 1;
            Some(entry)
        } else {
            None
        }
    }
}

/// Open handle state
pub struct HandleEntry {
    /// Type of handle
    pub handle_type: HandleType,
    /// Client badge for access control
    pub badge: u64,
    /// Raw file handle (if file)
    pub raw_file: Option<RawFile>,
    /// Raw directory handle (if directory)
    pub raw_dir: Option<RawDirectory>,
    /// Raw volume handle (if volume)
    pub raw_volume: Option<RawVolume>,
    /// Cached directory snapshot (if cached directory)
    pub dir_cache: Option<Box<DirCache>>,
}

impl HandleEntry {
    /// Create an empty (unused) handle entry
    pub const fn empty() -> Self {
        Self {
            handle_type: HandleType::None,
            badge: 0,
            raw_file: None,
            raw_dir: None,
            raw_volume: None,
            dir_cache: None,
        }
    }

    /// Check if this entry is in use
    pub fn is_used(&self) -> bool {
        self.handle_type != HandleType::None
    }
}

impl Default for HandleEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Handle table for tracking open files and directories
pub struct HandleTable {
    /// Handle entries
    entries: [HandleEntry; MAX_HANDLES],
}

impl HandleTable {
    /// Create a new empty handle table
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| HandleEntry::default()),
        }
    }

    /// Allocate a handle for a file
    pub fn alloc_file(&mut self, raw_file: RawFile, badge: u64) -> Option<u32> {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.is_used() {
                entry.handle_type = HandleType::File;
                entry.badge = badge;
                entry.raw_file = Some(raw_file);
                entry.raw_dir = None;
                entry.raw_volume = None;
                entry.dir_cache = None;
                return Some(i as u32);
            }
        }
        None
    }

    /// Allocate a handle for a directory
    pub fn alloc_dir(&mut self, raw_dir: RawDirectory, badge: u64) -> Option<u32> {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.is_used() {
                entry.handle_type = HandleType::Directory;
                entry.badge = badge;
                entry.raw_file = None;
                entry.raw_dir = Some(raw_dir);
                entry.raw_volume = None;
                entry.dir_cache = None;
                return Some(i as u32);
            }
        }
        None
    }

    /// Allocate a cached directory handle (entries pre-loaded, no live raw dir)
    pub fn alloc_dir_cached(&mut self, cache: Box<DirCache>, badge: u64) -> Option<u32> {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.is_used() {
                entry.handle_type = HandleType::CachedDirectory;
                entry.badge = badge;
                entry.raw_file = None;
                entry.raw_dir = None;
                entry.raw_volume = None;
                entry.dir_cache = Some(cache);
                return Some(i as u32);
            }
        }
        None
    }

    /// Allocate a handle for a volume
    pub fn alloc_volume(&mut self, raw_volume: RawVolume, badge: u64) -> Option<u32> {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if !entry.is_used() {
                entry.handle_type = HandleType::Volume;
                entry.badge = badge;
                entry.raw_file = None;
                entry.raw_dir = None;
                entry.raw_volume = Some(raw_volume);
                entry.dir_cache = None;
                return Some(i as u32);
            }
        }
        None
    }

    /// Get a handle entry by number (validates badge)
    pub fn get(&self, handle: u32, badge: u64) -> Option<&HandleEntry> {
        let entry = self.entries.get(handle as usize)?;
        if !entry.is_used() || entry.badge != badge {
            return None;
        }
        Some(entry)
    }

    /// Get a mutable handle entry by number (validates badge)
    pub fn get_mut(&mut self, handle: u32, badge: u64) -> Option<&mut HandleEntry> {
        let entry = self.entries.get_mut(handle as usize)?;
        if !entry.is_used() || entry.badge != badge {
            return None;
        }
        Some(entry)
    }

    /// Get mutable reference to a cached directory's DirCache (validates badge and type)
    pub fn get_dir_cache_mut(&mut self, handle: u32, badge: u64) -> Option<&mut DirCache> {
        let entry = self.entries.get_mut(handle as usize)?;
        if !entry.is_used() || entry.badge != badge || entry.handle_type != HandleType::CachedDirectory {
            return None;
        }
        entry.dir_cache.as_deref_mut()
    }

    /// Take a file handle out of the table
    pub fn take_file(&mut self, handle: u32, badge: u64) -> Option<RawFile> {
        let entry = self.entries.get_mut(handle as usize)?;
        if !entry.is_used() || entry.badge != badge || entry.handle_type != HandleType::File {
            return None;
        }
        entry.handle_type = HandleType::None;
        entry.raw_file.take()
    }

    /// Take a directory handle out of the table
    pub fn take_dir(&mut self, handle: u32, badge: u64) -> Option<RawDirectory> {
        let entry = self.entries.get_mut(handle as usize)?;
        if !entry.is_used() || entry.badge != badge || entry.handle_type != HandleType::Directory {
            return None;
        }
        entry.handle_type = HandleType::None;
        entry.raw_dir.take()
    }

    /// Close a handle
    pub fn close(&mut self, handle: u32, badge: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(handle as usize)
            && entry.is_used()
            && entry.badge == badge
        {
            entry.handle_type = HandleType::None;
            entry.raw_file = None;
            entry.raw_dir = None;
            entry.raw_volume = None;
            entry.dir_cache = None;
            return true;
        }
        false
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}
