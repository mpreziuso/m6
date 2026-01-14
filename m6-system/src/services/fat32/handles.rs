//! Handle table for tracking open files and directories.
//!
//! Uses fixed-size storage to avoid dynamic allocation.

#![allow(dead_code)]

use embedded_sdmmc::{RawDirectory, RawFile, RawVolume};

/// Maximum number of open handles
pub const MAX_HANDLES: usize = 16;

/// Handle types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandleType {
    /// Unused slot
    None,
    /// Open file handle
    File,
    /// Open directory handle
    Directory,
    /// Open volume handle
    Volume,
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
