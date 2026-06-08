// Forked from Fuchsia's Starnix for M6 (no_std).
// Original: Copyright 2025 The Fuchsia Authors. BSD license.
//
//! The `TaskCommand` type and associated functions.
//
// M6 adaptation: upstream interns the name with `flyweights::FlyByteStr`. M6 has
// no flyweights crate, so the name is backed by `alloc::sync::Arc<[u8]>`
// directly (no interning). The public API is unchanged.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use bstr::{BStr, ByteSlice};
use core::ops::Range;

/// The command for a task.
///
/// Linux task commands are limited to 15 bytes, but we allow longer names in
/// places for diagnostics and debugging.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TaskCommand {
    name: Arc<[u8]>,
    linux_name_range: Option<Range<usize>>,
}

impl TaskCommand {
    /// Create a new `TaskCommand` from a byte slice, truncated at the first null byte.
    pub fn new(name: &[u8]) -> Self {
        let name = if let Some(idx) = name.find_byte(b'\0') { &name[..idx] } else { name };
        Self { name: Arc::from(name), linux_name_range: None }
    }

    /// Create a new `TaskCommand` from a path. The basename of the path is used.
    pub fn from_path_bytes(path: &[u8]) -> Self {
        let basename = if let Some(idx) = path.rfind_byte(b'/') { &path[idx + 1..] } else { path };
        Self::new(basename)
    }

    /// Returns the name truncated to 15 bytes.
    pub fn comm_name(&self) -> &[u8] {
        let bytes = self.linux_name_bytes();
        &bytes[..core::cmp::min(bytes.len(), 15)]
    }

    /// Returns the name as a 16-byte array, null-terminated, as expected by `prctl(PR_GET_NAME)`.
    pub fn prctl_name(&self) -> [u8; 16] {
        let mut name = [0u8; 16];
        let comm = self.comm_name();
        name[..comm.len()].copy_from_slice(comm);
        name
    }

    /// Returns the entire name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.name
    }

    fn linux_name_bytes(&self) -> &[u8] {
        if let Some(range) = &self.linux_name_range {
            &self.name[range.clone()]
        } else {
            &self.name
        }
    }

    /// Tries to embed `other` as the Linux name within this command.
    pub fn try_embed(&self, other: &TaskCommand) -> Option<Self> {
        self.name.find(other.linux_name_bytes()).map(|offset| Self {
            name: self.name.clone(),
            linux_name_range: Some(offset..offset + other.linux_name_bytes().len()),
        })
    }
}

impl Default for TaskCommand {
    fn default() -> Self {
        Self::new(b"")
    }
}

impl core::fmt::Debug for TaskCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        BStr::new(&self.name).fmt(f)
    }
}

impl core::fmt::Display for TaskCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        BStr::new(&self.name).fmt(f)
    }
}

impl PartialOrd for TaskCommand {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TaskCommand {
    /// Total ordering based on the full name (ignores the Linux rendering).
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}
