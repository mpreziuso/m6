//! FFI types
//!
//! Re-exports from core::ffi plus CString/CStr from alloc.

pub use core::ffi::*;

// CStr is in core since Rust 1.64
pub use core::ffi::CStr;

// CString is in alloc
pub use alloc::ffi::CString;

/// OsStr/OsString — simplified wrappers around byte slices for no_std.
/// Starnix primarily operates on byte paths internally, so these are thin
/// wrappers rather than platform-aware types.

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct OsStr([u8]);

impl AsRef<OsStr> for OsStr {
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl OsStr {
    pub fn new(s: &str) -> &Self {
        // SAFETY: OsStr is repr(transparent) over [u8]
        unsafe { &*(s.as_bytes() as *const [u8] as *const OsStr) }
    }

    pub fn from_bytes(b: &[u8]) -> &Self {
        // SAFETY: OsStr is repr(transparent) over [u8]
        unsafe { &*(b as *const [u8] as *const OsStr) }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    pub fn to_os_string(&self) -> OsString {
        OsString(self.0.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsString(alloc::vec::Vec<u8>);

impl OsString {
    pub fn new() -> Self {
        Self(alloc::vec::Vec::new())
    }

    pub fn from_vec(v: alloc::vec::Vec<u8>) -> Self {
        Self(v)
    }

    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }

    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        self.0
    }

    pub fn push(&mut self, s: &OsStr) {
        self.0.extend_from_slice(&s.0);
    }
}

impl Default for OsString {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for OsString {
    type Target = OsStr;
    fn deref(&self) -> &OsStr {
        self.as_os_str()
    }
}

impl From<&str> for OsString {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().into())
    }
}

impl From<alloc::string::String> for OsString {
    fn from(s: alloc::string::String) -> Self {
        Self(s.into_bytes())
    }
}
