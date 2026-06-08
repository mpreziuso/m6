// Interned-string shim for the Starnix fork (replaces Fuchsia `flyweights`).
//
// M6 adaptation: upstream `flyweights` deduplicates identical strings in a global
// intern table backed by atomics. For the minimal core we skip the global table
// and back each value with an `Arc`, preserving cheap clones and value semantics
// (Eq/Ord/Hash by content). Interning can be added later without changing the API.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use bstr::BStr;
use core::borrow::Borrow;
use core::fmt;
use core::ops::Deref;

// -- An interned byte string. Backed by `Arc<[u8]>`; derefs to `bstr::BStr`.
#[derive(Clone, Default)]
pub struct FlyByteStr {
    inner: ByteStorage,
}

#[derive(Clone, Default)]
enum ByteStorage {
    #[default]
    Empty,
    Bytes(Arc<[u8]>),
}

impl ByteStorage {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            ByteStorage::Empty => &[],
            ByteStorage::Bytes(b) => b,
        }
    }
}

impl FlyByteStr {
    /// Create a new interned byte string from anything byte-slice-like.
    #[inline]
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        let bytes = value.as_ref();
        if bytes.is_empty() {
            Self { inner: ByteStorage::Empty }
        } else {
            Self { inner: ByteStorage::Bytes(Arc::from(bytes)) }
        }
    }

    /// The underlying bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// View as a `bstr::BStr`.
    #[inline]
    pub fn as_bstr(&self) -> &BStr {
        BStr::new(self.as_bytes())
    }

    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Whether the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl Deref for FlyByteStr {
    type Target = BStr;
    #[inline]
    fn deref(&self) -> &BStr {
        self.as_bstr()
    }
}

impl AsRef<[u8]> for FlyByteStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<BStr> for FlyByteStr {
    #[inline]
    fn as_ref(&self) -> &BStr {
        self.as_bstr()
    }
}

impl Borrow<[u8]> for FlyByteStr {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for FlyByteStr {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for FlyByteStr {}

impl PartialEq<[u8]> for FlyByteStr {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl Ord for FlyByteStr {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}
impl PartialOrd for FlyByteStr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for FlyByteStr {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for FlyByteStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_bstr(), f)
    }
}
impl fmt::Display for FlyByteStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_bstr(), f)
    }
}

impl From<&[u8]> for FlyByteStr {
    #[inline]
    fn from(v: &[u8]) -> Self {
        Self::new(v)
    }
}
impl From<&str> for FlyByteStr {
    #[inline]
    fn from(v: &str) -> Self {
        Self::new(v.as_bytes())
    }
}
impl From<Vec<u8>> for FlyByteStr {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}
impl From<&Vec<u8>> for FlyByteStr {
    #[inline]
    fn from(v: &Vec<u8>) -> Self {
        Self::new(v.as_slice())
    }
}
impl From<bstr::BString> for FlyByteStr {
    #[inline]
    fn from(v: bstr::BString) -> Self {
        let bytes: &[u8] = v.as_ref();
        Self::new(bytes)
    }
}
impl From<alloc::string::String> for FlyByteStr {
    #[inline]
    fn from(v: alloc::string::String) -> Self {
        Self::new(v.as_bytes())
    }
}

/// An interned UTF-8 string. Backed by `Arc<str>`; mirrors `FlyByteStr`.
#[derive(Clone, Default)]
pub struct FlyStr {
    inner: Option<Arc<str>>,
}

impl FlyStr {
    #[inline]
    pub fn new(value: impl AsRef<str>) -> Self {
        let s = value.as_ref();
        if s.is_empty() { Self { inner: None } } else { Self { inner: Some(Arc::from(s)) } }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.inner.as_deref().unwrap_or("")
    }
}

impl Deref for FlyStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for FlyStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<str> for FlyStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl PartialEq for FlyStr {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for FlyStr {}
impl Ord for FlyStr {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl PartialOrd for FlyStr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl core::hash::Hash for FlyStr {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
impl fmt::Debug for FlyStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}
impl fmt::Display for FlyStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}
impl From<&str> for FlyStr {
    #[inline]
    fn from(v: &str) -> Self {
        Self::new(v)
    }
}
impl From<alloc::string::String> for FlyStr {
    #[inline]
    fn from(v: alloc::string::String) -> Self {
        Self::new(v)
    }
}
