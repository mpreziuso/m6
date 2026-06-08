//! Path manipulation
//!
//! Lightweight reimplementation of `std::path::Path` and `PathBuf` for no_std.
//! Operates on byte slices with '/' as separator (Linux-only).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ffi::{OsStr, OsString};

/// A borrowed path slice (like `&str` but for filesystem paths).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Path(OsStr);

impl Path {
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &Self {
        // SAFETY: Path is repr(transparent) over OsStr
        unsafe { &*(s.as_ref() as *const OsStr as *const Path) }
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    pub fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf(self.0.to_os_string())
    }

    pub fn parent(&self) -> Option<&Path> {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        // Find last '/' that's not trailing
        let trimmed = if bytes.last() == Some(&b'/') && bytes.len() > 1 {
            &bytes[..bytes.len() - 1]
        } else {
            bytes
        };
        match trimmed.iter().rposition(|&b| b == b'/') {
            Some(0) => Some(Path::new(OsStr::from_bytes(b"/"))),
            Some(i) => Some(Path::new(OsStr::from_bytes(&trimmed[..i]))),
            None => None,
        }
    }

    pub fn file_name(&self) -> Option<&OsStr> {
        let bytes = self.0.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        let trimmed = if bytes.last() == Some(&b'/') && bytes.len() > 1 {
            &bytes[..bytes.len() - 1]
        } else {
            bytes
        };
        match trimmed.iter().rposition(|&b| b == b'/') {
            Some(i) => Some(OsStr::from_bytes(&trimmed[i + 1..])),
            None => Some(OsStr::from_bytes(trimmed)),
        }
    }

    pub fn join<P: AsRef<Path>>(&self, other: P) -> PathBuf {
        let mut buf = self.to_path_buf();
        buf.push(other);
        buf
    }

    pub fn is_absolute(&self) -> bool {
        self.0.as_bytes().first() == Some(&b'/')
    }

    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    pub fn starts_with<P: AsRef<Path>>(&self, base: P) -> bool {
        let self_bytes = self.0.as_bytes();
        let base_bytes = base.as_ref().0.as_bytes();
        self_bytes.starts_with(base_bytes)
            && (self_bytes.len() == base_bytes.len()
                || self_bytes.get(base_bytes.len()) == Some(&b'/'))
    }

    pub fn display(&self) -> PathDisplay<'_> {
        PathDisplay(self)
    }

    pub fn components(&self) -> Components<'_> {
        Components {
            path: self.0.as_bytes(),
            pos: 0,
        }
    }

    pub fn extension(&self) -> Option<&OsStr> {
        let name = self.file_name()?.as_bytes();
        let dot_pos = name.iter().rposition(|&b| b == b'.')?;
        if dot_pos == 0 {
            None
        } else {
            Some(OsStr::from_bytes(&name[dot_pos + 1..]))
        }
    }
}

impl AsRef<OsStr> for Path {
    fn as_ref(&self) -> &OsStr {
        &self.0
    }
}

impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(OsStr::new(self))
    }
}

impl AsRef<Path> for String {
    fn as_ref(&self) -> &Path {
        Path::new(OsStr::new(self.as_str()))
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<OsStr> for str {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(self)
    }
}

pub struct PathDisplay<'a>(&'a Path);

impl core::fmt::Display for PathDisplay<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0.to_str() {
            Some(s) => f.write_str(s),
            None => write!(f, "<non-utf8 path>"),
        }
    }
}

// -- PathBuf

/// An owned, mutable path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathBuf(OsString);

impl PathBuf {
    pub fn new() -> Self {
        Self(OsString::new())
    }

    pub fn from(s: &str) -> Self {
        Self(OsString::from(s))
    }

    pub fn as_path(&self) -> &Path {
        Path::new(self.0.as_os_str())
    }

    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        let other = path.as_ref().as_os_str().as_bytes();
        if other.starts_with(b"/") {
            // Absolute path replaces current
            self.0 = OsString::from_vec(other.into());
            return;
        }
        let bytes = self.0.as_os_str().as_bytes();
        if !bytes.is_empty() && !bytes.ends_with(b"/") {
            self.0.push(OsStr::from_bytes(b"/"));
        }
        self.0.push(OsStr::from_bytes(other));
    }

    pub fn pop(&mut self) -> bool {
        if let Some(parent) = self.as_path().parent() {
            self.0 = parent.as_os_str().to_os_string();
            true
        } else {
            false
        }
    }

    pub fn set_extension(&mut self, ext: &str) -> bool {
        let bytes = self.0.as_os_str().as_bytes();
        if let Some(dot) = bytes.iter().rposition(|&b| b == b'.') {
            let mut new = Vec::from(&bytes[..dot]);
            if !ext.is_empty() {
                new.push(b'.');
                new.extend_from_slice(ext.as_bytes());
            }
            self.0 = OsString::from_vec(new);
            true
        } else {
            if !ext.is_empty() {
                self.0.push(OsStr::from_bytes(b"."));
                self.0.push(OsStr::from_bytes(ext.as_bytes()));
            }
            false
        }
    }
}

impl Default for PathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for PathBuf {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<OsStr> for PathBuf {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl core::borrow::Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.as_path()
    }
}

impl From<&str> for PathBuf {
    fn from(s: &str) -> Self {
        Self::from(s)
    }
}

impl From<String> for PathBuf {
    fn from(s: String) -> Self {
        Self(OsString::from(s))
    }
}

impl From<OsString> for PathBuf {
    fn from(s: OsString) -> Self {
        Self(s)
    }
}

impl core::fmt::Display for PathBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_path().display().fmt(f)
    }
}

// -- Components iterator

pub struct Components<'a> {
    path: &'a [u8],
    pos: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component<'a> {
    RootDir,
    CurDir,
    ParentDir,
    Normal(&'a OsStr),
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip separators
        while self.pos < self.path.len() && self.path[self.pos] == b'/' {
            if self.pos == 0 {
                self.pos = 1;
                return Some(Component::RootDir);
            }
            self.pos += 1;
        }

        if self.pos >= self.path.len() {
            return None;
        }

        let start = self.pos;
        while self.pos < self.path.len() && self.path[self.pos] != b'/' {
            self.pos += 1;
        }

        let component = &self.path[start..self.pos];
        match component {
            b"." => Some(Component::CurDir),
            b".." => Some(Component::ParentDir),
            other => Some(Component::Normal(OsStr::from_bytes(other))),
        }
    }
}
