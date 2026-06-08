//! I/O traits and types
//!
//! Lightweight reimplementation of `std::io` core traits for no_std.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

// -- Error

/// I/O error type.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind, _msg: &str) -> Self {
        Self { kind }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn from_raw_os_error(code: i32) -> Self {
        let kind = match code {
            2 => ErrorKind::NotFound,
            13 => ErrorKind::PermissionDenied,
            17 => ErrorKind::AlreadyExists,
            11 => ErrorKind::WouldBlock,
            32 => ErrorKind::BrokenPipe,
            _ => ErrorKind::Other,
        };
        Self { kind }
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        None
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "I/O error: {:?}", self.kind)
    }
}

// -- ErrorKind

/// Categories of I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    UnexpectedEof,
    OutOfMemory,
    Unsupported,
    Other,
}

// -- Result

pub type Result<T> = core::result::Result<T, Error>;

// -- Read

pub trait Read {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "unexpected end of stream",
                    ));
                }
                Ok(n) => buf = &mut buf[n..],
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let start_len = buf.len();
        let mut tmp = [0u8; 512];
        loop {
            match self.read(&mut tmp) {
                Ok(0) => return Ok(buf.len() - start_len),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
        let mut bytes = Vec::new();
        let n = self.read_to_end(&mut bytes)?;
        let s = core::str::from_utf8(&bytes).map_err(|_| {
            Error::new(ErrorKind::InvalidData, "stream did not contain valid UTF-8")
        })?;
        buf.push_str(s);
        Ok(n)
    }
}

// -- Write

pub trait Write {
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    fn flush(&mut self) -> Result<()>;

    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => buf = &buf[n..],
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_fmt(&mut self, fmt: core::fmt::Arguments<'_>) -> Result<()> {
        struct Adapter<'a, T: Write + ?Sized> {
            inner: &'a mut T,
            error: Option<Error>,
        }
        impl<T: Write + ?Sized> core::fmt::Write for Adapter<'_, T> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                match self.inner.write_all(s.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.error = Some(e);
                        Err(core::fmt::Error)
                    }
                }
            }
        }
        let mut adapter = Adapter {
            inner: self,
            error: None,
        };
        match core::fmt::Write::write_fmt(&mut adapter, fmt) {
            Ok(()) => Ok(()),
            Err(_) => Err(adapter
                .error
                .unwrap_or_else(|| Error::new(ErrorKind::Other, "formatter error"))),
        }
    }
}

// -- Seek

pub trait Seek {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

// -- BufRead

pub trait BufRead: Read {
    fn fill_buf(&mut self) -> Result<&[u8]>;
    fn consume(&mut self, amt: usize);
}

// -- Cursor

pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T> Cursor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, pos: 0 }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn set_position(&mut self, pos: u64) {
        self.pos = pos;
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let slice = self.inner.as_ref();
        let start = self.pos as usize;
        if start >= slice.len() {
            return Ok(0);
        }
        let available = &slice[start..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<T: AsRef<[u8]>> Seek for Cursor<T> {
    fn seek(&mut self, style: SeekFrom) -> Result<u64> {
        let (base, offset) = match style {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::End(n) => (self.inner.as_ref().len() as u64, n),
            SeekFrom::Current(n) => (self.pos, n),
        };
        let new_pos = if offset >= 0 {
            base.checked_add(offset as u64)
        } else {
            base.checked_sub((-offset) as u64)
        };
        match new_pos {
            Some(n) => {
                self.pos = n;
                Ok(n)
            }
            None => Err(Error::new(
                ErrorKind::InvalidInput,
                "seek to negative position",
            )),
        }
    }
}

// -- Impls for common types

impl Read for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(self.len());
        let (head, tail) = self.split_at(n);
        buf[..n].copy_from_slice(head);
        *self = tail;
        Ok(n)
    }
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for alloc::collections::VecDeque<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.extend(buf.iter().copied());
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
