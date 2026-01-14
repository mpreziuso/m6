//! I/O traits and types
//!
//! Mirrors std::io where possible.

mod error;

pub use error::{Error, ErrorKind, Result};

use core::fmt;

use m6_syscall::invoke::debug_putc;

/// A trait for reading bytes.
///
/// Mirrors std::io::Read.
pub trait Read {
    /// Pull some bytes from this source into the specified buffer.
    ///
    /// Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Read the exact number of bytes required to fill buf.
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected end of file")),
                Ok(n) => buf = &mut buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// A trait for writing bytes.
///
/// Mirrors std::io::Write.
pub trait Write {
    /// Write a buffer into this writer.
    ///
    /// Returns the number of bytes written.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flush this output stream.
    fn flush(&mut self) -> Result<()>;

    /// Attempt to write an entire buffer.
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(Error::new(ErrorKind::WriteZero, "write returned Ok(0)")),
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Write a formatted string into this writer.
    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> Result<()> {
        // Create an adapter that implements fmt::Write
        struct Adapter<'a, W: ?Sized + Write> {
            inner: &'a mut W,
            error: Result<()>,
        }

        impl<W: ?Sized + Write> fmt::Write for Adapter<'_, W> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                match self.inner.write_all(s.as_bytes()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.error = Err(e);
                        Err(fmt::Error)
                    }
                }
            }
        }

        let mut adapter = Adapter {
            inner: self,
            error: Ok(()),
        };

        match fmt::write(&mut adapter, fmt) {
            Ok(()) => Ok(()),
            Err(..) => {
                if adapter.error.is_err() {
                    adapter.error
                } else {
                    Err(Error::new(ErrorKind::Other, "formatter error"))
                }
            }
        }
    }
}

/// Enumeration of possible methods to seek within an I/O object.
///
/// Mirrors std::io::SeekFrom.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),
    /// Sets the offset to the size of this object plus the specified number of bytes.
    End(i64),
    /// Sets the offset to the current position plus the specified number of bytes.
    Current(i64),
}

/// A trait for seeking within an I/O object.
///
/// Mirrors std::io::Seek.
pub trait Seek {
    /// Seek to an offset, in bytes, in a stream.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64>;

    /// Rewind to the beginning of a stream.
    fn rewind(&mut self) -> Result<()> {
        self.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    /// Returns the current seek position from the start of the stream.
    fn stream_position(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

/// Debug console writer.
///
/// Writes directly to the kernel debug console using the DebugPutChar syscall.
/// This is available even before the full I/O subsystem is initialised.
pub struct DebugConsole;

impl Write for DebugConsole {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        for &byte in buf {
            debug_putc(byte);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl fmt::Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            debug_putc(byte);
        }
        Ok(())
    }
}

/// Returns a handle to standard output.
///
/// For now, this returns the debug console. In the future, it could
/// be connected to a UART driver via IPC.
pub fn stdout() -> DebugConsole {
    DebugConsole
}

/// Returns a handle to standard error.
///
/// For now, this returns the debug console (same as stdout).
pub fn stderr() -> DebugConsole {
    DebugConsole
}
