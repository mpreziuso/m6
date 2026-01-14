//! I/O error types
//!
//! Mirrors std::io::Error and std::io::ErrorKind.

use core::fmt;

/// A specialised Result type for I/O operations.
pub type Result<T> = core::result::Result<T, Error>;

/// The error type for I/O operations.
///
/// Mirrors std::io::Error.
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
}

impl Error {
    /// Creates a new I/O error from an error kind and message.
    #[inline]
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    /// Returns the corresponding ErrorKind for this error.
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)
    }
}

/// A list specifying general categories of I/O error.
///
/// Mirrors std::io::ErrorKind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An entity was not found.
    NotFound,
    /// The operation lacked the necessary privileges.
    PermissionDenied,
    /// The connection was refused.
    ConnectionRefused,
    /// The connection was reset.
    ConnectionReset,
    /// The connection was aborted.
    ConnectionAborted,
    /// The network operation failed.
    NotConnected,
    /// A socket address could not be bound.
    AddrInUse,
    /// A nonexistent interface was requested.
    AddrNotAvailable,
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// An entity already exists.
    AlreadyExists,
    /// The operation needs to block to complete.
    WouldBlock,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    InvalidData,
    /// The I/O operation's timeout expired.
    TimedOut,
    /// An error returned when an operation could not be completed because a
    /// call to `write` returned `Ok(0)`.
    WriteZero,
    /// This operation is unsupported on this platform.
    Unsupported,
    /// An error returned when an operation could not be completed because an
    /// "end of file" was reached prematurely.
    UnexpectedEof,
    /// An operation was interrupted.
    Interrupted,
    /// Any I/O error not part of this list.
    Other,
}

impl ErrorKind {
    /// Returns a string describing this error kind.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound => "entity not found",
            Self::PermissionDenied => "permission denied",
            Self::ConnectionRefused => "connection refused",
            Self::ConnectionReset => "connection reset",
            Self::ConnectionAborted => "connection aborted",
            Self::NotConnected => "not connected",
            Self::AddrInUse => "address in use",
            Self::AddrNotAvailable => "address not available",
            Self::BrokenPipe => "broken pipe",
            Self::AlreadyExists => "entity already exists",
            Self::WouldBlock => "operation would block",
            Self::InvalidInput => "invalid input parameter",
            Self::InvalidData => "invalid data",
            Self::TimedOut => "operation timed out",
            Self::WriteZero => "write zero",
            Self::Unsupported => "unsupported",
            Self::UnexpectedEof => "unexpected end of file",
            Self::Interrupted => "operation interrupted",
            Self::Other => "other error",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
