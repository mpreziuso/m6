//! Zircon status codes mapped to M6 syscall errors

/// Zircon-compatible status type.
///
/// Starnix checks specific status values extensively — we preserve the
/// Zircon numeric encoding so forked match arms remain correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Status(i32);

impl Status {
    pub const OK: Self = Self(0);
    pub const ERR_INTERNAL: Self = Self(-1);
    pub const ERR_NOT_SUPPORTED: Self = Self(-2);
    pub const ERR_NO_RESOURCES: Self = Self(-3);
    pub const ERR_NO_MEMORY: Self = Self(-4);
    pub const ERR_INVALID_ARGS: Self = Self(-10);
    pub const ERR_BAD_HANDLE: Self = Self(-11);
    pub const ERR_WRONG_TYPE: Self = Self(-12);
    pub const ERR_BAD_SYSCALL: Self = Self(-13);
    pub const ERR_OUT_OF_RANGE: Self = Self(-14);
    pub const ERR_BUFFER_TOO_SMALL: Self = Self(-15);
    pub const ERR_BAD_STATE: Self = Self(-20);
    pub const ERR_TIMED_OUT: Self = Self(-21);
    pub const ERR_SHOULD_WAIT: Self = Self(-22);
    pub const ERR_CANCELED: Self = Self(-23);
    pub const ERR_PEER_CLOSED: Self = Self(-24);
    pub const ERR_NOT_FOUND: Self = Self(-25);
    pub const ERR_ALREADY_EXISTS: Self = Self(-26);
    pub const ERR_ALREADY_BOUND: Self = Self(-27);
    pub const ERR_UNAVAILABLE: Self = Self(-28);
    pub const ERR_ACCESS_DENIED: Self = Self(-30);
    pub const ERR_IO: Self = Self(-40);
    pub const ERR_IO_REFUSED: Self = Self(-41);
    pub const ERR_IO_DATA_INTEGRITY: Self = Self(-42);
    pub const ERR_IO_DATA_LOSS: Self = Self(-43);
    pub const ERR_IO_NOT_PRESENT: Self = Self(-44);
    pub const ERR_IO_OVERRUN: Self = Self(-45);
    pub const ERR_IO_MISSED_DEADLINE: Self = Self(-46);
    pub const ERR_IO_INVALID: Self = Self(-47);
    pub const ERR_BAD_PATH: Self = Self(-50);
    pub const ERR_NOT_DIR: Self = Self(-51);
    pub const ERR_NOT_FILE: Self = Self(-52);
    pub const ERR_FILE_BIG: Self = Self(-53);
    pub const ERR_NO_SPACE: Self = Self(-54);
    pub const ERR_NOT_EMPTY: Self = Self(-55);
    pub const ERR_STOP: Self = Self(-60);
    pub const ERR_NEXT: Self = Self(-61);
    pub const ERR_ASYNC: Self = Self(-62);
    pub const ERR_PROTOCOL_NOT_SUPPORTED: Self = Self(-63);
    pub const ERR_ADDRESS_UNREACHABLE: Self = Self(-64);
    pub const ERR_ADDRESS_IN_USE: Self = Self(-65);
    pub const ERR_NOT_CONNECTED: Self = Self(-66);
    pub const ERR_CONNECTION_REFUSED: Self = Self(-67);
    pub const ERR_CONNECTION_RESET: Self = Self(-68);
    pub const ERR_CONNECTION_ABORTED: Self = Self(-69);

    // -- Zircon-style aliases (the fork uses names without the `ERR_` prefix)
    pub const INTERNAL: Self = Self::ERR_INTERNAL;
    pub const NOT_SUPPORTED: Self = Self::ERR_NOT_SUPPORTED;
    pub const NO_RESOURCES: Self = Self::ERR_NO_RESOURCES;
    pub const NO_MEMORY: Self = Self::ERR_NO_MEMORY;
    pub const INVALID_ARGS: Self = Self::ERR_INVALID_ARGS;
    pub const BAD_HANDLE: Self = Self::ERR_BAD_HANDLE;
    pub const WRONG_TYPE: Self = Self::ERR_WRONG_TYPE;
    pub const OUT_OF_RANGE: Self = Self::ERR_OUT_OF_RANGE;
    pub const BAD_STATE: Self = Self::ERR_BAD_STATE;
    pub const TIMED_OUT: Self = Self::ERR_TIMED_OUT;
    pub const SHOULD_WAIT: Self = Self::ERR_SHOULD_WAIT;
    pub const CANCELED: Self = Self::ERR_CANCELED;
    pub const PEER_CLOSED: Self = Self::ERR_PEER_CLOSED;
    pub const NOT_FOUND: Self = Self::ERR_NOT_FOUND;
    pub const ALREADY_EXISTS: Self = Self::ERR_ALREADY_EXISTS;
    pub const ACCESS_DENIED: Self = Self::ERR_ACCESS_DENIED;
    pub const IO: Self = Self::ERR_IO;
    pub const NOT_DIR: Self = Self::ERR_NOT_DIR;

    /// Maps a raw status code to `Ok(())` on success, or `Err(Status)` otherwise.
    pub fn ok(raw: i32) -> Result<(), Status> {
        let status = Self(raw);
        if status.is_ok() {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// Create from raw status code.
    pub const fn from_raw(raw: i32) -> Self {
        Self(raw)
    }

    /// Get the raw status code.
    pub const fn into_raw(self) -> i32 {
        self.0
    }

    /// Check if this is a success status.
    pub const fn is_ok(self) -> bool {
        self.0 == 0
    }

    /// Check if this is an error status.
    pub const fn is_error(self) -> bool {
        self.0 != 0
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Status({})", self.0)
    }
}
