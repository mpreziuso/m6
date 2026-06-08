// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

#![allow(dead_code)]

use crate::{SA_RESTART, sigaction_t};
use alloc::string::{String, ToString};
use core::fmt::{Debug, Display, Formatter};

#[derive(Clone, Debug)]
pub struct Errno {
    pub code: ErrnoCode,
    location: &'static core::panic::Location<'static>,
    context: Option<String>,
}

impl Errno {
    /// Creates a new `Errno` with the given `ErrnoCode` and the location of the caller.
    ///
    /// Callers should use the `errno!` macro instead of calling this function directly.
    #[track_caller]
    pub fn new(code: ErrnoCode) -> Self {
        Errno {
            code,
            location: core::panic::Location::caller(),
            context: None,
        }
    }

    #[track_caller]
    pub fn with_context(code: ErrnoCode, context: impl ToString) -> Self {
        Errno {
            code,
            location: core::panic::Location::caller(),
            context: Some(context.to_string()),
        }
    }

    pub fn return_value(&self) -> u64 {
        self.code.return_value()
    }

    /// Returns whether this `Errno` indicates that a restartable syscall was interrupted.
    pub fn is_restartable(&self) -> bool {
        self.code.is_restartable()
    }
}

impl PartialEq for Errno {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl PartialEq<ErrnoCode> for Errno {
    fn eq(&self, other: &ErrnoCode) -> bool {
        self.code == *other
    }
}

impl Eq for Errno {}

impl Display for Errno {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        if let Some(context) = &self.context {
            write!(
                f,
                "{} from {}, context: {}",
                self.code, self.location, context
            )
        } else {
            write!(f, "{} from {}", self.code, self.location)
        }
    }
}

// `Errno` already impls `Display` (above) and derives `Debug`, satisfying the
// supertrait bounds of `core::error::Error`. This lets `?` convert `Errno` into
// `anyhow::Error` (mm_ref/memory_manager.rs).
impl core::error::Error for Errno {}

// There isn't really a mapping from `Errno` to `zx::Status`. The correct mapping is
// context-specific but this converter is a reasonable first-approximation. Mirrors
// upstream `starnix_uapi`'s `From<Errno> for zx_status::Status`. The shim uses
// `ERR_*` constant names (see m6-zx-shim status.rs).
impl From<Errno> for crate::__zx_status::Status {
    fn from(e: Errno) -> Self {
        use crate::__zx_status::Status;
        match e.code.error_code() {
            crate::uapi::ENOENT => Status::ERR_NOT_FOUND,
            crate::uapi::ENOMEM => Status::ERR_NO_MEMORY,
            crate::uapi::EINVAL => Status::ERR_INVALID_ARGS,
            crate::uapi::ETIMEDOUT => Status::ERR_TIMED_OUT,
            crate::uapi::EBUSY => Status::ERR_UNAVAILABLE,
            crate::uapi::EEXIST => Status::ERR_ALREADY_EXISTS,
            crate::uapi::EPIPE => Status::ERR_PEER_CLOSED,
            crate::uapi::ENAMETOOLONG => Status::ERR_BAD_PATH,
            crate::uapi::EIO => Status::ERR_IO,
            crate::uapi::EISDIR => Status::ERR_NOT_FILE,
            crate::uapi::ENOTDIR => Status::ERR_NOT_DIR,
            crate::uapi::EOPNOTSUPP => Status::ERR_NOT_SUPPORTED,
            crate::uapi::EBADF => Status::ERR_BAD_HANDLE,
            crate::uapi::EACCES => Status::ERR_ACCESS_DENIED,
            crate::uapi::EAGAIN => Status::ERR_SHOULD_WAIT,
            crate::uapi::EFBIG => Status::ERR_FILE_BIG,
            crate::uapi::ENOSPC => Status::ERR_NO_SPACE,
            crate::uapi::ENOTEMPTY => Status::ERR_NOT_EMPTY,
            crate::uapi::EPROTONOSUPPORT => Status::ERR_PROTOCOL_NOT_SUPPORTED,
            crate::uapi::ENETUNREACH => Status::ERR_ADDRESS_UNREACHABLE,
            crate::uapi::EADDRINUSE => Status::ERR_ADDRESS_IN_USE,
            crate::uapi::ENOTCONN => Status::ERR_NOT_CONNECTED,
            crate::uapi::ECONNREFUSED => Status::ERR_CONNECTION_REFUSED,
            crate::uapi::ECONNRESET => Status::ERR_CONNECTION_RESET,
            crate::uapi::ECONNABORTED => Status::ERR_CONNECTION_ABORTED,
            _ => Status::ERR_NOT_SUPPORTED,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct ErrnoCode(u32);

impl ErrnoCode {
    pub const fn from_return_value(retval: u64) -> Self {
        let retval = retval as i64;
        if retval >= 0 {
            // Collapse all success codes to 0. This is the only value in the u32 range which
            // is guaranteed to not be an error code.
            return Self(0);
        }
        Self(-retval as u32)
    }

    pub const fn from_error_code(code: i16) -> Self {
        Self(code as u32)
    }

    pub const fn return_value(&self) -> u64 {
        -(self.0 as i32) as u64
    }

    pub const fn error_code(&self) -> u32 {
        self.0
    }

    /// Returns whether this `ErrnoCode` indicates that a restartable syscall was interrupted.
    pub fn is_restartable(&self) -> bool {
        matches!(
            *self,
            ERESTARTSYS | ERESTARTNOINTR | ERESTARTNOHAND | ERESTART_RESTARTBLOCK
        )
    }

    /// Returns whether a combination of this `ErrnoCode` and a given `sigaction_t` mean that an
    /// interrupted syscall should be restarted.
    pub fn should_restart(&self, sigaction: Option<sigaction_t>) -> bool {
        let sigaction = sigaction.unwrap_or_default();

        let should_restart_even_if_sigaction_handler_not_null = match *self {
            ERESTARTSYS => sigaction.sa_flags & SA_RESTART as u64 != 0,
            ERESTARTNOINTR => true,
            ERESTARTNOHAND | ERESTART_RESTARTBLOCK => false,
            _ => return false,
        };

        // Always restart if the signal did not call a handler (i.e. SIGSTOP).
        should_restart_even_if_sigaction_handler_not_null || sigaction.sa_handler.addr == 0
    }
}

impl Debug for ErrnoCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for ErrnoCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", self.name(), self.0)
    }
}

// Special errors indicating a blocking syscall was interrupted, but it can be restarted.
pub const ERESTARTSYS: ErrnoCode = ErrnoCode(512);
pub const ERESTARTNOINTR: ErrnoCode = ErrnoCode(513);
pub const ERESTARTNOHAND: ErrnoCode = ErrnoCode(514);
pub const ERESTART_RESTARTBLOCK: ErrnoCode = ErrnoCode(516);

/// An extension trait for `Result<T, Errno>`.
pub trait ErrnoResultExt<T> {
    /// Maps `Err(EINTR)` to the specified errno.
    fn map_eintr(self, make_errno: impl Fn() -> Errno) -> Result<T, Errno>;
}

impl<T> ErrnoResultExt<T> for Result<T, Errno> {
    fn map_eintr(self, make_errno: impl Fn() -> Errno) -> Result<T, Errno> {
        self.map_err(|err| if err == EINTR { make_errno() } else { err })
    }
}

macro_rules! errno_codes {
    ($($name:ident),+) => {
        $(pub const $name: ErrnoCode = ErrnoCode(crate::uapi::$name);)+

        impl ErrnoCode {
            fn name(&self) -> &'static str {
                match self.0 {
                    $(
                        crate::uapi::$name => stringify!($name),
                    )+
                    _ => "unknown error code",
                }
            }
        }
    };
}

errno_codes![
    EPERM,
    ENOENT,
    ESRCH,
    EINTR,
    EIO,
    ENXIO,
    E2BIG,
    ENOEXEC,
    EBADF,
    ECHILD,
    EAGAIN,
    ENOMEM,
    EACCES,
    EFAULT,
    ENOTBLK,
    EBUSY,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    ENFILE,
    EMFILE,
    ENOTTY,
    ETXTBSY,
    EFBIG,
    ENOSPC,
    ESPIPE,
    EROFS,
    EMLINK,
    EPIPE,
    EDOM,
    ERANGE,
    ENAMETOOLONG,
    ENOLCK,
    ENOSYS,
    ENOTEMPTY,
    ELOOP,
    ENOMSG,
    EIDRM,
    ECHRNG,
    EL2NSYNC,
    EL3HLT,
    EL3RST,
    ELNRNG,
    EUNATCH,
    ENOCSI,
    EL2HLT,
    EBADE,
    EBADR,
    EXFULL,
    ENOANO,
    EBADRQC,
    EBADSLT,
    EDEADLOCK,
    EBFONT,
    ENOSTR,
    ENODATA,
    ETIME,
    ENOSR,
    ENONET,
    ENOPKG,
    EREMOTE,
    ENOLINK,
    EADV,
    ESRMNT,
    ECOMM,
    EPROTO,
    EMULTIHOP,
    EDOTDOT,
    EBADMSG,
    EOVERFLOW,
    ENOTUNIQ,
    EBADFD,
    EREMCHG,
    ELIBACC,
    ELIBBAD,
    ELIBSCN,
    ELIBMAX,
    ELIBEXEC,
    EILSEQ,
    ERESTART,
    ESTRPIPE,
    EUSERS,
    ENOTSOCK,
    EDESTADDRREQ,
    EMSGSIZE,
    EPROTOTYPE,
    ENOPROTOOPT,
    EPROTONOSUPPORT,
    ESOCKTNOSUPPORT,
    EOPNOTSUPP,
    EPFNOSUPPORT,
    EAFNOSUPPORT,
    EADDRINUSE,
    EADDRNOTAVAIL,
    ENETDOWN,
    ENETUNREACH,
    ENETRESET,
    ECONNABORTED,
    ECONNRESET,
    ENOBUFS,
    EISCONN,
    ENOTCONN,
    ESHUTDOWN,
    ETOOMANYREFS,
    ETIMEDOUT,
    ECONNREFUSED,
    EHOSTDOWN,
    EHOSTUNREACH,
    EALREADY,
    EINPROGRESS,
    ESTALE,
    EUCLEAN,
    ENOTNAM,
    ENAVAIL,
    EISNAM,
    EREMOTEIO,
    EDQUOT,
    ENOMEDIUM,
    EMEDIUMTYPE,
    ECANCELED,
    ENOKEY,
    EKEYEXPIRED,
    EKEYREVOKED,
    EKEYREJECTED,
    EOWNERDEAD,
    ENOTRECOVERABLE,
    ERFKILL,
    EHWPOISON
];

// ENOTSUP is a different error in POSIX, but has the same value as EOPNOTSUPP in Linux.
pub const ENOTSUP: ErrnoCode = EOPNOTSUPP;

/// `errno` returns an `Errno` struct tagged with the current file name and line number.
///
/// Use `error!` instead if you want the `Errno` to be wrapped in an `Err`.
#[macro_export]
macro_rules! errno {
    ($err:ident) => {
        $crate::errors::Errno::new($crate::errors::$err)
    };
    ($err:ident, $context:expr) => {
        $crate::errors::Errno::with_context($crate::errors::$err, $context)
    };
}

/// `error` returns a `Err` containing an `Errno` struct tagged with the current file name and
/// line number.
///
/// Use `errno!` instead if you want an unwrapped, but still tagged, `Errno`.
#[macro_export]
macro_rules! error {
    ($($args:tt)*) => { Err($crate::errno!($($args)*)) };
}

/// `errno_from_code` returns an `Errno` struct with the given error code.
#[macro_export]
macro_rules! errno_from_code {
    ($err:expr) => {{ $crate::errors::Errno::new($crate::errors::ErrnoCode::from_error_code($err)) }};
}

/// `errno_from_zxio_code` returns an `Errno` struct with the given error code and is
/// tagged with the current file name and line number.
#[macro_export]
macro_rules! errno_from_zxio_code {
    ($err:expr) => {{ $crate::errno_from_code!($err.raw()) }};
}

// There isn't really a mapping from zx_status::Status to Errno. The correct mapping is
// context-specific but this converter is a reasonable first-approximation. The translation matches
// fdio_status_to_errno. See https://fxbug.dev/42105838 for more context.
// M6: `$crate::__zx_status::Status` is re-exported from m6-zx-shim (see lib.rs). The shim uses
// the same numeric Zircon encoding but `ERR_*` constant names, so this macro references those.
#[macro_export]
macro_rules! from_status_like_fdio {
    ($status:expr) => {{ $crate::from_status_like_fdio!($status, "") }};
    ($status:expr, $context:expr) => {{
        match $status {
            $crate::__zx_status::Status::ERR_NOT_FOUND => $crate::errno!(ENOENT, $context),
            $crate::__zx_status::Status::ERR_NO_MEMORY => $crate::errno!(ENOMEM, $context),
            $crate::__zx_status::Status::ERR_INVALID_ARGS => $crate::errno!(EINVAL, $context),
            $crate::__zx_status::Status::ERR_BUFFER_TOO_SMALL => $crate::errno!(EINVAL, $context),
            $crate::__zx_status::Status::ERR_TIMED_OUT => $crate::errno!(ETIMEDOUT, $context),
            $crate::__zx_status::Status::ERR_UNAVAILABLE => $crate::errno!(EBUSY, $context),
            $crate::__zx_status::Status::ERR_ALREADY_EXISTS => $crate::errno!(EEXIST, $context),
            $crate::__zx_status::Status::ERR_PEER_CLOSED => $crate::errno!(EPIPE, $context),
            $crate::__zx_status::Status::ERR_BAD_STATE => $crate::errno!(EPIPE, $context),
            $crate::__zx_status::Status::ERR_BAD_PATH => $crate::errno!(ENAMETOOLONG, $context),
            $crate::__zx_status::Status::ERR_IO => $crate::errno!(EIO, $context),
            $crate::__zx_status::Status::ERR_NOT_FILE => $crate::errno!(EISDIR, $context),
            $crate::__zx_status::Status::ERR_NOT_DIR => $crate::errno!(ENOTDIR, $context),
            $crate::__zx_status::Status::ERR_NOT_SUPPORTED => $crate::errno!(EOPNOTSUPP, $context),
            $crate::__zx_status::Status::ERR_WRONG_TYPE => $crate::errno!(EOPNOTSUPP, $context),
            $crate::__zx_status::Status::ERR_OUT_OF_RANGE => $crate::errno!(EINVAL, $context),
            $crate::__zx_status::Status::ERR_NO_RESOURCES => $crate::errno!(ENOMEM, $context),
            $crate::__zx_status::Status::ERR_BAD_HANDLE => $crate::errno!(EBADF, $context),
            $crate::__zx_status::Status::ERR_ACCESS_DENIED => $crate::errno!(EACCES, $context),
            $crate::__zx_status::Status::ERR_SHOULD_WAIT => $crate::errno!(EAGAIN, $context),
            $crate::__zx_status::Status::ERR_FILE_BIG => $crate::errno!(EFBIG, $context),
            $crate::__zx_status::Status::ERR_NO_SPACE => $crate::errno!(ENOSPC, $context),
            $crate::__zx_status::Status::ERR_NOT_EMPTY => $crate::errno!(ENOTEMPTY, $context),
            $crate::__zx_status::Status::ERR_IO_REFUSED => $crate::errno!(ECONNREFUSED, $context),
            $crate::__zx_status::Status::ERR_IO_INVALID => $crate::errno!(EIO, $context),
            $crate::__zx_status::Status::ERR_CANCELED => $crate::errno!(EBADF, $context),
            $crate::__zx_status::Status::ERR_PROTOCOL_NOT_SUPPORTED => {
                $crate::errno!(EPROTONOSUPPORT, $context)
            }
            $crate::__zx_status::Status::ERR_ADDRESS_UNREACHABLE => {
                $crate::errno!(ENETUNREACH, $context)
            }
            $crate::__zx_status::Status::ERR_ADDRESS_IN_USE => $crate::errno!(EADDRINUSE, $context),
            $crate::__zx_status::Status::ERR_NOT_CONNECTED => $crate::errno!(ENOTCONN, $context),
            $crate::__zx_status::Status::ERR_CONNECTION_REFUSED => {
                $crate::errno!(ECONNREFUSED, $context)
            }
            $crate::__zx_status::Status::ERR_CONNECTION_RESET => {
                $crate::errno!(ECONNRESET, $context)
            }
            $crate::__zx_status::Status::ERR_CONNECTION_ABORTED => {
                $crate::errno!(ECONNABORTED, $context)
            }
            _ => $crate::errno!(EIO, $context),
        }
    }};
}

// Public re-export of macros allows them to be used like regular Rust items.
pub use {errno, errno_from_code, errno_from_zxio_code, error, from_status_like_fdio};
