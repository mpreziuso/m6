// Stubs for tracking unimplemented code paths.
//
// Ported from Fuchsia's `inspect_stubs` (re-exported by upstream
// `starnix_logging::stubs`). The M6 shim drops the Inspect integration and the
// global invocation map; `__track_stub_inner` simply emits a log line. The
// public API (`track_stub!`, `bug_ref!`, `BugRef`, `__track_stub_inner`) matches
// upstream so the fork's call sites resolve.

use core::fmt;
use core::num::NonZeroU64;
use core::panic::Location;

/// Tracks a stubbed implementation.
///
/// Records that a stub was encountered. The first time a particular stub is
/// encountered upstream, a log message is emitted; here we always log at debug
/// level.
///
/// Example:
/// ```ignore
/// track_stub!(TODO("https://fxbug.dev/12345"), "my component is not implemented");
/// ```
#[macro_export]
macro_rules! track_stub {
    (TODO($bug_url:literal), $message:expr, $flags:expr $(,)?) => {{
        $crate::__track_stub_inner(
            $crate::bug_ref!($bug_url),
            $message,
            Some($flags.into()),
            ::core::panic::Location::caller(),
        );
    }};
    (TODO($bug_url:literal), $message:expr $(,)?) => {{
        $crate::__track_stub_inner(
            $crate::bug_ref!($bug_url),
            $message,
            None,
            ::core::panic::Location::caller(),
        );
    }};
}

/// Tracks a stubbed implementation with a specified log level.
#[macro_export]
macro_rules! track_stub_log {
    ($level:expr, TODO($bug_url:literal), $message:expr, $flags:expr $(,)?) => {{
        $crate::__track_stub_inner_with_level(
            $level,
            $crate::bug_ref!($bug_url),
            $message,
            Some($flags.into()),
            ::core::panic::Location::caller(),
        );
    }};
    ($level:expr, TODO($bug_url:literal), $message:expr $(,)?) => {{
        $crate::__track_stub_inner_with_level(
            $level,
            $crate::bug_ref!($bug_url),
            $message,
            None,
            ::core::panic::Location::caller(),
        );
    }};
}

#[doc(hidden)]
#[inline]
pub fn __track_stub_inner(
    bug: BugRef,
    message: &str,
    flags: Option<u64>,
    location: &'static Location<'static>,
) -> u64 {
    __track_stub_inner_with_level(log::Level::Debug, bug, message, flags, location)
}

#[doc(hidden)]
#[inline]
pub fn __track_stub_inner_with_level(
    level: log::Level,
    bug: BugRef,
    message: &str,
    flags: Option<u64>,
    location: &'static Location<'static>,
) -> u64 {
    match flags {
        Some(flags) => {
            log::log!(level, tag = "track_stub", location:%; "{bug} {message}: 0x{flags:x}");
        }
        None => {
            log::log!(level, tag = "track_stub", location:%; "{bug} {message}");
        }
    }
    1
}

/// Records that a process attempted to open a file that does not exist.
///
/// Upstream this feeds a diagnostics aggregator; the M6 shim only logs at debug
/// level. Generic over the path type to avoid coupling to a specific string
/// type.
pub fn track_file_not_found<P: core::fmt::Debug>(path: P) {
    crate::log_debug!("file not found: {:?}", path);
}

/// Provide a callback to retrieve the current context name. Retained for API
/// parity; the M6 shim ignores the callback.
pub fn register_context_name_callback(
    _cb: impl Fn() -> alloc::string::String + Send + Sync + 'static,
) {
}

/// Initialise the stub-tracking context callback to surface the current Starnix
/// process name. No-op in the M6 shim.
pub fn register_stub_context_callback() {
    register_context_name_callback(crate::logging::get_current_leader_command);
}

/// Creates a `BugRef` from a URL literal.
///
/// This macro will cause a compilation error if the provided literal is not a
/// valid Fuchsia bug URL.
#[macro_export]
macro_rules! bug_ref {
    ($bug_url:literal) => {{
        // Assign the value to a const to ensure we get compile-time validation of the URL.
        const __REF: $crate::BugRef = match $crate::BugRef::from_str($bug_url) {
            Some(b) => b,
            None => panic!("bug references must have the form `https://fxbug.dev/123456789`"),
        };
        __REF
    }};
}

/// Represents a reference to a Fuchsia bug.
///
/// Used to ensure that stubs are tracked against a valid bug.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BugRef {
    number: u64,
}

impl BugRef {
    #[doc(hidden)] // use bug_ref!() instead
    pub const fn from_str(url: &'static str) -> Option<Self> {
        let expected_prefix = b"https://fxbug.dev/";
        let url = str::as_bytes(url);

        if url.len() < expected_prefix.len() {
            return None;
        }
        let (scheme_and_domain, number_str) = url.split_at(expected_prefix.len());
        if number_str.is_empty() {
            return None;
        }

        // The standard library does not have a const string or slice equality function.
        {
            let mut i = 0;
            while i < scheme_and_domain.len() {
                if scheme_and_domain[i] != expected_prefix[i] {
                    return None;
                }
                i += 1;
            }
        }

        // The standard library does not have a const base 10 string parser.
        let mut number = 0;
        {
            let mut i = 0;
            while i < number_str.len() {
                number *= 10;
                number += match number_str[i] {
                    b'0' => 0,
                    b'1' => 1,
                    b'2' => 2,
                    b'3' => 3,
                    b'4' => 4,
                    b'5' => 5,
                    b'6' => 6,
                    b'7' => 7,
                    b'8' => 8,
                    b'9' => 9,
                    _ => return None,
                };
                i += 1;
            }
        }

        if number != 0 {
            Some(Self { number })
        } else {
            None
        }
    }
}

impl From<NonZeroU64> for BugRef {
    fn from(value: NonZeroU64) -> Self {
        Self {
            number: value.get(),
        }
    }
}

impl From<BugRef> for NonZeroU64 {
    fn from(value: BugRef) -> Self {
        NonZeroU64::new(value.number).unwrap()
    }
}

impl fmt::Display for BugRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://fxbug.dev/{}", self.number)
    }
}
