// Logging primitives for the Starnix fork on M6.
//
// Mirrors the public surface of Fuchsia's `starnix_logging::logging` module but
// is `#![no_std]`-friendly. The log macros forward to the `log` crate, which is
// `no_std`. Task context tracking is reduced to a single global slot rather than
// a thread-local, since the fork runs on M6's cooperative kernel threads.

use alloc::string::String;
use core::fmt;

use spin::Mutex;

use starnix_task_command::TaskCommand;
use starnix_uapi::errors::Errno;
use starnix_uapi::{pid_t, tid_t};

// This needs to be available to the macros in this module without clients having
// to depend on `log` themselves.
#[doc(hidden)]
pub use log as __log;

pub use log::kv::{ToValue, Value};
pub use log::{Level, Record, logger};

/// Used to track the current thread's logical context.
enum TaskDebugInfo {
    /// The thread with this set is used for internal logic within the starnix kernel.
    Kernel,
    /// The thread with this set is used to service syscalls for a specific user thread, and this
    /// describes the user thread's identity.
    User {
        pid: pid_t,
        tid: tid_t,
        command: TaskCommand,
        leader_command: TaskCommand,
    },
}

impl TaskDebugInfo {
    fn leader_command(&self) -> TaskCommand {
        match self {
            Self::Kernel => TaskCommand::new(b"kthreadd"),
            Self::User { leader_command, .. } => leader_command.clone(),
        }
    }
}

impl fmt::Display for TaskDebugInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => write!(f, "kthread"),
            Self::User {
                pid, tid, command, ..
            } => write!(f, "{pid}:{tid}[{command}]"),
        }
    }
}

// Upstream uses a thread-local here. M6's logging shim does not assume a TLS
// runtime, so the context is held in a single spin-locked global. This loses
// per-thread precision but keeps the log tags informative and the crate
// `no_std` with no TLS dependency.
static CURRENT_TASK_INFO: Mutex<TaskDebugInfo> = Mutex::new(TaskDebugInfo::Kernel);

/// Whether trace and debug logs are enabled at compile time.
#[inline]
pub const fn trace_debug_logs_enabled() -> bool {
    cfg!(debug_assertions)
}

#[macro_export]
macro_rules! log_trace {
    ($($key:tt $(:$capture:tt)? $(= $value:expr)?),+; $($arg:tt)+) => {
        if $crate::trace_debug_logs_enabled() {
            $crate::with_current_task_info(|_task_info| {
                $crate::__log::trace!(
                    tag:% = _task_info,
                    $($key $(:$capture)* $(= $value)*),+;
                    $($arg)*
                );
            });
        }
    };
    ($($arg:tt)*) => {
        if $crate::trace_debug_logs_enabled() {
            $crate::with_current_task_info(|_task_info| {
                $crate::__log::trace!(tag:% = _task_info; $($arg)*);
            });
        }
    };
}

#[macro_export]
macro_rules! log_syscall {
    ($current_task:expr, $($arg:tt)*) => {
        if $crate::trace_debug_logs_enabled() {
            $crate::log!(
                $current_task.task.thread_group.syscall_log_level(),
                $($arg)*
            );
        }
    }
}

#[macro_export]
macro_rules! log_debug {
    ($($key:tt $(:$capture:tt)? $(= $value:expr)?),+; $($arg:tt)+) => {
        if $crate::trace_debug_logs_enabled() {
            $crate::with_current_task_info(|_task_info| {
                $crate::__log::debug!(
                    tag:% = _task_info,
                    $($key $(:$capture)* $(= $value)*),+;
                    $($arg)*
                );
            });
        }
    };
    ($($arg:tt)*) => {
        if $crate::trace_debug_logs_enabled() {
            $crate::with_current_task_info(|_task_info| {
                $crate::__log::debug!(tag:% = _task_info; $($arg)*);
            });
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::log!($crate::__log::Level::Info, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::log!($crate::__log::Level::Warn, $($arg)*);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log!($crate::__log::Level::Error, $($arg)*);
    };
}

#[macro_export]
macro_rules! log {
    ($lvl:expr, $($key:tt $(:$capture:tt)? $(= $value:expr)?),+; $($arg:tt)+) => {
        $crate::with_current_task_info(|_task_info| {
            $crate::__log::log!(
                $lvl,
                tag:% = _task_info,
                $($key $(:$capture)* $(= $value)*),+;
                $($arg)*
            );
        });
    };
    ($lvl:expr, $($arg:tt)+) => {
        $crate::with_current_task_info(|_task_info| {
            $crate::__log::log!($lvl, tag:% = _task_info; $($arg)*);
        });
    };
}

/// Call this when you get an error that should "never" happen, i.e. if it does that means the
/// kernel was updated to produce some other error after this match was written.
#[track_caller]
pub fn impossible_error(status: zx::Status) -> Errno {
    panic!("encountered impossible error: {status}");
}

/// M6 does not use Zircon handle names; these remain as no-ops for API parity.
pub fn set_zx_name<T>(_obj: &T, _name: impl AsRef<[u8]>) {}

pub fn with_zx_name<T>(obj: T, _name: impl AsRef<[u8]>) -> T {
    obj
}

/// Set the context for log messages from this thread. Should only be called when a thread has been
/// created to execute a user-level task, and should only be called once at the start of that
/// thread's execution.
pub fn set_current_task_info(
    command: TaskCommand,
    leader_command: TaskCommand,
    pid: pid_t,
    tid: tid_t,
) {
    *CURRENT_TASK_INFO.lock() = TaskDebugInfo::User {
        pid,
        tid,
        command,
        leader_command,
    };
}

/// Access this thread's task info for debugging. Intended for use internally by Starnix's log
/// macros.
///
/// *Do not use this for kernel logic.* If you need access to the current pid/tid/etc for the
/// purposes of writing kernel logic beyond logging for debugging purposes, those should be accessed
/// through the `CurrentTask` type as an argument explicitly passed to your function.
#[doc(hidden)]
pub fn with_current_task_info<T>(f: impl Fn(&dyn fmt::Display) -> T) -> T {
    f(&*CURRENT_TASK_INFO.lock())
}

pub(crate) fn get_current_leader_command() -> String {
    use alloc::string::ToString;
    CURRENT_TASK_INFO.lock().leader_command().to_string()
}

/// A filter for syscall logging.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyscallLogFilter {
    match_string: String,
}

impl SyscallLogFilter {
    pub fn new(match_string: String) -> Self {
        Self { match_string }
    }

    pub fn matches(&self, command: &TaskCommand) -> bool {
        let matcher = self.match_string.as_bytes();
        if matcher.is_empty() {
            return true;
        }
        command
            .as_bytes()
            .windows(matcher.len())
            .any(|w| w == matcher)
    }
}
