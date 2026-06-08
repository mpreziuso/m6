// Tracing primitives for the Starnix fork on M6.
//
// Upstream forwards these to `fuchsia_trace`, which is not available on M6. The
// shim keeps the public macro and constant surface but expands the macros to
// no-ops. They still accept the exact argument forms used by the fork so call
// sites continue to parse.

/// `TraceScope` represents the scope of a trace event. Mirrors
/// `fuchsia_trace::Scope`.
#[derive(Copy, Clone, Debug)]
pub enum TraceScope {
    Thread,
    Process,
    Global,
}

// The trace category used for starnix-related traces.
pub const CATEGORY_STARNIX: &str = "starnix";

// The trace category used for memory manager related traces.
pub const CATEGORY_STARNIX_MM: &str = "starnix:mm";

// The trace category used for security related traces.
pub const CATEGORY_STARNIX_SECURITY: &str = "starnix:security";

// The trace category used for atrace events generated within starnix.
pub const CATEGORY_ATRACE: &str = "starnix:atrace";

// The trace category used for trace events about emitting trace events.
pub const CATEGORY_TRACE_META: &str = "trace_meta";

// The name used to track the duration in Starnix while executing a task.
pub const NAME_RUN_TASK: &str = "RunTask";

// The name used to identify blob records from the container's Perfetto daemon.
pub const NAME_PERFETTO_BLOB: &str = "starnix_perfetto";

// The name used to track the duration of creating a container.
pub const NAME_CREATE_CONTAINER: &str = "CreateContainer";

// The name used to track the start time of the starnix kernel.
pub const NAME_START_KERNEL: &str = "StartKernel";

// The name used to track when a thread was kicked.
pub const NAME_RESTRICTED_KICK: &str = "RestrictedKick";

// The name used to track the duration for inline exception handling.
pub const NAME_HANDLE_EXCEPTION: &str = "HandleException";

// The names used to track durations for restricted state I/O.
pub const NAME_READ_RESTRICTED_STATE: &str = "ReadRestrictedState";
pub const NAME_WRITE_RESTRICTED_STATE: &str = "WriteRestrictedState";
pub const NAME_MAP_RESTRICTED_STATE: &str = "MapRestrictedState";

// The name used to track the duration of checking whether the task loop should exit.
pub const NAME_CHECK_TASK_EXIT: &str = "CheckTaskExit";

pub const ARG_NAME: &str = "name";

#[inline]
pub fn regular_trace_category_enabled(_category: &'static str) -> bool {
    false
}

#[macro_export]
macro_rules! trace_instant {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! firehose_trace_instant {
    ($($arg:tt)*) => {{}};
}

// `trace_duration` is used in statement position; the empty block keeps that valid.
#[macro_export]
macro_rules! trace_duration {
    ($($arg:tt)*) => {};
}

#[macro_export]
macro_rules! firehose_trace_duration {
    ($($arg:tt)*) => {};
}

#[macro_export]
macro_rules! trace_duration_begin {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! firehose_trace_duration_begin {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_duration_end {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! firehose_trace_duration_end {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_flow_begin {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_flow_end {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_flow_step {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_instaflow_begin {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_instaflow_end {
    ($($arg:tt)*) => {{}};
}

#[macro_export]
macro_rules! trace_instaflow_step {
    ($($arg:tt)*) => {{}};
}
