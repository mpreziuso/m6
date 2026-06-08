// Logging shim for the Starnix fork on M6.
//
// Replaces Fuchsia's `starnix_logging` crate. It mirrors the upstream public
// surface (log/trace macros, `track_stub!`/`bug_ref!`, task-context tracking,
// `SyscallLogFilter`, coredump bookkeeping) but is `#![no_std]` and forwards
// logging to the `no_std`-compatible `log` crate. Trace and Inspect integration
// are reduced to no-ops.

#![no_std]

extern crate alloc;

mod core_dump_list;
mod logging;
mod stubs;
mod trace;

pub use core_dump_list::{CoreDumpInfo, CoreDumpList, Node};
pub use logging::{
    __log, Level, Record, SyscallLogFilter, ToValue, Value, impossible_error, logger,
    set_current_task_info, set_zx_name, trace_debug_logs_enabled, with_current_task_info,
    with_zx_name,
};
pub use stubs::{
    __track_stub_inner, __track_stub_inner_with_level, BugRef, register_context_name_callback,
    register_stub_context_callback, track_file_not_found,
};
pub use trace::{
    ARG_NAME, CATEGORY_ATRACE, CATEGORY_STARNIX, CATEGORY_STARNIX_MM, CATEGORY_STARNIX_SECURITY,
    CATEGORY_TRACE_META, NAME_CHECK_TASK_EXIT, NAME_CREATE_CONTAINER, NAME_HANDLE_EXCEPTION,
    NAME_MAP_RESTRICTED_STATE, NAME_PERFETTO_BLOB, NAME_READ_RESTRICTED_STATE,
    NAME_RESTRICTED_KICK, NAME_RUN_TASK, NAME_START_KERNEL, NAME_WRITE_RESTRICTED_STATE,
    TraceScope, regular_trace_category_enabled,
};
