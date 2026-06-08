// Core-dump bookkeeping for the Starnix fork on M6.
//
// Upstream records coredumps into a Fuchsia Inspect `BoundedListNode`. M6 has no
// Inspect runtime, so this is a minimal, dependency-free shim that retains the
// public types (`CoreDumpInfo`, `CoreDumpList`) and emits a debug log instead.
//
// NOTE: the only consumer is `execution::crash_reporter`, which additionally
// depends on several Fuchsia-only crates that do not yet exist on M6, so that
// module is not currently buildable. These types exist so the
// `starnix_logging::` import path resolves.

use alloc::string::String;
use alloc::vec::Vec;

use crate::log_debug;

/// The maximum length of an argv string to record.
const MAX_ARGV_LENGTH: usize = 128;

/// A list of recently coredumped tasks.
#[derive(Default)]
pub struct CoreDumpList {
    _private: (),
}

/// An opaque diagnostics node handle. Placeholder for Fuchsia's `inspect::Node`.
#[derive(Default)]
pub struct Node {
    _private: (),
}

impl Node {
    pub fn create_child(&self, _name: &str) -> Node {
        Node::default()
    }
}

#[derive(Debug)]
pub struct CoreDumpInfo {
    pub process_koid: u64,
    pub thread_koid: u64,
    pub linux_pid: i64,
    pub argv: Vec<String>,
    pub uptime: i64,
    pub thread_name: String,
    pub signal: String,
}

impl CoreDumpList {
    pub fn new(_node: Node) -> Self {
        Self { _private: () }
    }

    pub fn record_core_dump(&self, core_dump_info: CoreDumpInfo) {
        let mut argv = core_dump_info.argv.join(" ");
        let original_len = argv.len();
        argv.truncate(MAX_ARGV_LENGTH.saturating_sub(3));
        if argv.len() < original_len {
            argv.push_str("...");
        }
        log_debug!(
            linux_pid = core_dump_info.linux_pid, argv:%;
            "Recording task with a coredump."
        );
    }
}
