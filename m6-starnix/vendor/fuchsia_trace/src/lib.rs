//! Minimal no-op `fuchsia_trace` shim for the M6 Starnix fork.
//!
//! Upstream Starnix instruments hot paths with Fuchsia tracing. M6 has no trace
//! buffer, so this provides only the types the fork names (`Id`, `trace_site_t`,
//! `TraceCategoryContext`) with inert behaviour. The trace *macros* themselves
//! (`trace_duration!`, `trace_instaflow_*!`, …) are no-op shims in
//! `starnix_logging`; this crate just satisfies the type references those macros
//! and the surrounding code mention.

#![no_std]

/// A trace event/flow id. Inert: `new()` returns a fixed id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Id(u64);

impl Id {
    /// Creates a new trace id. Always 0 in the no-op shim.
    pub fn new() -> Self {
        Id(0)
    }

    /// Creates a trace id from a raw value.
    pub fn from_raw(raw: u64) -> Self {
        Id(raw)
    }
}

impl From<u64> for Id {
    fn from(raw: u64) -> Self {
        Id(raw)
    }
}

/// Cache slot for a trace call site, mirroring Fuchsia's `trace_site_t`.
///
/// In real tracing this caches per-site enablement state; here it holds nothing.
#[allow(non_camel_case_types)]
pub struct trace_site_t {
    _state: core::sync::atomic::AtomicU64,
}

impl trace_site_t {
    /// Creates a call-site cache initialised to `value` (ignored).
    pub const fn new(value: u64) -> Self {
        Self { _state: core::sync::atomic::AtomicU64::new(value) }
    }
}

/// A handle proving a trace category is enabled.
///
/// Tracing is always disabled in the shim, so `acquire`/`acquire_cached` return
/// `None` and the instrumented closures never run.
pub struct TraceCategoryContext {
    _private: (),
}

impl TraceCategoryContext {
    /// Acquires a context if `category` is enabled. Always `None` (disabled).
    pub fn acquire(_category: &'static str) -> Option<Self> {
        None
    }

    /// Cached variant of [`acquire`]. Always `None` (disabled).
    pub fn acquire_cached(_category: &'static str, _site: &trace_site_t) -> Option<Self> {
        None
    }
}
