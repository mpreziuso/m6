// Forked from Fuchsia's starnix_types, adapted for M6 (no_std, ARM64).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
//
// Mirrors upstream's `pub mod` list. Fuchsia-runtime-only pieces (FIDL impls in
// `convert`) are gated behind the `fuchsia` feature (default off).

#![no_std]
#![allow(clippy::needless_lifetimes)]

extern crate alloc;

pub mod arch;
pub mod augmented;
pub mod convert;
pub mod futex_address;
pub mod math;
pub mod ownership;
pub mod stats;
pub mod string;
pub mod thread_start_info;
pub mod time;
pub mod user_buffer;
pub mod vfs;

// M6: local Zircon time/futex compatibility shim (see module docs). Not part of
// the upstream public API; used internally where upstream used `zx::` time/futex.
pub mod zx_time;

// M6: upstream's private `errors` module only contained compile-time
// `const_assert_eq!` checks that Fuchsia's `syncio::zxio` error codes match
// `uapi`. `syncio` is a Fuchsia crate, so the checks are omitted here.
// REMOVED(syncio): error-code parity assertions.

/// Page size — 4KB on ARM64.
///
/// M6: upstream exposes this as a `LazyLock<u64>` filled from the runtime page
/// size; on M6 the page size is a fixed compile-time constant.
pub const PAGE_SIZE: u64 = 4096;
