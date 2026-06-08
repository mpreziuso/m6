// Forked from Fuchsia's starnix_syscalls, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2021 The Fuchsia Authors. BSD license.

#![no_std]

pub mod decls;
mod syscall_arg;
mod syscall_result;

pub use syscall_arg::*;
pub use syscall_result::*;

#[doc(hidden)]
pub use paste as __paste;
