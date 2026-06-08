// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Minimal perf-event surface for the M6 Starnix fork.
//!
//! The upstream `perf` subsystem was not forked. This module provides only the
//! `perf_event_open(2)` entry point, which returns `ENOSYS`, so the syscall
//! dispatch table links.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::task::CurrentTask;
use starnix_sync::{Locked, Unlocked};
use starnix_syscalls::SyscallResult;
use starnix_uapi::errors::Errno;
use starnix_uapi::error;
use starnix_uapi::user_address::UserRef;
use starnix_uapi::tid_t;
use crate::vfs::FdNumber;
use linux_uapi::perf_event_attr;

/// The `perf_event_open(2)` syscall. M6 stub: perf events are not implemented.
pub fn sys_perf_event_open(
    _locked: &mut Locked<Unlocked>,
    _current_task: &CurrentTask,
    _attr: UserRef<perf_event_attr>,
    _tid: tid_t,
    _cpu: i32,
    _group_fd: FdNumber,
    _flags: u64,
) -> Result<SyscallResult, Errno> {
    error!(ENOSYS)
}

#[cfg(target_arch = "aarch64")]
pub use sys_perf_event_open as sys_arch32_perf_event_open;
