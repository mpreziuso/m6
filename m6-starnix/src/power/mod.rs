// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Minimal power-management surface for the M6 Starnix fork.
//!
//! The upstream `power` module implements suspend/resume backed by Fuchsia power
//! FIDL services. M6 has no such services yet, so this provides only the types
//! and a no-op [`SuspendResumeManager`] referenced by non-power code (epoll
//! wake sources, timer wake ops, the kernel struct). Suspend is never entered;
//! wake-source activation is tracked but inert.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::task::CurrentTask;
use m6_starnix_std::sync::Arc;
use starnix_uapi::errors::Errno;

/// Identifies a source that can keep the system awake.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum WakeupSourceOrigin {
    WakeLock(String),
    Epoll(String),
    HAL(String),
}

/// Callback invoked when a registered object observes a wake event.
pub trait OnWakeOps: Send + Sync {
    fn on_wake(&self, current_task: &CurrentTask, baton_lease: &zx::NullableHandle);
}

/// Aggregated suspend statistics, surfaced via sysfs.
#[derive(Debug, Default, Clone)]
pub struct SuspendStats {
    pub success_count: u64,
    pub fail_count: u64,
    pub last_failed_errno: Option<Errno>,
    pub last_failed_device: Option<String>,
    /// Last reason for resume.
    pub last_resume_reason: Option<String>,
    /// The amount of time spent in the previous suspend state.
    pub last_time_in_sleep: zx::BootDuration,
    /// The amount of time spent performing suspend and resume operations.
    pub last_time_in_suspend_operations: zx::BootDuration,
}

/// Manages suspend/resume and wake sources.
///
/// M6 stub: never suspends. Wake-source activation/deactivation are no-ops that
/// report success so callers behave as if the source was registered.
#[derive(Debug, Default)]
pub struct SuspendResumeManager;

impl SuspendResumeManager {
    pub fn activate_wakeup_source(&self, _origin: WakeupSourceOrigin) -> bool {
        true
    }

    pub fn deactivate_wakeup_source(&self, _origin: &WakeupSourceOrigin) -> bool {
        true
    }

    pub fn suspend_stats(&self) -> SuspendStats {
        SuspendStats::default()
    }
}

/// A shared handle to the [`SuspendResumeManager`].
pub type SuspendResumeManagerHandle = Arc<SuspendResumeManager>;
