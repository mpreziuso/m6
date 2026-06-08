// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
mod abstract_socket_namespace;
#[cfg(feature = "fuchsia")]
mod cgroup;
#[cfg(feature = "fuchsia")]
pub mod container_namespace;
mod current_task;
mod delayed_release;
#[cfg(feature = "fuchsia")]
mod iptables;
mod kernel;
mod kernel_or_task;
#[cfg(feature = "fuchsia")]
mod kernel_stats;
mod kernel_threads;
mod loader;
#[cfg(feature = "fuchsia")]
mod memory_attribution;
#[cfg(feature = "fuchsia")]
pub mod net;
mod pid_table;
mod process_group;
// The scheduler module is always declared so its pure types (SchedulerState,
// SchedulingPolicy, priorities) are available as core Task state; the FIDL
// role-manager (`SchedulerManager`) inside it stays gated behind `fuchsia`.
mod scheduler;
mod seccomp;
mod session;
#[cfg(feature = "fuchsia")]
pub(crate) mod syslog;
#[allow(clippy::module_inception)]
mod task;
mod thread_group;
mod thread_state;
#[cfg(feature = "fuchsia")]
pub mod tracing;
mod uts_namespace;
pub mod waiter;

pub use abstract_socket_namespace::*;
#[cfg(feature = "fuchsia")]
pub use cgroup::*;
pub use current_task::*;
pub use delayed_release::*;
pub mod dynamic_thread_spawner;
#[cfg(feature = "fuchsia")]
pub use iptables::*;
pub use kernel::*;
pub use kernel_or_task::*;
#[cfg(feature = "fuchsia")]
pub use kernel_stats::*;
pub use kernel_threads::*;
pub use limits::*;
pub use pid_table::*;
pub use process_group::*;
pub use scheduler::*;
pub use seccomp::*;
pub use session::*;
#[cfg(feature = "fuchsia")]
pub use syslog::*;
pub use task::*;
pub use thread_group::*;
pub use thread_state::*;
pub use uts_namespace::*;
pub use waiter::*;

pub mod limits;
pub mod syscalls;
