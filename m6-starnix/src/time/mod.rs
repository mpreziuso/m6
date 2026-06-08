// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

///! The time module is responsible for managing the UTC clock of the kernel.
#[allow(unused_imports)] use m6_starnix_std::prelude::*;
pub mod utc;

#[cfg(feature = "fuchsia")]
mod hr_timer_manager;
#[cfg(feature = "fuchsia")]
#[cfg(feature = "fuchsia")]
mod interval_timer;
// Minimal always-on interval-timer types (IntervalTimer/IntervalTimerHandle) so
// TimerTable + ClockId/TimerId in `timers` compile for the minimal core. The
// real POSIX-timer engine (hr_timer-backed) is gated; arming/firing is inert
// until the clock-object model lands (M5).
#[cfg(not(feature = "fuchsia"))]
#[path = "interval_timer_min.rs"]
mod interval_timer;
mod timeline;
mod timers;

#[cfg(feature = "fuchsia")]
pub use hr_timer_manager::*;
pub use interval_timer::*;
pub use timeline::*;
pub use timers::*;
