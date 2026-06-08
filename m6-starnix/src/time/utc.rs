// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Starnix-specific UTC clock implementation.
//!
//! On Fuchsia this module abstracts away the difference between the Fuchsia UTC
//! clock (which only starts once the system is confident the reading is
//! accurate) and what Linux programs expect (a clock that always runs).
//!
//! M6 has no Fuchsia UTC clock object. This implementation derives UTC from the
//! monotonic clock with a zero offset (i.e. UTC == boot time since power-on).
//! It is a faithful-enough placeholder for the static-binary bring-up target;
//! wall-clock accuracy will come once an M6 RTC/time service is wired in.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use fuchsia_runtime::UtcInstant;

/// Returns the current UTC time.
///
/// Derived from the monotonic clock; there is no wall-clock offset yet.
pub fn utc_now() -> UtcInstant {
    UtcInstant::from_nanos(zx::MonotonicInstant::get().into_nanos())
}

/// Estimates the boot time corresponding to `utc`.
///
/// # Returns
/// - [`zx::BootInstant`]: estimated boot time;
/// - `bool`: true if the system UTC clock has been started (always true here).
pub fn estimate_boot_deadline_from_utc(utc: UtcInstant) -> (zx::BootInstant, bool) {
    (zx::BootInstant::from_nanos(utc.into_nanos()), true)
}

/// Duplicates a handle to the system UTC clock.
///
/// M6 has no UTC clock object, so this yields a default (invalid) handle.
pub fn duplicate_real_utc_clock_handle() -> Result<fuchsia_runtime::UtcClock, zx::Status> {
    Ok(fuchsia_runtime::UtcClock::default())
}

/// A guard that temporarily overrides the UTC clock for testing.
///
/// M6 has no override mechanism yet; this is a no-op guard retained for API
/// parity with upstream test code.
#[cfg(test)]
pub struct UtcClockOverrideGuard(());

#[cfg(test)]
impl UtcClockOverrideGuard {
    pub fn new(_test_clock: fuchsia_runtime::UtcClock) -> Self {
        Self(())
    }
}
