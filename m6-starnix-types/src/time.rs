// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::zx_time as zx;
use linux_uapi::itimerval;
use starnix_uapi::errors::{Errno, error};
use starnix_uapi::{itimerspec, timespec, timeval};
use static_assertions::const_assert_eq;

const MICROS_PER_SECOND: i64 = 1000 * 1000;
pub const NANOS_PER_SECOND: i64 = 1000 * 1000 * 1000;

// Frequency of the "scheduler clock", which is used to report time values in some APIs, e.g. in
// `/proc` and `times()`. Passed to Linux processes by the loader as `AT_CLKTCK`.
pub const SCHEDULER_CLOCK_HZ: i64 = 100;

const_assert_eq!(NANOS_PER_SECOND % SCHEDULER_CLOCK_HZ, 0);
const NANOS_PER_SCHEDULER_TICK: i64 = NANOS_PER_SECOND / SCHEDULER_CLOCK_HZ;

pub fn timeval_from_time<T: zx::Timeline>(time: zx::Instant<T>) -> timeval {
    let nanos = time.into_nanos();
    timeval { tv_sec: nanos / NANOS_PER_SECOND, tv_usec: (nanos % NANOS_PER_SECOND) / 1000 }
}

pub fn timeval_from_duration<T: zx::Timeline>(duration: zx::Duration<T>) -> timeval {
    let nanos = duration.into_nanos();
    timeval { tv_sec: nanos / NANOS_PER_SECOND, tv_usec: (nanos % NANOS_PER_SECOND) / 1000 }
}

pub fn timespec_from_time<T: zx::Timeline>(time: zx::Instant<T>) -> timespec {
    let nanos = time.into_nanos();
    timespec { tv_sec: nanos / NANOS_PER_SECOND, tv_nsec: nanos % NANOS_PER_SECOND }
}

pub fn timespec_from_duration<T: zx::Timeline>(duration: zx::Duration<T>) -> timespec {
    let nanos = duration.into_nanos();
    timespec { tv_sec: nanos / NANOS_PER_SECOND, tv_nsec: nanos % NANOS_PER_SECOND }
}

pub fn duration_from_timespec<T: zx::Timeline>(ts: timespec) -> Result<zx::Duration<T>, Errno> {
    if ts.tv_nsec >= NANOS_PER_SECOND {
        return error!(EINVAL);
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return error!(EINVAL);
    }
    Ok(zx::Duration::from_seconds(ts.tv_sec) + zx::Duration::from_nanos(ts.tv_nsec))
}

pub fn duration_from_timeval<T: zx::Timeline>(tv: timeval) -> Result<zx::Duration<T>, Errno> {
    if tv.tv_usec < 0 || tv.tv_usec >= MICROS_PER_SECOND {
        return error!(EDOM);
    }
    Ok(zx::Duration::from_seconds(tv.tv_sec) + zx::Duration::from_micros(tv.tv_usec))
}

pub fn duration_from_poll_timeout(timeout_ms: i32) -> Result<zx::MonotonicDuration, Errno> {
    if timeout_ms == -1 {
        return Ok(zx::MonotonicDuration::INFINITE);
    }

    if timeout_ms < 0 {
        return error!(EINVAL);
    }

    Ok(zx::MonotonicDuration::from_millis(timeout_ms.into()))
}

pub fn itimerspec_from_itimerval(tv: itimerval) -> itimerspec {
    itimerspec {
        it_interval: timespec_from_timeval(tv.it_interval),
        it_value: timespec_from_timeval(tv.it_value),
    }
}

pub fn timespec_from_timeval(tv: timeval) -> timespec {
    timespec { tv_sec: tv.tv_sec, tv_nsec: tv.tv_usec * 1000 }
}

pub fn time_from_timeval<T: zx::Timeline + Copy>(tv: timeval) -> Result<zx::Instant<T>, Errno> {
    let duration = duration_from_timeval::<T>(tv)?;
    if duration.into_nanos() < 0 { error!(EINVAL) } else { Ok(zx::Instant::ZERO + duration) }
}

/// Returns a `zx::Instant` for the given `timespec`, treating it as an absolute point in time.
pub fn time_from_timespec<T: zx::Timeline>(ts: timespec) -> Result<zx::Instant<T>, Errno> {
    let duration = duration_from_timespec::<T>(ts)?;
    Ok(zx::Instant::ZERO + duration)
}

pub fn timespec_is_zero(ts: timespec) -> bool {
    ts.tv_sec == 0 && ts.tv_nsec == 0
}

/// Returns an `itimerspec` with `it_value` set to `deadline` and `it_interval` set to `interval`.
pub fn itimerspec_from_deadline_interval<T: zx::Timeline>(
    deadline: zx::Instant<T>,
    interval: zx::MonotonicDuration,
) -> itimerspec {
    itimerspec {
        it_interval: timespec_from_duration(interval),
        it_value: timespec_from_time(deadline),
    }
}

pub fn duration_to_scheduler_clock(duration: zx::MonotonicDuration) -> i64 {
    duration.into_nanos() / NANOS_PER_SCHEDULER_TICK
}
