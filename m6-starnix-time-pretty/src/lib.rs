// time_pretty — Starnix-fork shim for M6 (no_std).
//
// Ported verbatim from Fuchsia `//src/sys/time/timekeeper/pretty`. Adapted for
// `no_std`: `std::sync::LazyLock` + `Vec` of units becomes a plain `const`
// array (the data is static anyway), and `String`/`format!` come from `alloc`.
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

// This may be already handled by something, but I don't want new deps.
const USEC_IN_NANOS: i64 = 1000;
pub const MSEC_IN_NANOS: i64 = 1000 * USEC_IN_NANOS;
const SEC_IN_NANOS: i64 = 1000 * MSEC_IN_NANOS;
const MIN_IN_NANOS: i64 = SEC_IN_NANOS * 60;
const HOUR_IN_NANOS: i64 = MIN_IN_NANOS * 60;
const DAY_IN_NANOS: i64 = HOUR_IN_NANOS * 24;
const WEEK_IN_NANOS: i64 = DAY_IN_NANOS * 7;
const YEAR_IN_NANOS: i64 = DAY_IN_NANOS * 365; // Approximate.

const UNITS: [(i64, &str); 9] = [
    (YEAR_IN_NANOS, "year(s)"),
    (WEEK_IN_NANOS, "week(s)"),
    (DAY_IN_NANOS, "day(s)"),
    (HOUR_IN_NANOS, "h"),
    (MIN_IN_NANOS, "min"),
    (SEC_IN_NANOS, "s"),
    (MSEC_IN_NANOS, "ms"),
    (USEC_IN_NANOS, "μs"),
    (1, "ns"),
];

/// Formats a time value into a simplistic human-readable string.  This is meant
/// to be a human-friendly, but not an impeccable format.
pub fn format_common(mut value: i64) -> String {
    let value_copy = value;
    let mut repr: Vec<String> = vec![];
    for (unit_value, unit_str) in UNITS.iter() {
        if value == 0 {
            break;
        }
        let num_units = value / unit_value;
        if num_units.abs() > 0 {
            repr.push(format!("{}{}", num_units, unit_str));
            value %= unit_value;
        }
    }
    if repr.is_empty() {
        repr.push("0ns".to_string());
    }
    // 1year(s)_3week(s)_4day(s)_1h_2m_340ms. Not ideal but user-friendly enough.
    let repr = repr.join("_");

    let mut ret = vec![];
    ret.push(repr);
    // Also add the full nanosecond value too.
    ret.push(format!("({})", value_copy));
    ret.join(" ")
}

/// Pretty prints a timer value into a simplistic format.
pub fn format_timer<T: zx::Timeline>(timer: zx::Instant<T>) -> String {
    format_common(timer.into_nanos())
}

/// Pretty prints a duration into a simplistic format.
pub fn format_duration<T: zx::Timeline>(duration: zx::Duration<T>) -> String {
    format_common(duration.into_nanos())
}
