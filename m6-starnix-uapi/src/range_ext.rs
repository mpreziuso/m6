// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

use core::cmp::{max, min};
use core::ops::Range;

/// Provides convenience methods for [`Range`].
pub trait RangeExt {
    /// Returns the intersection of self and rhs. If there is no intersection, the result will
    /// return true for .is_empty().
    fn intersect(&self, rhs: &Self) -> Self;
}

impl<K: Ord + Copy> RangeExt for Range<K> {
    fn intersect(&self, rhs: &Self) -> Self {
        max(self.start, rhs.start)..min(self.end, rhs.end)
    }
}
