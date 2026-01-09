//! Badge values for capability identification
//!
//! A badge is an immutable value attached to a capability during minting.
//! When a message is sent through a badged endpoint, the receiver sees the
//! badge value, allowing them to identify the sender without needing a
//! separate authentication mechanism.
//!
//! # Usage
//!
//! Badges are typically used in capability-based systems to:
//!
//! 1. **Identify senders**: A server mints badged endpoint capabilities for
//!    each client. When receiving messages, the badge identifies which client
//!    sent the message.
//!
//! 2. **Distinguish resources**: A server can mint capabilities with different
//!    badges for different resources, using the badge to identify which
//!    resource the client is accessing.
//!
//! 3. **Aggregate notifications**: For notification objects, multiple badges
//!    are OR'd together, allowing a single wait to detect signals from
//!    multiple sources.

use core::fmt;

/// A badge value for capability identification.
///
/// Badges are 64-bit values attached to capabilities during minting.
/// They are immutable once set and are delivered to the receiver during
/// IPC operations.
///
/// # Zero Badge
///
/// A badge of zero (`Badge::NONE`) indicates an unbadged capability.
/// This is the default for original (non-minted) capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Badge(u64);

impl Badge {
    /// No badge (unbadged capability).
    ///
    /// Indicates this capability was not minted from another capability,
    /// or was minted without specifying a badge.
    pub const NONE: Self = Self(0);

    /// Maximum badge value.
    pub const MAX: Self = Self(u64::MAX);

    /// Create a new badge with the given value.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw badge value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Check if this is an unbadged capability (badge is zero).
    #[inline]
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Check if this capability has a badge (badge is non-zero).
    #[inline]
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }

    /// Combine badges using logical OR.
    ///
    /// This is used for notification objects where signals from multiple
    /// sources are aggregated. Each source has a distinct badge bit, and
    /// OR'ing them together indicates which sources have signalled.
    #[inline]
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if this badge contains all bits of another badge.
    ///
    /// Useful for checking if a combined notification badge includes
    /// a specific source's badge.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl fmt::Debug for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            write!(f, "Badge::NONE")
        } else {
            write!(f, "Badge({:#018x})", self.0)
        }
    }
}

impl fmt::Display for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            write!(f, "none")
        } else {
            write!(f, "{:#x}", self.0)
        }
    }
}

impl fmt::LowerHex for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Badge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl From<u64> for Badge {
    #[inline]
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Badge> for u64 {
    #[inline]
    fn from(badge: Badge) -> Self {
        badge.0
    }
}

impl core::ops::BitOr for Badge {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.combine(rhs)
    }
}

impl core::ops::BitOrAssign for Badge {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for Badge {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badge_none() {
        assert!(Badge::NONE.is_none());
        assert!(!Badge::NONE.is_some());
        assert_eq!(Badge::NONE.value(), 0);
    }

    #[test]
    fn test_badge_value() {
        let badge = Badge::new(0x1234);
        assert!(!badge.is_none());
        assert!(badge.is_some());
        assert_eq!(badge.value(), 0x1234);
    }

    #[test]
    fn test_badge_combine() {
        let a = Badge::new(0x01);
        let b = Badge::new(0x02);
        let combined = a.combine(b);
        assert_eq!(combined.value(), 0x03);
        assert!(combined.contains(a));
        assert!(combined.contains(b));
    }
}
