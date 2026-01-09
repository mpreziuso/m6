//! Capability access rights
//!
//! Rights are orthogonal and can be independently granted or revoked.
//! Interpretation is object-type specific:
//!
//! - **Read**: Receive for IPC endpoints, read for memory frames
//! - **Write**: Send for IPC endpoints, write for memory frames
//! - **Grant**: Transfer any capabilities via IPC
//! - **GrantReply**: Transfer reply capabilities only via IPC

use core::fmt;

/// Access rights for capabilities.
///
/// Following the seL4 model, rights are orthogonal and can be independently
/// attenuated (reduced) but never escalated (increased). When minting a
/// derived capability, the new rights must be a subset of the source rights.
///
/// # Layout
///
/// Rights are packed into a single byte for efficient storage in [`CapSlot`](crate::CapSlot).
/// The layout is:
/// - Bit 0: Read
/// - Bit 1: Write
/// - Bit 2: Grant
/// - Bit 3: GrantReply
/// - Bits 4-7: Reserved (must be zero)
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
#[repr(transparent)]
pub struct CapRights(u8);

impl CapRights {
    /// No rights (empty capability).
    pub const NONE: Self = Self(0);

    /// Read permission.
    ///
    /// For IPC: receive messages from an endpoint.
    /// For memory: read from a mapped frame.
    pub const READ: Self = Self(1 << 0);

    /// Write permission.
    ///
    /// For IPC: send messages to an endpoint.
    /// For memory: write to a mapped frame.
    pub const WRITE: Self = Self(1 << 1);

    /// Grant permission.
    ///
    /// Allows transferring any capabilities through IPC.
    /// This is a powerful right that should be granted sparingly.
    pub const GRANT: Self = Self(1 << 2);

    /// Grant-Reply permission.
    ///
    /// Allows transferring reply capabilities only through IPC.
    /// This is a restricted form of Grant for call-reply patterns.
    pub const GRANT_REPLY: Self = Self(1 << 3);

    /// All rights.
    pub const ALL: Self = Self(0x0F);

    /// Read and Write rights.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);

    /// Read, Write, and Grant rights.
    pub const RWG: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::GRANT.0);

    /// Read, Write, Grant, and GrantReply rights.
    pub const RWGG: Self = Self(Self::ALL.0);

    /// Create rights from individual flags.
    #[inline]
    #[must_use]
    pub const fn new(read: bool, write: bool, grant: bool, grant_reply: bool) -> Self {
        let mut bits = 0u8;
        if read {
            bits |= Self::READ.0;
        }
        if write {
            bits |= Self::WRITE.0;
        }
        if grant {
            bits |= Self::GRANT.0;
        }
        if grant_reply {
            bits |= Self::GRANT_REPLY.0;
        }
        Self(bits)
    }

    /// Create rights from raw bits.
    ///
    /// Only the lower 4 bits are used; upper bits are masked off.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0x0F)
    }

    /// Get the raw bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Check if these rights contain the Read right.
    #[inline]
    #[must_use]
    pub const fn has_read(self) -> bool {
        (self.0 & Self::READ.0) != 0
    }

    /// Check if these rights contain the Write right.
    #[inline]
    #[must_use]
    pub const fn has_write(self) -> bool {
        (self.0 & Self::WRITE.0) != 0
    }

    /// Check if these rights contain the Grant right.
    #[inline]
    #[must_use]
    pub const fn has_grant(self) -> bool {
        (self.0 & Self::GRANT.0) != 0
    }

    /// Check if these rights contain the GrantReply right.
    #[inline]
    #[must_use]
    pub const fn has_grant_reply(self) -> bool {
        (self.0 & Self::GRANT_REPLY.0) != 0
    }

    /// Check if these rights contain all the specified rights.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Intersect rights (logical AND).
    ///
    /// Used when minting derived capabilities with reduced rights.
    /// The result contains only rights present in both operands.
    #[inline]
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Union rights (logical OR).
    ///
    /// Note: This should only be used during initial capability creation,
    /// never to escalate existing rights.
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if this set of rights is a subset of another.
    ///
    /// Returns true if all rights in `self` are also present in `other`.
    /// This is used to verify that minting doesn't escalate rights.
    #[inline]
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        (self.0 & !other.0) == 0
    }

    /// Check if no rights are set.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for CapRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_set();
        if self.has_read() {
            list.entry(&"Read");
        }
        if self.has_write() {
            list.entry(&"Write");
        }
        if self.has_grant() {
            list.entry(&"Grant");
        }
        if self.has_grant_reply() {
            list.entry(&"GrantReply");
        }
        list.finish()
    }
}

impl fmt::Display for CapRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.has_read() { "R" } else { "-" },
            if self.has_write() { "W" } else { "-" },
            if self.has_grant() { "G" } else { "-" },
            if self.has_grant_reply() { "g" } else { "-" },
        )
    }
}

impl core::ops::BitAnd for CapRights {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersect(rhs)
    }
}

impl core::ops::BitOr for CapRights {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rights_construction() {
        assert_eq!(CapRights::NONE.bits(), 0);
        assert_eq!(CapRights::ALL.bits(), 0x0F);
        assert_eq!(CapRights::RW.bits(), 0x03);
        assert_eq!(CapRights::RWG.bits(), 0x07);
    }

    #[test]
    fn test_rights_contains() {
        assert!(CapRights::ALL.contains(CapRights::READ));
        assert!(CapRights::ALL.contains(CapRights::RW));
        assert!(!CapRights::READ.contains(CapRights::WRITE));
        assert!(CapRights::RW.contains(CapRights::READ));
    }

    #[test]
    fn test_rights_subset() {
        assert!(CapRights::READ.is_subset_of(CapRights::ALL));
        assert!(CapRights::RW.is_subset_of(CapRights::RWG));
        assert!(!CapRights::GRANT.is_subset_of(CapRights::RW));
    }

    #[test]
    fn test_rights_intersect() {
        assert_eq!(CapRights::ALL.intersect(CapRights::RW), CapRights::RW);
        assert_eq!(CapRights::READ.intersect(CapRights::WRITE), CapRights::NONE);
    }
}
