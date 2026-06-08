//! Zircon port packets
//!
//! Minimal stubs for the packet types delivered through a [`crate::Port`].

use crate::sys::zx_page_request_command_t;
use core::ops::Range;

/// The user-defined payload of a [`Packet`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct UserPacket([u8; 32]);

impl UserPacket {
    /// Builds a user packet from a 32-byte array.
    pub const fn from_u8_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The payload of a pager packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PagerPacket {
    command: zx_page_request_command_t,
    range: Range<u64>,
}

impl PagerPacket {
    /// Returns the pager command.
    pub fn command(&self) -> zx_page_request_command_t {
        self.command
    }

    /// Returns the affected byte range.
    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }
}

/// The decoded contents of a [`Packet`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PacketContents {
    /// A user-queued packet.
    User(UserPacket),
    /// A pager request packet.
    Pager(PagerPacket),
}

/// A packet received from or queued to a port.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Packet {
    key: u64,
    status: i32,
    contents: PacketContents,
}

impl Packet {
    /// Builds a user packet with the given key, status and payload.
    pub fn from_user_packet(key: u64, status: i32, user: UserPacket) -> Self {
        Self {
            key,
            status,
            contents: PacketContents::User(user),
        }
    }

    /// Returns the packet key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the packet status.
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Returns the decoded contents.
    pub fn contents(&self) -> PacketContents {
        self.contents.clone()
    }
}
