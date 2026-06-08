// Minimal always-on socket type layer for M6 first-light.
//
// The full Fuchsia socket subsystem (`vfs::socket`, gated behind
// `feature = "fuchsia"`) is zxio/netlink/FIDL-heavy and off the hello-world +
// FAT32 path. But its *types* are woven into the VFS/task core — `SocketAddress`
// in `Message` (also used by pipes), `SocketHandle` in `FsNode.bound_socket` and
// the abstract-socket namespaces, `UnixSocket` in `namespace::bind_socket`. This
// module supplies exactly those types so the core compiles and runs without
// sockets, returning ENOSYS/None on the (unreachable for first-light) socket
// paths. Sockets return for real in M5; this layer is replaced by the gated
// module then.

#[allow(unused_imports)]
use m6_starnix_std::prelude::*;
use m6_starnix_std::sync::Arc;
use starnix_sync::{FileOpsCore, Locked};
use starnix_uapi::errors::Errno;

use crate::task::CurrentTask;
use crate::vfs::{DirEntryHandle, FsNodeHandle};

// -- Pure-data socket types (shared verbatim with the full module).
#[path = "socket/socket_types.rs"]
mod socket_types;
pub use socket_types::*;

/// Netlink socket address. Stub: netlink is gated out of the minimal core, but
/// `socket_types` references this type, so a placeholder definition is kept.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct NetlinkAddress {
    groups: u32,
    pid: u32,
}

impl NetlinkAddress {
    /// Creates a netlink address. Inert in the minimal core.
    pub fn new(pid: u32, groups: u32) -> Self {
        Self { pid, groups }
    }

    /// The netlink port id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The multicast group mask.
    pub fn groups(&self) -> u32 {
        self.groups
    }

    /// Serialises this address as a `sockaddr_nl` byte buffer
    /// (family:u16, pad:u16, pid:u32, groups:u32 — native-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        const AF_NETLINK: u16 = 16;
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&AF_NETLINK.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // nl_pad
        bytes.extend_from_slice(&self.pid.to_ne_bytes());
        bytes.extend_from_slice(&self.groups.to_ne_bytes());
        bytes
    }
}

/// An opaque socket object.
///
/// In the minimal core a `Socket` carries no implementation — there is no AF_*
/// backend wired. It exists so `FsNode`/abstract-namespace/`Message` code that
/// stores `SocketHandle` compiles; the operations below return errors/None.
#[derive(Debug, Default)]
pub struct Socket {
    _private: (),
}

/// A reference-counted handle to a [`Socket`].
pub type SocketHandle = Arc<Socket>;

impl Socket {
    /// Binds the socket to `address`. Inert: the minimal core has no socket
    /// backend, so binding is unsupported.
    pub fn bind(
        &self,
        _locked: &mut Locked<FileOpsCore>,
        _current_task: &CurrentTask,
        _address: SocketAddress,
    ) -> Result<(), Errno> {
        starnix_uapi::error!(ENOSYS)
    }

    /// Attempts to view this socket as a concrete socket type `T`. Always `None`
    /// in the minimal core (no concrete socket backends exist).
    pub fn downcast_socket<T>(&self) -> Option<&T> {
        None
    }
}

/// An AF_UNIX socket. Opaque in the minimal core.
#[derive(Debug, Default)]
pub struct UnixSocket {
    _private: (),
}

impl UnixSocket {
    /// Associates this socket with a freshly created filesystem node. Unreachable
    /// in the minimal core (`Socket::downcast_socket` always returns `None`), but
    /// present so the bind path type-checks.
    pub fn bind_socket_to_node(
        &self,
        _socket: &SocketHandle,
        _address: SocketAddress,
        _node: &FsNodeHandle,
    ) -> Result<(), Errno> {
        starnix_uapi::error!(ENOSYS)
    }
}

/// Socket-related syscall helpers. The minimal core only needs the control-
/// message pointer alias (used by the generic message buffers / pipes); the
/// actual socket syscalls are gated out of `syscall_table`.
pub mod syscalls {
    use starnix_uapi::uapi;
    use starnix_uapi::user_address::MultiArchUserRef;

    /// Multi-arch pointer to a `cmsghdr` control-message header.
    pub type CMsgHdrPtr = MultiArchUserRef<uapi::cmsghdr, uapi::arch32::cmsghdr>;
}
