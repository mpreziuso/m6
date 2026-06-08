//! Minimal `syncio` shim for the M6 Starnix fork.
//!
//! Upstream `syncio` wraps Fuchsia's `zxio` C library. M6 has no zxio runtime,
//! but a handful of non-Fuchsia-runtime modules in the fork (I/O buffers, the
//! waiter, message control data) reference plain data types from `syncio`. This
//! crate provides exactly those types so the default (non-`fuchsia`) build
//! compiles. The full zxio-backed socket/file implementation remains gated
//! behind the `fuchsia` feature in `m6-starnix`.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

use bitflags::bitflags;

/// Raw zxio FFI data types referenced by the fork.
pub mod zxio {
    use core::ffi::c_void;

    /// A scatter/gather descriptor with a raw buffer pointer (zxio flavour).
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct zx_iovec {
        pub buffer: *mut c_void,
        pub capacity: usize,
    }

    impl Default for zx_iovec {
        fn default() -> Self {
            Self { buffer: core::ptr::null_mut(), capacity: 0 }
        }
    }

    /// A POSIX-style scatter/gather descriptor.
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct iovec {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    impl Default for iovec {
        fn default() -> Self {
            Self { iov_base: core::ptr::null_mut(), iov_len: 0 }
        }
    }

    /// The zxio signal bitset type.
    pub type zxio_signals_t = u32;

    /// Copies `count` bytes from `src` to `dest`.
    ///
    /// Upstream this performs a fault-trapping copy. M6 has no fault-trapping
    /// primitive here yet, so this is a plain `copy_nonoverlapping` and always
    /// reports success. Callers use this only as the fallback when the usercopy
    /// hermetic copier is unavailable.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reads of `count` bytes and `dest` valid for
    /// writes of `count` bytes; the regions must not overlap.
    pub unsafe fn zxio_default_maybe_faultable_copy(
        dest: *mut u8,
        src: *const u8,
        count: usize,
        _ret_dest: bool,
    ) -> bool {
        // SAFETY: Guaranteed by the caller's contract (see the doc comment).
        unsafe {
            core::ptr::copy_nonoverlapping(src, dest, count);
        }
        true
    }
}

/// Bitmask describing which node attributes are present / requested.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct zxio_node_attr_has_t {
    pub protocols: bool,
    pub abilities: bool,
    pub id: bool,
    pub content_size: bool,
    pub storage_size: bool,
    pub link_count: bool,
    pub creation_time: bool,
    pub modification_time: bool,
    pub change_time: bool,
    pub access_time: bool,
    pub mode: bool,
    pub uid: bool,
    pub gid: bool,
    pub rdev: bool,
    pub fsverity_options: bool,
    pub fsverity_root_hash: bool,
    pub fsverity_enabled: bool,
    pub object_type: bool,
    pub casefold: bool,
    pub wrapping_key_id: bool,
    pub selinux_context: bool,
    pub pending_access_time_update: bool,
}

bitflags! {
    /// Signals that can be observed on a zxio object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ZxioSignals: zxio::zxio_signals_t {
        const NONE            =      0;
        const READABLE        = 1 << 0;
        const WRITABLE        = 1 << 1;
        const READ_DISABLED   = 1 << 2;
        const WRITE_DISABLED  = 1 << 3;
        const READ_THRESHOLD  = 1 << 4;
        const WRITE_THRESHOLD = 1 << 5;
        const OUT_OF_BAND     = 1 << 6;
        const ERROR           = 1 << 7;
        const PEER_CLOSED     = 1 << 8;
    }
}

bitflags! {
    /// The flags for shutting down sockets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ZxioShutdownFlags: u32 {
        const WRITE = 1 << 0;
        const READ = 1 << 1;
    }
}

/// A zxio object handle.
///
/// Stub: M6 has no zxio runtime, so this never wraps a live object. The methods
/// exist so non-Fuchsia code that holds a [`ZxioWeak`] in inert socket/file
/// paths compiles; they are unreachable on the default build because
/// [`ZxioWeak::upgrade`] always returns `None`.
#[derive(Debug, Default)]
pub struct Zxio;

impl ControlMessage {
    /// Returns the size of this control message's data payload.
    pub fn get_data_size(&self) -> usize {
        match self {
            ControlMessage::IpTos(_) => 1,
            ControlMessage::IpTtl(_) => core::mem::size_of::<i32>(),
            ControlMessage::IpRecvOrigDstAddr(addr) => core::mem::size_of_val(addr),
            ControlMessage::Ipv6Tclass(_) => core::mem::size_of::<i32>(),
            ControlMessage::Ipv6HopLimit(_) => core::mem::size_of::<i32>(),
            ControlMessage::Ipv6PacketInfo { .. } => 4 + 16,
            ControlMessage::Timestamp { .. } => 16,
            ControlMessage::TimestampNs { .. } => 16,
        }
    }
}

impl Zxio {
    /// Begins an asynchronous wait. Stub: observes no signals.
    pub fn wait_begin(&self, _signals: zxio::zxio_signals_t) -> (usize, zx::Signals) {
        (0, zx::Signals::NONE)
    }

    /// Ends an asynchronous wait. Stub: observes no zxio signals.
    pub fn wait_end(&self, _signals: zx::Signals) -> zxio::zxio_signals_t {
        0
    }
}

/// A weak reference to a [`Zxio`] object.
///
/// Stub: cannot be upgraded on M6 (there is never a live backing object).
#[derive(Debug, Default, Clone)]
pub struct ZxioWeak;

impl ZxioWeak {
    /// Attempts to upgrade to a strong reference. Stub: always `None`.
    pub fn upgrade(&self) -> Option<alloc::sync::Arc<Zxio>> {
        None
    }
}

/// Socket-level ancillary (control) message data.
///
/// Faithful to upstream's enum shape; the M6 build only constructs these in
/// non-Fuchsia network code paths that are otherwise inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    IpTos(u8),
    IpTtl(u8),
    IpRecvOrigDstAddr([u8; 16]),
    Ipv6Tclass(u8),
    Ipv6HopLimit(u8),
    Ipv6PacketInfo { iface: u32, local_addr: [u8; 16] },
    Timestamp { sec: i64, usec: i64 },
    TimestampNs { sec: i64, nsec: i64 },
}
