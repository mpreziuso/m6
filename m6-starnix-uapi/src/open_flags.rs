// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2021 The Fuchsia Authors. BSD license.

use core::fmt;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct OpenFlags: u32 {
        const ACCESS_MASK = 0o3;
        const RDONLY = 0o0;
        const WRONLY = 0o1;
        const RDWR = 0o2;
        const CREAT = 0o100;
        const EXCL = 0o200;
        const NOCTTY = 0o400;
        const TRUNC = 0o1000;
        const APPEND = 0o2000;
        const NONBLOCK = 0o4000;
        const ASYNC = 0o20000;
        const DSYNC = 0o10000;
        // aarch64 (asm-generic) values, not the x86 ones upstream ships:
        // O_DIRECTORY and O_DIRECT are swapped vs x86, likewise NOFOLLOW/LARGEFILE.
        const DIRECTORY = 0o40000;
        const NOFOLLOW = 0o100000;
        const DIRECT = 0o200000;
        const LARGEFILE = 0o400000;
        const NOATIME = 0o1000000;
        const CLOEXEC = 0o2000000;
        const SYNC = 0o4010000;
        const PATH = 0o10000000;
        // __O_TMPFILE | O_DIRECTORY (aarch64).
        const TMPFILE = 0o20040000;
        const NDELAY = Self::NONBLOCK.bits();
    }
}

impl OpenFlags {
    pub fn can_read(&self) -> bool {
        let access = self.bits() & Self::ACCESS_MASK.bits();
        access == Self::RDONLY.bits() || access == Self::RDWR.bits()
    }

    pub fn can_write(&self) -> bool {
        let access = self.bits() & Self::ACCESS_MASK.bits();
        access == Self::WRONLY.bits() || access == Self::RDWR.bits()
    }
}

impl fmt::Display for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#o}", self.bits())
    }
}

// -- AtomicOpenFlags
//
// M6: upstream generates this via the Fuchsia-internal `atomic_bitflags!` macro (which is not
// published). We hand-roll an equivalent over `core::sync::atomic::AtomicU32`, mirroring the
// method set and signatures so the fork compiles unchanged.

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Default)]
pub struct AtomicOpenFlags {
    inner: AtomicU32,
}

impl AtomicOpenFlags {
    pub fn new(initial: OpenFlags) -> Self {
        Self {
            inner: AtomicU32::new(initial.bits()),
        }
    }

    pub fn load(&self, order: Ordering) -> OpenFlags {
        OpenFlags::from_bits_truncate(self.inner.load(order))
    }

    pub fn store(&self, val: OpenFlags, order: Ordering) {
        self.inner.store(val.bits(), order);
    }

    pub fn fetch_or(&self, val: OpenFlags, order: Ordering) -> OpenFlags {
        OpenFlags::from_bits_truncate(self.inner.fetch_or(val.bits(), order))
    }

    pub fn fetch_and(&self, val: OpenFlags, order: Ordering) -> OpenFlags {
        OpenFlags::from_bits_truncate(self.inner.fetch_and(val.bits(), order))
    }

    pub fn swap(&self, val: OpenFlags, order: Ordering) -> OpenFlags {
        OpenFlags::from_bits_truncate(self.inner.swap(val.bits(), order))
    }

    pub fn compare_exchange(
        &self,
        current: OpenFlags,
        new: OpenFlags,
        success: Ordering,
        failure: Ordering,
    ) -> Result<OpenFlags, OpenFlags> {
        self.inner
            .compare_exchange(current.bits(), new.bits(), success, failure)
            .map(OpenFlags::from_bits_truncate)
            .map_err(OpenFlags::from_bits_truncate)
    }

    pub fn update(
        &self,
        value: OpenFlags,
        mask: OpenFlags,
        set_order: Ordering,
        fetch_order: Ordering,
    ) -> OpenFlags {
        self.inner
            .fetch_update(set_order, fetch_order, |old| {
                Some((old & !mask.bits()) | (value.bits() & mask.bits()))
            })
            .map(OpenFlags::from_bits_truncate)
            .unwrap()
    }
}
