//! Generic capability handle wrapper

/// A generic handle wrapping an M6 capability pointer.
///
/// In Zircon, handles are unforgeable tokens to kernel objects.
/// In M6, this wraps a CPtr (capability pointer into the CSpace).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u64);

impl Handle {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(&self) -> u64 {
        self.0
    }

    pub const fn is_invalid(&self) -> bool {
        self.0 == 0
    }
}

impl Default for Handle {
    fn default() -> Self {
        Self::INVALID
    }
}
