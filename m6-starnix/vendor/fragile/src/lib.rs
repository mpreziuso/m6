//! Minimal `no_std` `fragile::Fragile` shim for the M6 Starnix fork.
//!
//! Upstream `Fragile<T>` makes a `!Send` value movable across threads by
//! storing the owning thread id and panicking on access from any other thread.
//! M6's first-light bring-up is single-threaded, so this stores the value
//! directly and (unsafely) asserts `Send`/`Sync`. The single-thread invariant
//! makes that sound for bring-up; when M6 runs the Starnix service across
//! threads this must regain the thread-id guard. The accessor surface
//! (`new`/`get`/`get_mut`/`into_inner`) matches upstream.

#![no_std]

use core::cell::UnsafeCell;

/// A wrapper that allows a `!Send` value to live in a `Send`/`Sync` context.
pub struct Fragile<T> {
    value: UnsafeCell<T>,
}

// SAFETY: bring-up is single-threaded, so the value is only ever touched from
// the one thread that owns it. See the module note — this is the documented
// single-thread approximation of upstream's thread-id-guarded `Fragile`.
unsafe impl<T> Send for Fragile<T> {}
unsafe impl<T> Sync for Fragile<T> {}

impl<T> Fragile<T> {
    /// Wraps `value`.
    pub fn new(value: T) -> Self {
        Self { value: UnsafeCell::new(value) }
    }


    /// Returns a shared reference to the wrapped value.
    pub fn get(&self) -> &T {
        // SAFETY: single-threaded bring-up; no concurrent access (module note).
        unsafe { &*self.value.get() }
    }

    /// Returns a mutable reference to the wrapped value.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// Consumes the wrapper, returning the inner value.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }

    /// Returns a reference if accessed from the owning thread. Always `Some` in
    /// the single-thread shim.
    pub fn try_get(&self) -> Result<&T, InvalidThreadAccess> {
        Ok(self.get())
    }
}

impl<T> From<T> for Fragile<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> core::fmt::Debug for Fragile<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Fragile")
    }
}

/// Error returned by the thread-checked accessors upstream. Never produced by
/// the single-thread shim.
#[derive(Debug)]
pub struct InvalidThreadAccess;
