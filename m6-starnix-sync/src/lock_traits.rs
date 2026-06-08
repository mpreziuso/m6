//! Traits describing how to acquire locks on a given type for a given level.

use core::ops::{Deref, DerefMut};

/// Describes how to acquire a mutex-style lock on `Self` for lock level `L`.
///
/// An implementation of `LockFor<L>` for some `Self` means that `Self` holds
/// state protected by the lock indicated by `L`.
pub trait LockFor<L> {
    /// The data produced by locking the state indicated by `L`.
    type Data;

    /// A guard providing read and write access to the data.
    type Guard<'l>: DerefMut<Target = Self::Data>
    where
        Self: 'l;

    /// Lock `Self` for lock level `L`.
    fn lock(&self) -> Self::Guard<'_>;
}

/// Describes how to acquire reader/writer locks on `Self` for lock level `L`.
///
/// An implementation of `RwLockFor<L>` for some `Self` means that `Self` holds
/// state protected by the read-write lock indicated by `L`.
pub trait RwLockFor<L> {
    /// The data produced by locking the state indicated by `L`.
    type Data;

    /// A guard providing read access to the data.
    type ReadGuard<'l>: Deref<Target = Self::Data>
    where
        Self: 'l;

    /// A guard providing write access to the data.
    type WriteGuard<'l>: DerefMut<Target = Self::Data>
    where
        Self: 'l;

    /// Acquire a read lock on the data in `Self` indicated by `L`.
    fn read_lock(&self) -> Self::ReadGuard<'_>;

    /// Acquire a write lock on the data in `Self` indicated by `L`.
    fn write_lock(&self) -> Self::WriteGuard<'_>;
}
