//! Concrete lock wrappers that integrate with the ordering system.
//!
//! M6: port of Fuchsia's `locks.rs`. Upstream backed `Mutex`/`RwLock` with
//! `fuchsia_sync`; here we back them with `spin` via `lock_api`, which also
//! gives us `MappedMutexGuard` and `MutexGuard::map` for free. The
//! `AsyncUnlockable` trait and `ordered_lock`'s async machinery (which depended
//! on `async_trait`/`scopeguard`) are omitted as they are unused by the M6 core.

extern crate alloc;

use alloc::vec::Vec;
use core::any;
use core::fmt;
use core::marker::PhantomData;

use crate::{LockAfter, LockBefore, LockFor, Locked, RwLockFor, UninterruptibleLock};

// M6: lock_api-backed primitives over spin's raw locks. These type aliases give
// the same public names the Starnix core expects, plus `MappedMutexGuard`.
pub type Mutex<T> = lock_api::Mutex<spin::Mutex<()>, T>;
pub type MutexGuard<'a, T> = lock_api::MutexGuard<'a, spin::Mutex<()>, T>;
pub type MappedMutexGuard<'a, T> = lock_api::MappedMutexGuard<'a, spin::Mutex<()>, T>;
pub type RwLock<T> = lock_api::RwLock<spin::RwLock<()>, T>;
pub type RwLockReadGuard<'a, T> = lock_api::RwLockReadGuard<'a, spin::RwLock<()>, T>;
pub type RwLockWriteGuard<'a, T> = lock_api::RwLockWriteGuard<'a, spin::RwLock<()>, T>;

/// Lock `m1` and `m2` in a consistent order (using their memory addresses).
///
/// This ensures `ordered_lock(m1, m2)` and `ordered_lock(m2, m1)` will not
/// deadlock against each other.
pub fn ordered_lock<'a, T>(
    m1: &'a Mutex<T>,
    m2: &'a Mutex<T>,
) -> (MutexGuard<'a, T>, MutexGuard<'a, T>) {
    let ptr1: *const Mutex<T> = m1;
    let ptr2: *const Mutex<T> = m2;
    if ptr1 < ptr2 {
        let g1 = m1.lock();
        let g2 = m2.lock();
        (g1, g2)
    } else {
        let g2 = m2.lock();
        let g1 = m1.lock();
        (g1, g2)
    }
}

/// Acquire multiple mutexes in a consistent order based on their memory
/// addresses to avoid deadlocks, returning the guards in the input order.
pub fn ordered_lock_vec<'a, T>(mutexes: &[&'a Mutex<T>]) -> Vec<MutexGuard<'a, T>> {
    let mut indexed_mutexes =
        mutexes.iter().enumerate().map(|(i, m)| (i, *m)).collect::<Vec<_>>();

    indexed_mutexes.sort_by_key(|(_, m)| *m as *const Mutex<T>);

    let mut guards = indexed_mutexes
        .into_iter()
        .map(|(i, m)| (i, m.lock()))
        .collect::<Vec<_>>();

    guards.sort_by_key(|(i, _)| *i);

    guards.into_iter().map(|(_, g)| g).collect::<Vec<_>>()
}

// -- OrderedMutex

/// A `Mutex` wrapper that requires a `Locked` context to acquire.
///
/// `L` is a phantom lock level type that must come after `UninterruptibleLock`
/// in the lock ordering graph. Acquiring the lock requires presenting a
/// `Locked<P>` context where `P: LockBefore<L>`.
pub struct OrderedMutex<T, L: LockAfter<UninterruptibleLock>> {
    mutex: Mutex<T>,
    _phantom: PhantomData<L>,
}

impl<T: Default, L: LockAfter<UninterruptibleLock>> Default for OrderedMutex<T, L> {
    fn default() -> Self {
        Self {
            mutex: Default::default(),
            _phantom: Default::default(),
        }
    }
}

impl<T: fmt::Debug, L: LockAfter<UninterruptibleLock>> fmt::Debug for OrderedMutex<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OrderedMutex({:?}, {})", self.mutex, any::type_name::<L>())
    }
}

impl<T, L: LockAfter<UninterruptibleLock>> LockFor<L> for OrderedMutex<T, L> {
    type Data = T;
    type Guard<'a>
        = MutexGuard<'a, T>
    where
        T: 'a,
        L: 'a;
    fn lock(&self) -> Self::Guard<'_> {
        self.mutex.lock()
    }
}

impl<T, L: LockAfter<UninterruptibleLock>> OrderedMutex<T, L> {
    pub const fn new(t: T) -> Self {
        Self {
            mutex: Mutex::new(t),
            _phantom: PhantomData,
        }
    }

    pub fn lock<'a, P>(&'a self, locked: &'a mut Locked<P>) -> <Self as LockFor<L>>::Guard<'a>
    where
        P: LockBefore<L>,
    {
        locked.lock(self)
    }

    pub fn lock_and<'a, P>(
        &'a self,
        locked: &'a mut Locked<P>,
    ) -> (<Self as LockFor<L>>::Guard<'a>, &'a mut Locked<L>)
    where
        P: LockBefore<L>,
    {
        locked.lock_and(self)
    }
}

/// Lock two `OrderedMutex` of the same level in a consistent order. Returns both
/// guards and a new locked context.
pub fn lock_both<'a, T, L: LockAfter<UninterruptibleLock>, P>(
    locked: &'a mut Locked<P>,
    m1: &'a OrderedMutex<T, L>,
    m2: &'a OrderedMutex<T, L>,
) -> (MutexGuard<'a, T>, MutexGuard<'a, T>, &'a mut Locked<L>)
where
    P: LockBefore<L>,
{
    locked.lock_both_and(m1, m2)
}

// -- OrderedRwLock

/// An `RwLock` wrapper that requires a `Locked` context to acquire.
///
/// `L` is a phantom lock level type that must come after `UninterruptibleLock`
/// in the lock ordering graph.
pub struct OrderedRwLock<T, L: LockAfter<UninterruptibleLock>> {
    rwlock: RwLock<T>,
    _phantom: PhantomData<L>,
}

impl<T: Default, L: LockAfter<UninterruptibleLock>> Default for OrderedRwLock<T, L> {
    fn default() -> Self {
        Self {
            rwlock: Default::default(),
            _phantom: Default::default(),
        }
    }
}

impl<T: fmt::Debug, L: LockAfter<UninterruptibleLock>> fmt::Debug for OrderedRwLock<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OrderedRwLock({:?}, {})", self.rwlock, any::type_name::<L>())
    }
}

impl<T, L: LockAfter<UninterruptibleLock>> RwLockFor<L> for OrderedRwLock<T, L> {
    type Data = T;
    type ReadGuard<'a>
        = RwLockReadGuard<'a, T>
    where
        T: 'a,
        L: 'a;
    type WriteGuard<'a>
        = RwLockWriteGuard<'a, T>
    where
        T: 'a,
        L: 'a;
    fn read_lock(&self) -> Self::ReadGuard<'_> {
        self.rwlock.read()
    }
    fn write_lock(&self) -> Self::WriteGuard<'_> {
        self.rwlock.write()
    }
}

impl<T, L: LockAfter<UninterruptibleLock>> OrderedRwLock<T, L> {
    pub const fn new(t: T) -> Self {
        Self {
            rwlock: RwLock::new(t),
            _phantom: PhantomData,
        }
    }

    pub fn read<'a, P>(&'a self, locked: &'a mut Locked<P>) -> <Self as RwLockFor<L>>::ReadGuard<'a>
    where
        P: LockBefore<L>,
    {
        locked.read_lock(self)
    }

    pub fn write<'a, P>(
        &'a self,
        locked: &'a mut Locked<P>,
    ) -> <Self as RwLockFor<L>>::WriteGuard<'a>
    where
        P: LockBefore<L>,
    {
        locked.write_lock(self)
    }

    pub fn read_and<'a, P>(
        &'a self,
        locked: &'a mut Locked<P>,
    ) -> (<Self as RwLockFor<L>>::ReadGuard<'a>, &'a mut Locked<L>)
    where
        P: LockBefore<L>,
    {
        locked.read_lock_and(self)
    }

    pub fn write_and<'a, P>(
        &'a self,
        locked: &'a mut Locked<P>,
    ) -> (<Self as RwLockFor<L>>::WriteGuard<'a>, &'a mut Locked<L>)
    where
        P: LockBefore<L>,
    {
        locked.write_lock_and(self)
    }
}
