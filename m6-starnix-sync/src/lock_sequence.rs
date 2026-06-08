//! Lock-sequence tracking via the `Locked` zero-sized context type.
//!
//! `Locked<L>` is a zero-cost proof token that records which lock level the
//! caller currently holds. Acquiring a new lock through a `Locked` reference
//! consumes it (via mutable borrow) and yields a `Locked` at the new level,
//! preventing out-of-order acquisition.

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::{LockBefore, LockEqualOrBefore, LockFor, RwLockFor};

// -- Locked context

/// Zero-sized lock-level witness.
///
/// `Locked<L>` carries no runtime data; it exists purely to thread lock-level
/// information through the type system. Methods on `Locked` enforce ordering
/// by requiring `L: LockBefore<M>` before level `M` can be acquired.
pub struct Locked<L>(PhantomData<L>);

impl<L> core::fmt::Debug for Locked<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Locked").finish()
    }
}

// -- Unlocked (root level)

/// The root lock level — "no lock held".
///
/// User code should implement `LockAfter<Unlocked>` for the top of any lock
/// ordering tree.
pub enum Unlocked {}

impl Unlocked {
    /// Create a new root-level locked context.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no locks in the ordering graph are currently
    /// held on the calling thread. Creating multiple `Unlocked` contexts
    /// concurrently can subvert ordering guarantees.
    #[inline(always)]
    pub unsafe fn new() -> &'static mut Locked<Unlocked> {
        Locked::fabricate()
    }

    /// Create an owned root-level locked context.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Unlocked::new`].
    #[inline(always)]
    pub unsafe fn new_instance() -> Locked<Unlocked> {
        Locked::<Unlocked>(PhantomData)
    }
}

impl LockEqualOrBefore<Unlocked> for Unlocked {}

// -- Locked implementation

impl<L> Locked<L> {
    /// Acquire the given lock.
    ///
    /// Requires that `M` can be locked after `L`.
    #[inline(always)]
    pub fn lock<'a, M, S>(&'a mut self, source: &'a S) -> S::Guard<'a>
    where
        M: 'a,
        S: LockFor<M>,
        L: LockBefore<M>,
    {
        let (data, _) = self.lock_and::<M, S>(source);
        data
    }

    /// Acquire the given lock and return a new locked context at level `M`.
    ///
    /// Requires that `M` can be locked after `L`.
    #[inline(always)]
    pub fn lock_and<'a, M, S>(&'a mut self, source: &'a S) -> (S::Guard<'a>, &'a mut Locked<M>)
    where
        M: 'a,
        S: LockFor<M>,
        L: LockBefore<M>,
    {
        let data = S::lock(source);
        (data, Locked::fabricate())
    }

    /// Acquire two locks at the same level in address order, returning both
    /// guards and a new locked context.
    #[inline(always)]
    pub fn lock_both_and<'a, M, S>(
        &'a mut self,
        source1: &'a S,
        source2: &'a S,
    ) -> (S::Guard<'a>, S::Guard<'a>, &'a mut Locked<M>)
    where
        M: 'a,
        S: LockFor<M>,
        L: LockBefore<M>,
    {
        let ptr1: *const S = source1;
        let ptr2: *const S = source2;
        if ptr1 < ptr2 {
            let g1 = S::lock(source1);
            let g2 = S::lock(source2);
            (g1, g2, Locked::fabricate())
        } else {
            let g2 = S::lock(source2);
            let g1 = S::lock(source1);
            (g1, g2, Locked::fabricate())
        }
    }

    /// Acquire two locks at the same level in address order.
    #[inline(always)]
    pub fn lock_both<'a, M, S>(
        &'a mut self,
        source1: &'a S,
        source2: &'a S,
    ) -> (S::Guard<'a>, S::Guard<'a>)
    where
        M: 'a,
        S: LockFor<M>,
        L: LockBefore<M>,
    {
        let (g1, g2, _) = self.lock_both_and(source1, source2);
        (g1, g2)
    }

    /// Acquire a read lock.
    #[inline(always)]
    pub fn read_lock<'a, M, S>(&'a mut self, source: &'a S) -> S::ReadGuard<'a>
    where
        M: 'a,
        S: RwLockFor<M>,
        L: LockBefore<M>,
    {
        let (data, _) = self.read_lock_and::<M, S>(source);
        data
    }

    /// Acquire a read lock and return a new locked context.
    #[inline(always)]
    pub fn read_lock_and<'a, M, S>(
        &'a mut self,
        source: &'a S,
    ) -> (S::ReadGuard<'a>, &'a mut Locked<M>)
    where
        M: 'a,
        S: RwLockFor<M>,
        L: LockBefore<M>,
    {
        let data = S::read_lock(source);
        (data, Locked::fabricate())
    }

    /// Acquire a write lock.
    #[inline(always)]
    pub fn write_lock<'a, M, S>(&'a mut self, source: &'a S) -> S::WriteGuard<'a>
    where
        M: 'a,
        S: RwLockFor<M>,
        L: LockBefore<M>,
    {
        let (data, _) = self.write_lock_and::<M, S>(source);
        data
    }

    /// Acquire a write lock and return a new locked context.
    #[inline(always)]
    pub fn write_lock_and<'a, M, S>(
        &'a mut self,
        source: &'a S,
    ) -> (S::WriteGuard<'a>, &'a mut Locked<M>)
    where
        M: 'a,
        S: RwLockFor<M>,
        L: LockBefore<M>,
    {
        let data = S::write_lock(source);
        (data, Locked::fabricate())
    }

    /// Restrict the context as if lock `M` had been acquired, without
    /// actually acquiring anything.
    ///
    /// This is safe because any lock reachable from `M` is also reachable
    /// from `L` (since `L` is equal to or before `M`).
    #[inline(always)]
    pub fn cast_locked<M>(&mut self) -> &mut Locked<M>
    where
        L: LockEqualOrBefore<M>,
    {
        Locked::fabricate()
    }

    // -- Internal helpers

    /// Fabricate a `&mut Locked<L>` out of thin air.
    ///
    /// This is sound because `Locked<L>` is a ZST (contains only
    /// `PhantomData`), so the dangling pointer is valid for reads and writes
    /// of zero bytes.
    fn fabricate<'a>() -> &'a mut Self {
        // SAFETY: `Locked<L>` is a zero-sized type. A dangling, well-aligned
        // pointer to a ZST is valid for conversion to a reference because:
        //  - `NonNull::dangling()` is properly aligned and non-null
        //  - ZST dereferences access zero bytes, so no memory is touched
        //  - Aliasing rules are trivially satisfied for ZSTs
        unsafe { NonNull::dangling().as_mut() }
    }
}
