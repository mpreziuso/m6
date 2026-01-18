//! Read-write lock implementation
//!
//! Provides a read-write lock that allows multiple readers or a single writer.
//! Uses spinlock-based synchronisation for simplicity.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

/// A read-write lock.
///
/// This lock allows multiple readers or exactly one writer at a time.
/// Currently uses spinlocks for simplicity.
///
/// # Example
///
/// ```ignore
/// use m6_std::sync::RwLock;
///
/// let lock = RwLock::new(5);
///
/// // Many readers can hold the lock at once
/// {
///     let r1 = lock.read();
///     let r2 = lock.read();
///     assert_eq!(*r1, 5);
///     assert_eq!(*r2, 5);
/// }
///
/// // Only one writer at a time
/// {
///     let mut w = lock.write();
///     *w += 1;
/// }
/// ```
pub struct RwLock<T: ?Sized> {
    /// Lock state:
    /// - 0: unlocked
    /// - 1..=MAX-1: number of readers holding the lock
    /// - MAX (0xFFFFFFFF): writer holding the lock
    state: AtomicU32,
    data: UnsafeCell<T>,
}

/// Value indicating a writer holds the lock.
const WRITER: u32 = u32::MAX;

// SAFETY: RwLock provides interior mutability with synchronisation
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Creates a new rwlock in an unlocked state.
    #[inline]
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Consumes this rwlock, returning the underlying data.
    #[inline]
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Acquires the lock for reading, blocking until available.
    ///
    /// Multiple readers can hold the lock simultaneously.
    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let state = self.state.load(Ordering::Relaxed);
            // Can't acquire read lock if writer is holding or about to hold
            if state == WRITER {
                core::hint::spin_loop();
                continue;
            }
            // Try to increment reader count
            if self
                .state
                .compare_exchange_weak(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwLockReadGuard { rwlock: self };
            }
            core::hint::spin_loop();
        }
    }

    /// Attempts to acquire the lock for reading without blocking.
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let state = self.state.load(Ordering::Relaxed);
        if state == WRITER {
            return None;
        }
        if self
            .state
            .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockReadGuard { rwlock: self })
        } else {
            None
        }
    }

    /// Acquires the lock for writing, blocking until available.
    ///
    /// Only one writer can hold the lock at a time, and no readers.
    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            // Try to acquire exclusive lock (0 -> WRITER)
            if self
                .state
                .compare_exchange_weak(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwLockWriteGuard { rwlock: self };
            }
            core::hint::spin_loop();
        }
    }

    /// Attempts to acquire the lock for writing without blocking.
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(RwLockWriteGuard { rwlock: self })
        } else {
            None
        }
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// This method requires exclusive access, so no actual locking needs to occur.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Returns whether the lock is currently held by a writer.
    #[inline]
    pub fn is_write_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) == WRITER
    }

    /// Returns the number of current readers.
    ///
    /// Returns 0 if a writer holds the lock.
    #[inline]
    pub fn reader_count(&self) -> u32 {
        let state = self.state.load(Ordering::Relaxed);
        if state == WRITER { 0 } else { state }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_read() {
            Some(guard) => f.debug_struct("RwLock").field("data", &&*guard).finish(),
            None => {
                struct LockedPlaceholder;
                impl core::fmt::Debug for LockedPlaceholder {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        f.write_str("<locked>")
                    }
                }
                f.debug_struct("RwLock")
                    .field("data", &LockedPlaceholder)
                    .finish()
            }
        }
    }
}

/// RAII read guard for a RwLock.
///
/// When this guard is dropped, the read lock will be released.
pub struct RwLockReadGuard<'a, T: ?Sized> {
    rwlock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: We hold a read lock, so shared access is safe
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.rwlock.state.fetch_sub(1, Ordering::Release);
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for RwLockReadGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + core::fmt::Display> core::fmt::Display for RwLockReadGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&**self, f)
    }
}

/// RAII write guard for a RwLock.
///
/// When this guard is dropped, the write lock will be released.
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    rwlock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: We hold the write lock, so exclusive access is safe
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the write lock, so exclusive access is safe
        unsafe { &mut *self.rwlock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.rwlock.state.store(0, Ordering::Release);
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for RwLockWriteGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + core::fmt::Display> core::fmt::Display for RwLockWriteGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&**self, f)
    }
}
