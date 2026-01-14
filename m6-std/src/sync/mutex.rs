//! Mutex implementation
//!
//! Provides a mutual exclusion primitive using spinlock-based synchronisation.
//! In the future, this could be upgraded to use notification-based blocking.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A mutual exclusion primitive useful for protecting shared data.
///
/// This mutex uses a spinlock for simplicity. For production use with
/// multiple threads, consider using notification-based blocking to avoid
/// busy-waiting.
pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: Mutex provides interior mutability with synchronisation
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state.
    #[inline]
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Consumes this mutex, returning the underlying data.
    #[inline]
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires the mutex, blocking the current thread until it is able to do so.
    ///
    /// Returns a guard that releases the lock when dropped.
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        // Simple spinlock implementation
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin with a hint to the processor
            core::hint::spin_loop();
        }

        MutexGuard { mutex: self }
    }

    /// Attempts to acquire the mutex without blocking.
    ///
    /// If the lock could not be acquired, returns `None`.
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
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

    /// Checks whether the mutex is currently locked.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("Mutex").field("data", &&*guard).finish(),
            None => {
                struct LockedPlaceholder;
                impl core::fmt::Debug for LockedPlaceholder {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        f.write_str("<locked>")
                    }
                }
                f.debug_struct("Mutex")
                    .field("data", &LockedPlaceholder)
                    .finish()
            }
        }
    }
}

/// An RAII implementation of a "scoped lock" for a mutex.
///
/// When this guard is dropped, the lock will be released.
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> MutexGuard<'_, T> {
    /// Returns a reference to the underlying mutex.
    ///
    /// This is used by Condvar to re-acquire the lock after waiting.
    #[inline]
    pub fn mutex(&self) -> &Mutex<T> {
        self.mutex
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so we have exclusive access
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so we have exclusive access
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}

impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + core::fmt::Display> core::fmt::Display for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&**self, f)
    }
}
