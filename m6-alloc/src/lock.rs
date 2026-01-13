//! Lightweight locking primitives for the allocator

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// Lightweight spinlock for per-size-class protection
///
/// Uses test-and-set with exponential backoff for low contention scenarios.
/// This is simpler than a full mutex and appropriate for short critical sections.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: SpinLock provides synchronisation for T
unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new spinlock
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let mut backoff = 1u32;

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin with exponential backoff
            for _ in 0..backoff {
                spin_loop();
            }
            backoff = (backoff * 2).min(64);
        }

        SpinLockGuard { lock: self }
    }

    /// Try to acquire the lock without blocking
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

/// Guard for a held spinlock
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We hold the lock
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: We hold the lock
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// Simple raw spinlock without data (for protecting external state)
pub struct RawSpinLock {
    locked: AtomicBool,
}

impl RawSpinLock {
    /// Create a new raw spinlock
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    /// Acquire the lock
    pub fn lock(&self) -> RawSpinLockGuard<'_> {
        let mut backoff = 1u32;

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            for _ in 0..backoff {
                spin_loop();
            }
            backoff = (backoff * 2).min(64);
        }

        RawSpinLockGuard { lock: self }
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for RawSpinLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for a held raw spinlock
pub struct RawSpinLockGuard<'a> {
    lock: &'a RawSpinLock,
}

impl Drop for RawSpinLockGuard<'_> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}
