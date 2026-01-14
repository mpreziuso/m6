//! Condition variable implementation
//!
//! Provides a condition variable for thread synchronisation. Threads can wait
//! on a condition variable until another thread signals them.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::{Mutex, MutexGuard};

/// A condition variable.
///
/// Condition variables allow threads to wait until a particular condition
/// becomes true. They are always used with a Mutex.
///
/// # Example
///
/// ```ignore
/// use m6_std::sync::{Condvar, Mutex};
///
/// let mutex = Mutex::new(false);
/// let condvar = Condvar::new();
///
/// // Thread 1: wait for condition
/// {
///     let mut guard = mutex.lock();
///     while !*guard {
///         guard = condvar.wait(guard);
///     }
///     // Condition is now true
/// }
///
/// // Thread 2: signal condition
/// {
///     let mut guard = mutex.lock();
///     *guard = true;
///     condvar.notify_one();
/// }
/// ```
pub struct Condvar {
    /// Generation counter. Incremented on each notify, used to detect spurious wakeups.
    generation: AtomicU64,
}

impl Condvar {
    /// Creates a new condition variable.
    #[inline]
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
        }
    }

    /// Blocks the current thread until this condition variable receives a notification.
    ///
    /// This function will atomically unlock the mutex and block the current thread.
    /// On return, the mutex will be re-locked.
    ///
    /// Note: Spurious wakeups are possible. Always check the condition in a loop.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let generation = self.generation.load(Ordering::Acquire);

        // Get a reference to the mutex before dropping the guard
        // SAFETY: MutexGuard contains a reference to the Mutex it was created from.
        // We need to get the mutex reference before dropping the guard.
        // We use a raw pointer to avoid lifetime issues.
        let mutex_ptr = guard.mutex() as *const Mutex<T>;

        // Release the mutex
        drop(guard);

        // Wait for generation to change (indicating a notify)
        while self.generation.load(Ordering::Acquire) == generation {
            core::hint::spin_loop();
        }

        // Re-acquire the mutex
        // SAFETY: We obtained this pointer from a valid MutexGuard, so the mutex is valid.
        unsafe { (*mutex_ptr).lock() }
    }

    /// Blocks until notified or timeout.
    ///
    /// Returns `true` if the condition was signalled, `false` on timeout.
    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout_ticks: u64,
    ) -> (MutexGuard<'a, T>, bool) {
        let generation = self.generation.load(Ordering::Acquire);
        let start = crate::time::Instant::now();

        // Get a reference to the mutex before dropping the guard
        let mutex_ptr = guard.mutex() as *const Mutex<T>;

        // Release the mutex
        drop(guard);

        // Wait for generation to change or timeout
        let signalled = loop {
            if self.generation.load(Ordering::Acquire) != generation {
                break true;
            }
            if crate::time::Instant::now().as_ticks() - start.as_ticks() >= timeout_ticks {
                break false;
            }
            core::hint::spin_loop();
        };

        // Re-acquire the mutex
        // SAFETY: We obtained this pointer from a valid MutexGuard.
        let guard = unsafe { (*mutex_ptr).lock() };

        (guard, signalled)
    }

    /// Wakes up one blocked thread on this condition variable.
    ///
    /// If no threads are waiting, this is a no-op.
    #[inline]
    pub fn notify_one(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Wakes up all blocked threads on this condition variable.
    ///
    /// If no threads are waiting, this is a no-op.
    #[inline]
    pub fn notify_all(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Condvar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Condvar").finish_non_exhaustive()
    }
}
