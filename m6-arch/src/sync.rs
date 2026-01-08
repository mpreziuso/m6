//! Interrupt-safe synchronization primitives
//!
//! Provides [`IrqSpinMutex`] which disables interrupts while held to prevent
//! deadlock when interrupt handlers need to acquire the same lock.
//!
//! # Example
//!
//! ```ignore
//! use m6_arch::sync::IrqSpinMutex;
//!
//! static COUNTER: IrqSpinMutex<u64> = IrqSpinMutex::new(0);
//!
//! fn increment() {
//!     let mut guard = COUNTER.lock();
//!     *guard += 1;
//! }   // Interrupts restored here
//! ```

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::cpu::{disable_interrupts, restore_interrupts};

/// A spinlock that disables interrupts while held.
///
/// This prevents deadlock when:
/// 1. Thread A acquires lock
/// 2. Interrupt fires on same CPU
/// 3. Interrupt handler tries to acquire same lock
/// 4. Deadlock! (with regular spinlock)
///
/// By disabling interrupts before acquiring the lock, we ensure that
/// no interrupt can preempt a lock holder on the same CPU.
///
/// # Safety Invariants
///
/// - The lock must be released (and interrupts restored) before:
///   - Sleeping or blocking
///   - Calling functions that may sleep
/// - Critical sections should be kept short
/// - Nested locking of different `IrqSpinMutex`es is supported but discouraged
pub struct IrqSpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: IrqSpinMutex provides synchronization for its data.
// The data is only accessible through the guard which requires holding the lock.
unsafe impl<T: Send> Sync for IrqSpinMutex<T> {}
unsafe impl<T: Send> Send for IrqSpinMutex<T> {}

impl<T> IrqSpinMutex<T> {
    /// Create a new mutex with the given value.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, disabling interrupts.
    ///
    /// Returns a guard that restores interrupts when dropped.
    /// Spins until the lock is acquired.
    #[must_use]
    pub fn lock(&self) -> IrqSpinMutexGuard<'_, T> {
        // Save and disable interrupts BEFORE attempting to acquire lock.
        // This prevents the deadlock scenario where an interrupt fires
        // while we're spinning and the ISR tries to acquire this lock.
        let daif = disable_interrupts();

        // Spin until we acquire the lock
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Hint to the CPU that we're spinning
            core::hint::spin_loop();
        }

        IrqSpinMutexGuard {
            mutex: self,
            daif,
            _not_send: core::marker::PhantomData,
        }
    }

    /// Try to acquire the lock without blocking.
    ///
    /// Returns `None` if the lock is already held.
    /// Interrupts are only disabled if the lock is successfully acquired.
    #[must_use]
    pub fn try_lock(&self) -> Option<IrqSpinMutexGuard<'_, T>> {
        let daif = disable_interrupts();

        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(IrqSpinMutexGuard {
                mutex: self,
                daif,
                _not_send: core::marker::PhantomData,
            })
        } else {
            // Failed to acquire - restore interrupts
            restore_interrupts(daif);
            None
        }
    }

    /// Check if the lock is currently held.
    ///
    /// This is a racy check and should only be used for debugging.
    /// Do not use for synchronization decisions.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Get a mutable reference to the underlying data.
    ///
    /// This is safe because `&mut self` guarantees exclusive access.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Consume the mutex and return the inner value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: Default> Default for IrqSpinMutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for IrqSpinMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("IrqSpinMutex").field("data", &*guard).finish(),
            None => f.debug_struct("IrqSpinMutex").field("data", &"<locked>").finish(),
        }
    }
}

/// Guard that provides access to the locked data.
///
/// Interrupts are disabled while this guard exists.
/// When the guard is dropped:
/// 1. The lock is released
/// 2. Interrupts are restored to their previous state
///
/// This guard is `!Send` because sending it to another thread would
/// restore interrupts on the wrong CPU.
pub struct IrqSpinMutexGuard<'a, T> {
    mutex: &'a IrqSpinMutex<T>,
    daif: u64,
    // Marker to make guard !Send (raw pointers are !Send)
    _not_send: core::marker::PhantomData<*const ()>,
}

impl<'a, T> Deref for IrqSpinMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so we have exclusive access
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T> DerefMut for IrqSpinMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so we have exclusive access
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T> Drop for IrqSpinMutexGuard<'a, T> {
    fn drop(&mut self) {
        // Release lock BEFORE restoring interrupts.
        // This ensures all writes are visible before any interrupt can fire.
        self.mutex.locked.store(false, Ordering::Release);

        // Memory barrier to ensure the lock release is visible
        // before interrupts can fire and potentially see stale data.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Restore previous interrupt state
        restore_interrupts(self.daif);
    }
}

// Note: IrqSpinMutexGuard is !Send due to PhantomData<*const ()>
// This prevents sending the guard to another thread, which would
// restore interrupts on the wrong CPU.

// Guard can be Sync if T is Sync (multiple refs to same data is fine)
unsafe impl<T: Sync> Sync for IrqSpinMutexGuard<'_, T> {}
