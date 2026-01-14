//! One-time initialisation primitives
//!
//! Provides types for ensuring code runs exactly once.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

/// State values for Once
const INCOMPLETE: u8 = 0;
const RUNNING: u8 = 1;
const COMPLETE: u8 = 2;

/// A synchronisation primitive for running one-time initialisation.
///
/// # Example
///
/// ```ignore
/// use m6_std::sync::Once;
///
/// static INIT: Once = Once::new();
///
/// INIT.call_once(|| {
///     // Initialisation code that runs exactly once
/// });
/// ```
pub struct Once {
    state: AtomicU8,
}

impl Once {
    /// Creates a new `Once` in the incomplete state.
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(INCOMPLETE),
        }
    }

    /// Calls the given closure if this is the first call to `call_once`.
    ///
    /// If another thread is currently running the initialisation, this method
    /// will block until it completes.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        // Fast path: already complete
        if self.state.load(Ordering::Acquire) == COMPLETE {
            return;
        }

        self.call_once_slow(f);
    }

    #[cold]
    fn call_once_slow<F: FnOnce()>(&self, f: F) {
        loop {
            match self.state.compare_exchange(
                INCOMPLETE,
                RUNNING,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We won the race, run the initialisation
                    f();
                    self.state.store(COMPLETE, Ordering::Release);
                    return;
                }
                Err(COMPLETE) => {
                    // Already complete
                    return;
                }
                Err(RUNNING) => {
                    // Another thread is running, wait
                    while self.state.load(Ordering::Acquire) == RUNNING {
                        core::hint::spin_loop();
                    }
                    // Now check if it completed
                    if self.state.load(Ordering::Acquire) == COMPLETE {
                        return;
                    }
                    // Otherwise loop and try again (in case of panic during init)
                }
                Err(_) => unreachable!(),
            }
        }
    }

    /// Returns `true` if the `Once` has completed initialisation.
    #[inline]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == COMPLETE
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Once {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Once")
            .field("is_completed", &self.is_completed())
            .finish()
    }
}

/// A cell that can be written to exactly once.
///
/// Similar to `std::sync::OnceLock`, this provides lazy initialisation
/// of a value that can be accessed by multiple threads.
///
/// # Example
///
/// ```ignore
/// use m6_std::sync::OnceLock;
///
/// static CONFIG: OnceLock<Config> = OnceLock::new();
///
/// fn get_config() -> &'static Config {
///     CONFIG.get_or_init(|| Config::load())
/// }
/// ```
pub struct OnceLock<T> {
    once: Once,
    value: UnsafeCell<Option<T>>,
}

// SAFETY: OnceLock synchronises access with the Once primitive
unsafe impl<T: Send + Sync> Send for OnceLock<T> {}
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}

impl<T> OnceLock<T> {
    /// Creates a new empty `OnceLock`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            once: Once::new(),
            value: UnsafeCell::new(None),
        }
    }

    /// Gets the reference to the underlying value.
    ///
    /// Returns `None` if the cell is not yet initialised.
    #[inline]
    pub fn get(&self) -> Option<&T> {
        if self.once.is_completed() {
            // SAFETY: The Once is complete, so the value is initialised
            unsafe { (*self.value.get()).as_ref() }
        } else {
            None
        }
    }

    /// Gets the mutable reference to the underlying value.
    ///
    /// Returns `None` if the cell is not yet initialised.
    /// This requires exclusive access, so no synchronisation is needed.
    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.value.get_mut().as_mut()
    }

    /// Gets the reference to the underlying value, initialising it if necessary.
    ///
    /// If another thread is currently running the initialisation, this method
    /// will block until it completes.
    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        self.once.call_once(|| {
            // SAFETY: We're inside call_once, so we have exclusive access
            unsafe {
                *self.value.get() = Some(f());
            }
        });

        // SAFETY: call_once ensures the value is initialised
        unsafe { (*self.value.get()).as_ref().unwrap() }
    }

    /// Sets the value, returning `Err(value)` if already initialised.
    pub fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);

        self.once.call_once(|| {
            // SAFETY: We're inside call_once, so we have exclusive access
            unsafe {
                *self.value.get() = value.take();
            }
        });

        match value {
            None => Ok(()),
            Some(v) => Err(v),
        }
    }

    /// Takes the value out of this `OnceLock`, moving it back to uninitialised.
    ///
    /// This requires exclusive access.
    pub fn take(&mut self) -> Option<T> {
        if self.once.is_completed() {
            // SAFETY: We have exclusive access via &mut self
            self.value.get_mut().take()
        } else {
            None
        }
    }

    /// Consumes the `OnceLock`, returning the contained value.
    ///
    /// Returns `None` if the cell was never initialised.
    pub fn into_inner(self) -> Option<T> {
        self.value.into_inner()
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.get() {
            Some(v) => f.debug_tuple("OnceLock").field(v).finish(),
            None => f.write_str("OnceLock(<uninitialised>)"),
        }
    }
}

impl<T: Clone> Clone for OnceLock<T> {
    fn clone(&self) -> Self {
        match self.get() {
            Some(v) => {
                let lock = OnceLock::new();
                let _ = lock.set(v.clone());
                lock
            }
            None => OnceLock::new(),
        }
    }
}

impl<T: PartialEq> PartialEq for OnceLock<T> {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<T: Eq> Eq for OnceLock<T> {}
