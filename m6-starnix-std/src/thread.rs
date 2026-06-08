//! Minimal `std::thread` shim.
//!
//! M6 has no host-thread API at this layer yet. These types mirror the small
//! subset of `std::thread` that forked Starnix code references so it compiles.
//! `spawn`/`Builder::spawn` currently return an error rather than launching a
//! real thread — this is a documented placeholder until M6 thread spawning is
//! wired through `m6-std`.

extern crate alloc;

use crate::time::Duration;
use alloc::string::String;
use core::marker::PhantomData;

/// A handle to a (would-be) spawned thread.
///
/// Joining a stub handle yields the value the closure produced when run inline
/// is not available; callers that depend on real concurrency must wait for the
/// native implementation.
pub struct JoinHandle<T> {
    _marker: PhantomData<T>,
}

impl<T> JoinHandle<T> {
    /// Waits for the associated thread to finish.
    ///
    /// Placeholder: always reports the thread as panicked/absent.
    pub fn join(self) -> Result<T, JoinError> {
        Err(JoinError)
    }

    /// Returns whether the associated thread has finished. Stub: always true.
    pub fn is_finished(&self) -> bool {
        true
    }
}

impl<T> core::fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinHandle { .. }")
    }
}

/// Opaque payload type returned by a failed [`JoinHandle::join`].
#[derive(Debug)]
pub struct JoinError;

/// A builder for configuring thread attributes before spawning.
#[derive(Default)]
pub struct Builder {
    _name: Option<String>,
    _stack_size: Option<usize>,
}

impl Builder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the name of the thread-to-be.
    pub fn name(mut self, name: String) -> Self {
        self._name = Some(name);
        self
    }

    /// Sets the stack size of the thread-to-be.
    pub fn stack_size(mut self, size: usize) -> Self {
        self._stack_size = Some(size);
        self
    }

    /// Spawns a new thread.
    ///
    /// Placeholder: M6 thread spawning is not yet wired here, so this returns an
    /// error without running `f`.
    pub fn spawn<F, T>(self, _f: F) -> crate::io::Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        Err(crate::io::Error::new(
            crate::io::ErrorKind::Unsupported,
            "thread spawning is not implemented on M6",
        ))
    }
}

/// Spawns a new thread.
///
/// Placeholder: returns a stub [`JoinHandle`] without running `f`.
pub fn spawn<F, T>(_f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    JoinHandle { _marker: PhantomData }
}

/// Puts the current thread to sleep for at least the given duration.
///
/// Placeholder: no-op (there is no thread to block here yet).
pub fn sleep(_dur: Duration) {}

/// Yields the current thread's time slice. Placeholder: no-op.
pub fn yield_now() {}

// -- Thread-local storage (single-threaded bring-up variant)
//
// M6's Starnix service runs the guest single-threaded during bring-up, so a
// process-global cell is observationally equivalent to true TLS here. This
// `LocalKey` lazily initialises its slot on first `with()` and presents the
// std `thread_local!` API so forked code compiles and runs unchanged. When M6
// gains real per-thread storage, replace the body of `with`/`LocalKey` with a
// TLS-backed implementation; the public API stays identical.
use core::cell::UnsafeCell;

/// A thread-local storage key, mirroring `std::thread::LocalKey`.
pub struct LocalKey<T: 'static> {
    init: fn() -> T,
    slot: UnsafeCell<Option<T>>,
}

// SAFETY: bring-up is single-threaded; only one thread ever touches `slot`.
// This is the documented single-thread approximation of TLS (see module note).
unsafe impl<T: 'static> Sync for LocalKey<T> {}

impl<T: 'static> LocalKey<T> {
    /// Creates a new key with the given lazy initialiser. Intended for use by
    /// the [`crate::thread_local!`] macro, not directly.
    pub const fn new(init: fn() -> T) -> Self {
        Self { init, slot: UnsafeCell::new(None) }
    }

    /// Acquires a reference to the value in this TLS key, initialising it on
    /// first access.
    pub fn with<F, R>(&'static self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        // SAFETY: single-threaded bring-up — no concurrent access to `slot`.
        let opt = unsafe { &mut *self.slot.get() };
        if opt.is_none() {
            *opt = Some((self.init)());
        }
        f(opt.as_ref().unwrap())
    }
}

/// `std::thread_local!` shim: declares one or more [`LocalKey`] statics.
#[macro_export]
macro_rules! thread_local {
    () => {};
    ($(#[$attr:meta])* $vis:vis static $name:ident : $t:ty = $init:expr; $($rest:tt)*) => {
        $(#[$attr])* $vis static $name: $crate::thread::LocalKey<$t> =
            $crate::thread::LocalKey::new(|| $init);
        $crate::thread_local!($($rest)*);
    };
}
