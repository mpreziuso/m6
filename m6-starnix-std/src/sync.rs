//! Synchronisation primitives
//!
//! Provides the subset of `std::sync` that Starnix uses, backed by
//! `alloc::sync` and `spin` for mutex/rwlock.

pub use alloc::sync::{Arc, Weak};
pub use core::sync::atomic;
pub use core::sync::atomic::*;

// Mutex and RwLock from spin (no_std)
pub use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

// -- OnceLock

/// A synchronisation primitive that can be written to only once.
///
/// Equivalent to `std::sync::OnceLock`.
pub struct OnceLock<T> {
    inner: spin::Once<T>,
}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            inner: spin::Once::new(),
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }

    pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        self.inner.call_once(f)
    }

    pub fn get_or_try_init<E>(&self, f: impl FnOnce() -> Result<T, E>) -> Result<&T, E> {
        self.inner.try_call_once(f)
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        if self.inner.get().is_some() {
            return Err(value);
        }
        // There's a race here, but OnceLock::set has inherent TOCTOU.
        // call_once guarantees only one initialiser runs.
        let mut slot = Some(value);
        self.inner.call_once(|| slot.take().unwrap());
        match slot {
            None => Ok(()),
            Some(v) => Err(v),
        }
    }

    /// Takes the value out of this `OnceLock`, moving it back to an uninitialised state.
    ///
    /// Mirrors `std::sync::OnceLock::take`. Requires `&mut self`, so no other access is
    /// possible and the operation is race-free.
    pub fn take(&mut self) -> Option<T> {
        core::mem::replace(&mut self.inner, spin::Once::new()).try_into_inner()
    }

    /// Returns an iterator yielding the stored value if initialised, otherwise empty.
    ///
    /// Mirrors the `&OnceCell`-style `iter` used by upstream Fuchsia to treat an
    /// optionally-initialised cell as a 0-or-1 element collection.
    pub fn iter(&self) -> core::option::IntoIter<&T> {
        self.get().into_iter()
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: OnceLock<T> is safe to share across threads if T is Send + Sync.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
unsafe impl<T: Send> Send for OnceLock<T> {}

// -- OnceBool

/// A boolean that is initialised at most once.
///
/// Mirrors `once_cell::race::OnceBool`: `get_or_init` returns the stored value
/// by copy (not by reference).
#[derive(Default)]
pub struct OnceBool {
    inner: OnceLock<bool>,
}

impl OnceBool {
    pub const fn new() -> Self {
        Self { inner: OnceLock::new() }
    }

    pub fn get(&self) -> Option<bool> {
        self.inner.get().copied()
    }

    pub fn get_or_init(&self, f: impl FnOnce() -> bool) -> bool {
        *self.inner.get_or_init(f)
    }

    pub fn set(&self, value: bool) -> Result<(), bool> {
        self.inner.set(value)
    }
}

// -- LazyLock

/// A value which is initialised on the first access.
///
/// Equivalent to `std::sync::LazyLock`.
pub struct LazyLock<T, F = fn() -> T> {
    once: spin::Once<T>,
    init: spin::Mutex<Option<F>>,
}

impl<T, F: FnOnce() -> T> LazyLock<T, F> {
    pub const fn new(f: F) -> Self {
        Self {
            once: spin::Once::new(),
            init: spin::Mutex::new(Some(f)),
        }
    }

    /// Forces the evaluation of this lazy value and returns a reference to the result.
    ///
    /// Mirrors `std::sync::LazyLock::force`. Takes `&LazyLock` (an associated function,
    /// not a method) to avoid conflicting with a possible `Deref` target method.
    pub fn force(this: &LazyLock<T, F>) -> &T {
        this
    }
}

impl<T, F: FnOnce() -> T> core::ops::Deref for LazyLock<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        self.once.call_once(|| {
            let f = self
                .init
                .lock()
                .take()
                .expect("LazyLock initialiser called twice");
            f()
        })
    }
}

// SAFETY: LazyLock<T, F> is safe to share across threads if T is Send + Sync.
unsafe impl<T: Send + Sync, F: Send> Sync for LazyLock<T, F> {}
unsafe impl<T: Send, F: Send> Send for LazyLock<T, F> {}

pub mod mpsc {
    //! Multi-producer, single-consumer channel.
    //!
    //! Minimal implementation using a spin-locked VecDeque.

    extern crate alloc;
    use alloc::collections::VecDeque;
    use spin::Mutex;

    pub struct Sender<T> {
        inner: alloc::sync::Arc<Mutex<ChannelInner<T>>>,
    }

    pub struct Receiver<T> {
        inner: alloc::sync::Arc<Mutex<ChannelInner<T>>>,
    }

    struct ChannelInner<T> {
        queue: VecDeque<T>,
        closed: bool,
    }

    pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let inner = alloc::sync::Arc::new(Mutex::new(ChannelInner {
            queue: VecDeque::new(),
            closed: false,
        }));
        (
            Sender {
                inner: inner.clone(),
            },
            Receiver { inner },
        )
    }

    impl<T> Sender<T> {
        pub fn send(&self, value: T) -> Result<(), T> {
            let mut inner = self.inner.lock();
            if inner.closed {
                return Err(value);
            }
            inner.queue.push_back(value);
            Ok(())
        }
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T> Drop for Sender<T> {
        fn drop(&mut self) {
            // If this is the last sender, mark channel as closed
            if alloc::sync::Arc::strong_count(&self.inner) <= 2 {
                self.inner.lock().closed = true;
            }
        }
    }

    impl<T> Receiver<T> {
        pub fn try_recv(&self) -> Result<T, TryRecvError> {
            let mut inner = self.inner.lock();
            match inner.queue.pop_front() {
                Some(v) => Ok(v),
                None if inner.closed => Err(TryRecvError::Disconnected),
                None => Err(TryRecvError::Empty),
            }
        }

        /// Receives a value. Upstream `std::sync::mpsc::Receiver::recv` blocks
        /// until a value or disconnect; M6's bring-up channel is single-threaded
        /// with no reactor, so an empty queue is reported as `RecvError` rather
        /// than blocking. A real blocking variant returns with the executor.
        pub fn recv(&self) -> Result<T, RecvError> {
            self.try_recv().map_err(|_| RecvError)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum TryRecvError {
        Empty,
        Disconnected,
    }

    /// The error returned by [`Receiver::recv`] when the channel is empty and
    /// all senders have been dropped.
    #[derive(Debug, PartialEq, Eq)]
    pub struct RecvError;

    /// The error returned by [`Sender::send`] / [`SyncSender::send`] when the
    /// receiver has been dropped. Carries the unsent value.
    #[derive(PartialEq, Eq)]
    pub struct SendError<T>(pub T);

    // Hand-written `Debug` so it does not require `T: Debug`, matching std's
    // behaviour. The fork sends boxed non-`Debug` closures through the channel
    // and calls `.unwrap()`/`.expect()` on the result.
    impl<T> core::fmt::Debug for SendError<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SendError").finish_non_exhaustive()
        }
    }

    /// The error returned by [`SyncSender::try_send`].
    #[derive(PartialEq, Eq)]
    pub enum TrySendError<T> {
        /// The bounded channel is full.
        Full(T),
        /// The receiver has been dropped.
        Disconnected(T),
    }

    // Hand-written `Debug` so it does not require `T: Debug`, matching std.
    impl<T> core::fmt::Debug for TrySendError<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                TrySendError::Full(..) => f.debug_tuple("Full").finish(),
                TrySendError::Disconnected(..) => f.debug_tuple("Disconnected").finish(),
            }
        }
    }

    /// A bounded multi-producer, single-consumer sender.
    ///
    /// This shim ignores the bound (it never blocks); it is a thin wrapper over
    /// [`Sender`] so forked code that expects `std::sync::mpsc::SyncSender`
    /// compiles. M6 does not yet need true back-pressure here.
    pub struct SyncSender<T> {
        inner: Sender<T>,
    }

    impl<T> SyncSender<T> {
        pub fn send(&self, value: T) -> Result<(), SendError<T>> {
            self.inner.send(value).map_err(SendError)
        }

        pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>> {
            self.inner.send(value).map_err(TrySendError::Disconnected)
        }
    }

    impl<T> Clone for SyncSender<T> {
        fn clone(&self) -> Self {
            Self { inner: self.inner.clone() }
        }
    }

    impl<T> core::fmt::Debug for SyncSender<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("SyncSender { .. }")
        }
    }

    /// Creates a bounded channel. The `bound` is accepted for API compatibility
    /// but not currently enforced (sends never block).
    pub fn sync_channel<T>(_bound: usize) -> (SyncSender<T>, Receiver<T>) {
        let (tx, rx) = channel();
        (SyncSender { inner: tx }, rx)
    }
}
