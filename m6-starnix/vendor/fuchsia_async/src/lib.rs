//! Minimal `no_std`, single-threaded `fuchsia_async` shim for the M6 Starnix fork.
//!
//! Upstream Starnix runs kernel work on a Fuchsia async executor with a Zircon
//! port reactor. M6's first-light bring-up is single-threaded and driven by the
//! restricted-mode syscall loop, so this provides a minimal executor:
//!
//! - [`block_on`] / [`LocalExecutor::run_singlethreaded`] poll a future to
//!   completion with a no-op waker. There is no reactor yet, so a future that
//!   parks on external I/O will busy-poll — fine for the synchronous first-light
//!   path; a real reactor is M3/M5 work.
//! - [`Task::local`] wraps a future and runs it inline when awaited.
//! - [`EHandle::spawn_detached`] currently drops the future (no background
//!   execution). Background kthread futures (delayed releaser, netlink — gated)
//!   are not exercised on the hello-world path; wiring real spawning is M3/M5.
//!
//! The API surface matches the subset the fork uses (`EHandle`, `Task`,
//! `LocalExecutor`); semantics are upgraded when M6 gains a reactor.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// -- no-op waker
fn noop_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

fn noop_waker() -> Waker {
    // SAFETY: the vtable functions are all valid no-ops with no state.
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

/// Drives `future` to completion on the current thread.
///
/// Bring-up semantics: busy-polls on `Pending` (no reactor). Suitable for the
/// synchronous first-light path.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

/// A single-threaded executor.
#[derive(Default)]
pub struct LocalExecutor {
    _private: (),
}

impl LocalExecutor {
    /// Creates a new executor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `future` to completion on the current thread.
    pub fn run_singlethreaded<F: Future>(&mut self, future: F) -> F::Output {
        block_on(future)
    }
}

/// A handle to the executor for the current thread.
#[derive(Clone)]
pub struct EHandle {
    _private: (),
}

impl EHandle {
    /// Returns a handle to the current thread's executor.
    pub fn local() -> Self {
        Self { _private: () }
    }

    /// Spawns a detached future on the executor.
    ///
    /// Bring-up: there is no background execution yet, so the future is dropped.
    /// Hot kthread futures are gated out of the minimal core; real spawning is
    /// M3/M5 work.
    pub fn spawn_detached<F>(&self, _future: F)
    where
        F: Future<Output = ()> + 'static,
    {
    }
}

/// A handle to a spawned task. Awaiting it runs the wrapped future inline.
pub struct Task<T> {
    future: Pin<Box<dyn Future<Output = T>>>,
}

impl<T: 'static> Task<T> {
    /// Wraps `future` as a local task. It runs when awaited.
    pub fn local<F>(future: F) -> Self
    where
        F: Future<Output = T> + 'static,
    {
        Self { future: Box::pin(future) }
    }

    /// Detaches the task. Bring-up: drops the wrapped future (no background run).
    pub fn detach(self) {}
}

impl<T> Future for Task<T> {
    type Output = T;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        self.future.as_mut().poll(cx)
    }
}
