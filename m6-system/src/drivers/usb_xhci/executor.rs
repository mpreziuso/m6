//! Minimal polling executor for async futures
//!
//! Since m6 userspace doesn't have a full async runtime, we provide a
//! simple polling executor that blocks until futures complete.
//!
//! For USB drivers using crab-usb, the event ring must be polled to
//! process hardware events and complete async operations.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crab_usb::EventHandler;

/// Event handler storage for processing xHCI events during async execution.
///
/// When set, the executor will poll this handler on each iteration to process
/// hardware events that complete async operations.
///
/// SAFETY: This is only accessed from the single-threaded executor loop.
static mut EVENT_HANDLER: Option<EventHandler> = None;

/// Whether event polling is enabled.
///
/// Event polling must be disabled during xHCI init() because the event ring
/// hasn't been set up yet. Enable it after init() completes.
static mut POLLING_ENABLED: bool = false;

/// Set the event handler to be polled during async execution.
///
/// This transfers ownership of the event handler to the executor. The handler
/// will be polled on each iteration of `block_on` to process xHCI completion
/// events.
///
/// Note: Event polling is initially disabled. Call `enable_event_polling()`
/// after xHCI init completes.
///
/// # Safety
///
/// Must be called before any async operations. Only call once per driver
/// initialisation. The driver must be single-threaded.
pub unsafe fn set_event_handler(handler: EventHandler) {
    // SAFETY: Single-threaded access during driver initialisation
    unsafe {
        EVENT_HANDLER = Some(handler);
    }
}

/// Enable event polling in the executor.
///
/// Call this after xHCI init() completes and the event ring is set up.
///
/// # Safety
///
/// Must only be called after xHCI initialisation is complete.
pub unsafe fn enable_event_polling() {
    // SAFETY: Single-threaded access
    unsafe {
        POLLING_ENABLED = true;
    }
}

/// Poll events from the xHCI event ring.
fn poll_events() {
    // SAFETY: Single-threaded access from block_on loop only
    unsafe {
        if POLLING_ENABLED {
            if let Some(ref mut handler) = EVENT_HANDLER {
                handler.handle_event();
            }
        }
    }
}

/// Poll a future to completion using a blocking spin loop.
///
/// This is a simple executor suitable for single-threaded drivers that
/// need to use async libraries like crab-usb without a full runtime.
///
/// The executor polls the xHCI event ring on each iteration to process
/// hardware events that complete async operations.
pub fn block_on<F: Future>(mut future: F) -> F::Output {
    // Pin the future on the stack
    // SAFETY: The future is not moved after pinning
    let mut future = unsafe { Pin::new_unchecked(&mut future) };

    // Create a no-op waker
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    loop {
        // Poll the xHCI event ring to process completions
        poll_events();

        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                // Yield to scheduler to avoid busy-looping
                core::hint::spin_loop();
            }
        }
    }
}

/// Poll a future once, returning Ready or Pending.
pub fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    future.poll(&mut cx)
}

// -- No-op waker implementation

fn noop_waker() -> Waker {
    // SAFETY: The waker vtable operations are all no-ops
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

fn noop_raw_waker() -> RawWaker {
    RawWaker::new(core::ptr::null(), &NOOP_WAKER_VTABLE)
}

const NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    // clone
    |_| noop_raw_waker(),
    // wake
    |_| {},
    // wake_by_ref
    |_| {},
    // drop
    |_| {},
);
