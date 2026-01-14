//! Threading support
//!
//! Provides thread spawning and management for M6 userspace programs.
//! Threads share the same VSpace (address space) but have independent
//! execution contexts.
//!
//! # Example
//!
//! ```ignore
//! use m6_std::thread;
//!
//! let handle = thread::spawn(|| {
//!     println!("Hello from spawned thread!");
//!     42
//! });
//!
//! let result = handle.join().unwrap();
//! assert_eq!(result, 42);
//! ```

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use m6_cap::ObjectType;
use m6_syscall::error::SyscallError;
use m6_syscall::invoke::{
    map_frame, retype, signal, tcb_configure, tcb_resume, tcb_write_registers, wait,
};

use crate::sync::Mutex;

/// A wrapper to make raw pointers Send.
///
/// SAFETY: This is only safe when the pointer is exclusively owned by one thread
/// at a time, which is guaranteed by our thread spawning protocol.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct SendPtr<T>(core::ptr::NonNull<T>);

impl<T> SendPtr<T> {
    fn new(ptr: *mut T) -> Option<Self> {
        core::ptr::NonNull::new(ptr).map(SendPtr)
    }

    fn ptr(self) -> *mut T {
        self.0.as_ptr()
    }
}

// SAFETY: We guarantee exclusive ownership during thread handoff
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

// -- Thread configuration

/// Default stack size for spawned threads (64 KiB).
pub const DEFAULT_STACK_SIZE: usize = 64 * 1024;

/// Stack alignment (16 bytes for AArch64).
const STACK_ALIGN: usize = 16;

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

// -- Capability slot management
//
// These constants define well-known slot positions in the thread's CSpace.
// The thread module allocates capabilities starting from a high slot number
// to avoid conflicts with statically allocated slots.

/// First slot for thread-allocated resources.
/// Threads allocate TCB, Notification, and stack frames starting here.
const THREAD_SLOT_BASE: u64 = 256;

/// Global counter for allocating thread resource slots.
static NEXT_THREAD_SLOT: AtomicU64 = AtomicU64::new(THREAD_SLOT_BASE);

/// CNode radix (matches the root CNode setup).
const CNODE_RADIX: u8 = 10;

/// Root CNode CPtr (self-reference at slot 0).
const ROOT_CNODE_CPTR: u64 = 0;

/// Root VSpace CPtr (slot 2).
const ROOT_VSPACE_CPTR: u64 = 2 << 54;

/// First untyped capability slot.
const UNTYPED_SLOT: u64 = 9;

/// Untyped capability CPtr.
const UNTYPED_CPTR: u64 = UNTYPED_SLOT << 54;

// -- Thread spawning

/// Error type for thread operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadError {
    /// Failed to allocate resources.
    AllocationFailed,
    /// Failed to configure thread.
    ConfigurationFailed,
    /// Failed to start thread.
    StartFailed,
    /// Thread panicked.
    Panicked,
    /// Syscall error.
    Syscall(SyscallError),
}

impl From<SyscallError> for ThreadError {
    fn from(e: SyscallError) -> Self {
        ThreadError::Syscall(e)
    }
}

/// A handle to a spawned thread.
///
/// When dropped without calling `join()`, the thread is detached and will
/// continue running in the background.
pub struct JoinHandle<T> {
    /// Notification capability for join synchronisation.
    notification_cptr: u64,
    /// Shared result location.
    result: *mut Option<T>,
}

// SAFETY: JoinHandle is Send if T is Send (we only move the result once)
unsafe impl<T: Send> Send for JoinHandle<T> {}
// SAFETY: JoinHandle is not inherently Sync, but the result is protected by IPC
unsafe impl<T: Send> Sync for JoinHandle<T> {}

impl<T> JoinHandle<T> {
    /// Wait for the thread to finish and get its result.
    ///
    /// Returns `Ok(value)` if the thread completed successfully,
    /// or `Err(ThreadError)` if it panicked or failed.
    pub fn join(self) -> Result<T, ThreadError> {
        // Wait for the thread to signal completion
        wait(self.notification_cptr).map_err(|_| ThreadError::Panicked)?;

        // Take the result from the shared location
        // SAFETY: The thread has signalled completion, so the result is ready.
        // We have exclusive ownership of the JoinHandle so no race is possible.
        let result = unsafe { (*self.result).take() };

        // Free the result box
        // SAFETY: We allocated this box in spawn() and now have exclusive access
        let _ = unsafe { Box::from_raw(self.result) };

        result.ok_or(ThreadError::Panicked)
    }

    /// Check if the thread has finished without blocking.
    pub fn is_finished(&self) -> bool {
        // Try to poll the notification
        m6_syscall::invoke::poll(self.notification_cptr).is_ok()
    }
}

/// Thread builder for configuring thread parameters before spawning.
pub struct Builder {
    /// Stack size in bytes.
    stack_size: usize,
    /// Thread name (unused for now).
    #[allow(dead_code)]
    name: Option<&'static str>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Create a new thread builder with default settings.
    pub fn new() -> Self {
        Self {
            stack_size: DEFAULT_STACK_SIZE,
            name: None,
        }
    }

    /// Set the stack size for the thread.
    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }

    /// Set the thread name.
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// Spawn a new thread with the configured parameters.
    pub fn spawn<F, T>(self, f: F) -> Result<JoinHandle<T>, ThreadError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        spawn_inner(f, self.stack_size)
    }
}

/// Spawn a new thread with default settings.
///
/// # Example
///
/// ```ignore
/// let handle = thread::spawn(|| {
///     42
/// });
/// assert_eq!(handle.join().unwrap(), 42);
/// ```
pub fn spawn<F, T>(f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_inner(f, DEFAULT_STACK_SIZE).expect("thread spawn failed")
}

/// Internal spawn implementation.
fn spawn_inner<F, T>(f: F, stack_size: usize) -> Result<JoinHandle<T>, ThreadError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // Allocate capability slots for thread resources:
    // - 1 slot for TCB
    // - 1 slot for Notification (join synchronisation)
    // - N slots for stack frames
    let stack_pages = stack_size.div_ceil(PAGE_SIZE);
    let slots_needed = 2 + stack_pages;

    let base_slot = NEXT_THREAD_SLOT.fetch_add(slots_needed as u64, Ordering::Relaxed);

    let tcb_slot = base_slot;
    let notification_slot = base_slot + 1;
    let stack_slot_base = base_slot + 2;

    // Convert slots to CPtrs
    let tcb_cptr = tcb_slot << (64 - CNODE_RADIX as u64);
    let notification_cptr = notification_slot << (64 - CNODE_RADIX as u64);

    // Allocate TCB from untyped
    retype(
        UNTYPED_CPTR,
        ObjectType::TCB as u64,
        0, // TCB size is fixed
        ROOT_CNODE_CPTR,
        tcb_slot,
        1,
    )
    .map_err(|_| ThreadError::AllocationFailed)?;

    // Allocate Notification from untyped
    retype(
        UNTYPED_CPTR,
        ObjectType::Notification as u64,
        0, // Notification size is fixed
        ROOT_CNODE_CPTR,
        notification_slot,
        1,
    )
    .map_err(|_| ThreadError::AllocationFailed)?;

    // Allocate stack frames from untyped
    retype(
        UNTYPED_CPTR,
        ObjectType::Frame as u64,
        12, // 4KB pages
        ROOT_CNODE_CPTR,
        stack_slot_base,
        stack_pages as u64,
    )
    .map_err(|_| ThreadError::AllocationFailed)?;

    // Allocate virtual address for stack
    // We use a simple bump allocator starting from a high address
    static NEXT_STACK_ADDR: AtomicU64 = AtomicU64::new(0x0000_1000_0000_0000);
    let stack_base = NEXT_STACK_ADDR.fetch_add((stack_pages * PAGE_SIZE) as u64, Ordering::Relaxed);

    // Map stack frames into VSpace
    for i in 0..stack_pages {
        let frame_slot = stack_slot_base + i as u64;
        let frame_cptr = frame_slot << (64 - CNODE_RADIX as u64);
        let vaddr = stack_base + (i * PAGE_SIZE) as u64;

        // Rights: R=1, W=2 (stack needs read+write, no execute)
        map_frame(ROOT_VSPACE_CPTR, frame_cptr, vaddr, 3, 0)
            .map_err(|_| ThreadError::ConfigurationFailed)?;
    }

    // Calculate stack top (stacks grow down on ARM64)
    let stack_top = (stack_base as usize + stack_pages * PAGE_SIZE) & !(STACK_ALIGN - 1);

    // Create the result storage box
    let result_box: Box<Option<T>> = Box::new(None);
    let result_ptr = Box::into_raw(result_box);

    // Wrap the result pointer in a Send-safe wrapper
    let send_result_ptr = SendPtr::new(result_ptr).expect("result ptr is non-null");

    // Create the closure wrapper
    // This wrapper calls the closure, stores the result, and signals completion
    let wrapper: Box<dyn FnOnce() + Send> = Box::new(move || {
        let value = f();
        // Store result
        // SAFETY: We have exclusive access during thread execution
        unsafe {
            *send_result_ptr.ptr() = Some(value);
        }
        // Signal completion
        let _ = signal(notification_cptr);
        // Exit thread
        m6_syscall::invoke::tcb_exit(0);
    });

    // Double-box to get a thin pointer (Box<Box<_>> has a known size)
    let wrapper_box: Box<Box<dyn FnOnce() + Send>> = Box::new(wrapper);
    let wrapper_ptr = Box::into_raw(wrapper_box) as *mut u8 as u64;

    // Configure TCB:
    // - fault_ep = 0 (no fault endpoint for now)
    // - cspace = ROOT_CNODE_CPTR (share parent's CSpace)
    // - vspace = ROOT_VSPACE_CPTR (share parent's VSpace)
    // - ipc_buf_addr = 0 (no IPC buffer for now)
    // - ipc_buf_frame = 0
    tcb_configure(tcb_cptr, 0, ROOT_CNODE_CPTR, ROOT_VSPACE_CPTR, 0, 0)
        .map_err(|_| ThreadError::ConfigurationFailed)?;

    // Write registers:
    // - PC = thread_entry trampoline
    // - SP = stack_top
    // - x0 = wrapper_ptr (closure pointer)
    tcb_write_registers(tcb_cptr, thread_entry as *const () as u64, stack_top as u64, wrapper_ptr)
        .map_err(|_| ThreadError::ConfigurationFailed)?;

    // Resume the thread
    tcb_resume(tcb_cptr).map_err(|_| ThreadError::StartFailed)?;

    Ok(JoinHandle {
        notification_cptr,
        result: result_ptr,
    })
}

/// Thread entry point.
///
/// This function is called in the new thread context with the closure pointer in x0.
/// The pointer is a thin pointer to a `Box<Box<dyn FnOnce() + Send>>`.
/// It calls the closure and never returns.
#[unsafe(no_mangle)]
extern "C" fn thread_entry(closure_ptr: u64) -> ! {
    // SAFETY: The closure pointer was created by Box::into_raw in spawn_inner.
    // We have exclusive ownership because this is a new thread.
    // It's a Box<Box<dyn FnOnce() + Send>> pointer.
    let outer_box: Box<Box<dyn FnOnce() + Send>> =
        unsafe { Box::from_raw(closure_ptr as *mut Box<dyn FnOnce() + Send>) };
    let closure = *outer_box;
    closure();

    // The closure should have called tcb_exit(), but just in case:
    m6_syscall::invoke::tcb_exit(0);
}

// -- Utility functions

/// Yield the current thread's time slice.
///
/// This allows other threads to run. The calling thread remains runnable
/// and will be scheduled again.
#[inline]
pub fn yield_now() {
    m6_syscall::invoke::sched_yield();
}

/// Get a unique identifier for the current thread.
///
/// Note: This is a placeholder. In a full implementation, this would
/// return a proper thread ID from the kernel.
pub fn current_id() -> u64 {
    // For now, return a placeholder
    // A full implementation would query the kernel for the current TCB ID
    0
}

/// Sleep for a short period using busy-wait.
///
/// This is a simple busy-wait loop for short delays. For longer delays,
/// use the timer system.
pub fn sleep_ticks(ticks: u64) {
    let start = crate::time::Instant::now();
    let target = start.as_ticks() + ticks;
    while crate::time::Instant::now().as_ticks() < target {
        core::hint::spin_loop();
    }
}

/// Global lock for thread-related operations.
///
/// This is used to serialise resource allocation to avoid races.
#[allow(dead_code)]
pub(crate) static THREAD_LOCK: Mutex<()> = Mutex::new(());
