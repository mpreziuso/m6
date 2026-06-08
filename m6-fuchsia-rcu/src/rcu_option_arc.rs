// An RCU version of `Option<Arc<...>>`.

use crate::rcu_ptr::{RcuPtr, RcuReadGuard};
use crate::rcu_read_scope::RcuReadScope;
use crate::state_machine::rcu_drop;
use alloc::sync::Arc;

/// An RCU (Read-Copy-Update) version of `Option<Arc<...>>`.
///
/// This Arc can be read from multiple threads concurrently without blocking.
/// When the Arc is written, reads may continue to see the old value for some
/// period of time.
#[derive(Debug)]
pub struct RcuOptionArc<T: Send + Sync + 'static> {
    ptr: RcuPtr<T>,
}

impl<T: Send + Sync + 'static> RcuOptionArc<T> {
    /// Create a new `RcuOptionArc` from an `Option<Arc<T>>`.
    pub fn new(data: Option<Arc<T>>) -> Self {
        Self {
            ptr: RcuPtr::new(Self::into_ptr(data)),
        }
    }

    /// Read the value of the `RcuOptionArc`.
    pub fn read(&self) -> Option<RcuReadGuard<T>> {
        self.ptr.maybe_get()
    }

    /// Returns a reference to the value, valid for the lifetime of the
    /// `RcuReadScope`.
    pub fn as_ref<'a>(&self, scope: &'a RcuReadScope) -> Option<&'a T> {
        self.ptr.read(scope).as_ref()
    }

    /// Write the value of the `RcuOptionArc`.
    pub fn update(&self, data: Option<Arc<T>>) {
        let ptr = Self::into_ptr(data);
        // SAFETY: `ptr` was produced by `Self::into_ptr`.
        unsafe { self.replace(ptr) };
    }

    /// Create a new `Option<Arc<T>>` to the referenced object.
    pub fn to_option_arc(&self) -> Option<Arc<T>> {
        let guard = self.read()?;
        let ptr = guard.as_ptr();
        // SAFETY: Incrementing the strong count and reconstructing the `Arc`
        // from the same pointer yields a new owning handle.
        unsafe {
            Arc::increment_strong_count(ptr);
            Some(Arc::from_raw(ptr))
        }
    }

    /// Extract the raw pointer from an `Option<Arc<T>>`.
    ///
    /// The caller must ensure the returned pointer is eventually converted back
    /// into an `Option<Arc<T>>` to balance its reference count.
    fn into_ptr(data: Option<Arc<T>>) -> *mut T {
        match data {
            Some(arc) => Arc::into_raw(arc) as *mut T,
            None => core::ptr::null_mut(),
        }
    }

    /// Replace the pointer in the `RcuOptionArc` with a new pointer.
    ///
    /// # Safety
    ///
    /// The caller must have obtained the pointer from `Self::into_ptr` or from
    /// `core::ptr::null_mut`.
    unsafe fn replace(&self, ptr: *mut T) {
        let old_ptr = self.ptr.replace(ptr);
        if !old_ptr.is_null() {
            // SAFETY: A non-null `old_ptr` was previously produced from an
            // `Arc` by `Self::into_ptr`.
            let arc = unsafe { Arc::from_raw(old_ptr) };
            rcu_drop(arc);
        }
    }
}

impl<T: Send + Sync + 'static> Drop for RcuOptionArc<T> {
    fn drop(&mut self) {
        // SAFETY: We pass `core::ptr::null_mut`.
        unsafe { self.replace(core::ptr::null_mut()) };
    }
}

impl<T: Send + Sync + 'static> Clone for RcuOptionArc<T> {
    fn clone(&self) -> Self {
        Self::new(self.to_option_arc())
    }
}

impl<T: Send + Sync + 'static> From<Option<Arc<T>>> for RcuOptionArc<T> {
    fn from(data: Option<Arc<T>>) -> Self {
        Self::new(data)
    }
}

impl<T: Send + Sync + 'static> Default for RcuOptionArc<T> {
    fn default() -> Self {
        Self::new(None)
    }
}
