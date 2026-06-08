// An RCU version of `Arc`.

use crate::rcu_ptr::{RcuPtr, RcuReadGuard};
use crate::rcu_read_scope::RcuReadScope;
use crate::state_machine::rcu_drop;
use alloc::sync::Arc;

/// An RCU (Read-Copy-Update) version of `Arc`.
///
/// This Arc can be read from multiple threads concurrently without blocking.
/// When the Arc is written, reads may continue to see the old value for some
/// period of time.
#[derive(Debug)]
pub struct RcuArc<T: Send + Sync + 'static> {
    ptr: RcuPtr<T>,
}

impl<T: Send + Sync + 'static> RcuArc<T> {
    /// Create a new RCU Arc from an `Arc`.
    pub fn new(data: Arc<T>) -> Self {
        Self {
            ptr: RcuPtr::new(Self::into_ptr(data)),
        }
    }

    /// Read the value of the RCU Arc.
    ///
    /// The referenced object remains valid until the `RcuReadGuard` is dropped.
    pub fn read(&self) -> RcuReadGuard<T> {
        self.ptr.get()
    }

    /// Returns a reference to the value of the RCU Arc, valid for the lifetime of
    /// the `RcuReadScope`.
    pub fn as_ref<'a>(&self, scope: &'a RcuReadScope) -> &'a T {
        self.ptr.read(scope).as_ref().unwrap()
    }

    /// Write the value of the RCU Arc.
    pub fn update(&self, data: Arc<T>) {
        let ptr = Self::into_ptr(data);
        // SAFETY: `ptr` was produced by `Self::into_ptr`.
        unsafe { self.replace(ptr) };
    }

    /// Create a new `Arc` to the object referenced by the RCU Arc.
    pub fn to_arc(&self) -> Arc<T> {
        let guard = self.read();
        let ptr = guard.as_ptr();
        // SAFETY: Incrementing the strong count and reconstructing the `Arc`
        // from the same pointer yields a new owning handle.
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }

    /// Extract the raw pointer from an `Arc`.
    ///
    /// The caller must ensure the returned pointer is eventually converted back
    /// into an `Arc` to balance its reference count.
    fn into_ptr(data: Arc<T>) -> *mut T {
        Arc::into_raw(data) as *mut T
    }

    /// Replace the pointer in the RCU Arc with a new pointer.
    ///
    /// # Safety
    ///
    /// The caller must have obtained the pointer from `Self::into_ptr` or from
    /// `core::ptr::null_mut`.
    unsafe fn replace(&self, ptr: *mut T) {
        let old_ptr = self.ptr.replace(ptr);
        // SAFETY: `old_ptr` was previously produced by `Self::into_ptr`.
        let arc = unsafe { Arc::from_raw(old_ptr) };
        rcu_drop(arc);
    }
}

impl<T: Send + Sync + 'static> Drop for RcuArc<T> {
    fn drop(&mut self) {
        // SAFETY: A non-null pointer was always produced by `Self::into_ptr`.
        unsafe { self.replace(core::ptr::null_mut()) };
    }
}

impl<T: Send + Sync + 'static> Clone for RcuArc<T> {
    fn clone(&self) -> Self {
        Self::new(self.to_arc())
    }
}

impl<T: Send + Sync + 'static> From<Arc<T>> for RcuArc<T> {
    fn from(data: Arc<T>) -> Self {
        Self::new(data)
    }
}

impl<T: Default + Send + Sync + 'static> Default for RcuArc<T> {
    fn default() -> Self {
        Self::new(Arc::new(T::default()))
    }
}
