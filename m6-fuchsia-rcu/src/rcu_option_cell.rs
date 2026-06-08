// An RCU version of `Cell<Option<T>>`.

use crate::rcu_ptr::{RcuPtr, RcuReadGuard};
use crate::rcu_read_scope::RcuReadScope;
use crate::state_machine::rcu_drop;
use alloc::boxed::Box;

/// An RCU (Read-Copy-Update) version of `Cell<Option<T>>`.
///
/// This Cell can be read from multiple threads concurrently without blocking.
/// When the Cell is written, reads may continue to see the old value for some
/// period of time.
#[derive(Debug)]
pub struct RcuOptionCell<T: Send + Sync + 'static> {
    ptr: RcuPtr<T>,
}

impl<T: Send + Sync + 'static> RcuOptionCell<T> {
    /// Create a new RCU Cell from an optional value.
    pub fn new(data: Option<T>) -> Self {
        Self::from(data.map(Box::new))
    }

    /// Read the value of the RCU Cell.
    pub fn read(&self) -> Option<RcuReadGuard<T>> {
        self.ptr.maybe_get()
    }

    /// Returns a reference to the value, valid for the lifetime of the
    /// `RcuReadScope`.
    pub fn as_ref<'a>(&self, scope: &'a RcuReadScope) -> Option<&'a T> {
        self.ptr.read(scope).as_ref()
    }

    /// Write the value of the RCU Cell.
    pub fn update(&self, data: Option<T>) {
        let ptr = data
            .map(|data| Box::into_raw(Box::new(data)))
            .unwrap_or(core::ptr::null_mut());
        // SAFETY: `ptr` is either null or was produced by `Box::into_raw`.
        unsafe { self.replace(ptr) };
    }

    /// Replace the pointer in the RCU Cell with a new pointer.
    ///
    /// # Safety
    ///
    /// The pointer must have been created by `Box::into_raw` or from
    /// `core::ptr::null_mut`.
    unsafe fn replace(&self, ptr: *mut T) {
        let old_ptr = self.ptr.replace(ptr);
        if !old_ptr.is_null() {
            // SAFETY: A non-null `old_ptr` was previously produced by
            // `Box::into_raw`.
            let object = unsafe { Box::from_raw(old_ptr) };
            rcu_drop(object);
        }
    }
}

impl<T: Send + Sync + 'static> Drop for RcuOptionCell<T> {
    fn drop(&mut self) {
        // SAFETY: We pass `core::ptr::null_mut`.
        unsafe { self.replace(core::ptr::null_mut()) };
    }
}

impl<T: Send + Sync + 'static> Default for RcuOptionCell<T> {
    fn default() -> Self {
        Self::new(None)
    }
}

impl<T: Clone + Send + Sync + 'static> Clone for RcuOptionCell<T> {
    fn clone(&self) -> Self {
        let value = self.read();
        Self::new(value.map(|value| value.clone()))
    }
}

impl<T: Send + Sync + 'static> From<Option<Box<T>>> for RcuOptionCell<T> {
    fn from(value: Option<Box<T>>) -> Self {
        let ptr = value.map(Box::into_raw).unwrap_or(core::ptr::null_mut());
        Self {
            ptr: RcuPtr::new(ptr),
        }
    }
}
