// An RCU version of `Cell`.

use crate::rcu_ptr::{RcuPtr, RcuReadGuard};
use crate::rcu_read_scope::RcuReadScope;
use crate::state_machine::rcu_drop;
use alloc::boxed::Box;

/// An RCU (Read-Copy-Update) version of `Cell`.
///
/// This Cell can be read from multiple threads concurrently without blocking.
/// When the Cell is written, reads may continue to see the old value for some
/// period of time.
#[derive(Debug)]
pub struct RcuCell<T: Send + Sync + 'static> {
    ptr: RcuPtr<T>,
}

impl<T: Send + Sync + 'static> RcuCell<T> {
    /// Create a new RCU Cell from a value.
    pub fn new(data: T) -> Self {
        Self::from(Box::new(data))
    }

    /// Read the value of the RCU Cell.
    pub fn read(&self) -> RcuReadGuard<T> {
        self.ptr.get()
    }

    /// Returns a reference to the value, valid for the lifetime of the
    /// `RcuReadScope`.
    pub fn as_ref<'a>(&self, scope: &'a RcuReadScope) -> &'a T {
        self.ptr.read(scope).as_ref().unwrap()
    }

    /// Write the value of the RCU Cell.
    pub fn update(&self, data: T) {
        let ptr = Box::into_raw(Box::new(data));
        // SAFETY: `ptr` was produced by `Box::into_raw`.
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
        // SAFETY: `old_ptr` was previously produced by `Box::into_raw`.
        let object = unsafe { Box::from_raw(old_ptr) };
        rcu_drop(object);
    }
}

impl<T: Send + Sync + 'static> Drop for RcuCell<T> {
    fn drop(&mut self) {
        // SAFETY: A non-null pointer was always produced by `Box::into_raw`.
        unsafe { self.replace(core::ptr::null_mut()) };
    }
}

impl<T: Default + Send + Sync + 'static> Default for RcuCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Clone + Send + Sync + 'static> Clone for RcuCell<T> {
    fn clone(&self) -> Self {
        let value = self.read();
        Self::new(value.clone())
    }
}

impl<T: Send + Sync + 'static> From<Box<T>> for RcuCell<T> {
    fn from(value: Box<T>) -> Self {
        Self {
            ptr: RcuPtr::new(Box::into_raw(value)),
        }
    }
}
