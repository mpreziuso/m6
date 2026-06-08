// RCU-managed raw pointer and its read guards.
//
// Mirrors the public API of upstream `fuchsia_rcu::rcu_ptr`. Reclamation of
// replaced values is deferred via `rcu_drop` (see `state_machine.rs`), which in
// the bring-up shim leaks the old value so outstanding references stay valid.

use crate::rcu_read_scope::RcuReadScope;
use crate::state_machine::{rcu_assign_pointer, rcu_read_pointer, rcu_replace_pointer};
use core::marker::PhantomData;
use core::ops::Deref;
use core::sync::atomic::AtomicPtr;

/// A pointer managed by the RCU state machine.
///
/// The pointer can be read concurrently without blocking. When the pointer is
/// written, readers may continue to see the old value for some period of time.
#[derive(Debug)]
pub struct RcuPtr<T> {
    ptr: AtomicPtr<T>,
}

impl<T> RcuPtr<T> {
    /// Create a new RCU pointer from a raw pointer.
    pub fn new(ptr: *mut T) -> Self {
        Self {
            ptr: AtomicPtr::new(ptr),
        }
    }

    /// Create a new RCU pointer from a reference.
    pub fn from_ref(reference: &T) -> Self {
        Self::new(reference as *const T as *mut T)
    }

    /// Create a null RCU pointer.
    pub fn null() -> Self {
        Self {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Get the value pointed to by the RCU pointer.
    ///
    /// Panics if the RCU pointer is null.
    pub fn get(&self) -> RcuReadGuard<T> {
        let scope = RcuReadScope::new();
        let ptr = self.read(&scope).as_ptr();
        assert!(!ptr.is_null());
        RcuReadGuard { scope, ptr }
    }

    /// Get the value pointed to by the RCU pointer, or `None` if it is null.
    pub fn maybe_get(&self) -> Option<RcuReadGuard<T>> {
        let scope = RcuReadScope::new();
        let ptr = self.read(&scope).as_ptr();
        if ptr.is_null() {
            None
        } else {
            Some(RcuReadGuard { scope, ptr })
        }
    }

    /// Read the value of the RCU pointer.
    ///
    /// The returned pointer remains valid until the `RcuReadScope` is dropped.
    pub fn read<'a>(&self, scope: &'a RcuReadScope) -> RcuPtrRef<'a, T> {
        let ptr = rcu_read_pointer(&self.ptr);
        // SAFETY: The RCU state machine ensures the pointer is valid for reads
        // until we drop the `RcuReadScope` whose lifetime is described by the
        // lifetime parameter `'a`.
        unsafe { RcuPtrRef::new(scope, ptr) }
    }

    /// Assign a new value to the RCU pointer.
    pub fn assign(&self, ptr: *mut T) {
        rcu_assign_pointer(&self.ptr, ptr);
    }

    /// Assign a new value to the RCU pointer from a borrowed `RcuPtrRef`.
    pub fn assign_ptr(&self, ptr: RcuPtrRef<'_, T>) {
        self.assign(ptr.as_mut_ptr());
    }

    /// Replace the value of the RCU pointer, returning the previous value.
    pub fn replace(&self, ptr: *mut T) -> *mut T {
        rcu_replace_pointer(&self.ptr, ptr)
    }

    /// Replace the value of the RCU pointer from a borrowed `RcuPtrRef`.
    pub fn replace_ptr(&self, ptr: RcuPtrRef<'_, T>) -> *mut T {
        self.replace(ptr.as_mut_ptr())
    }

    /// Poison the RCU pointer so readers see a dangling pointer.
    pub fn poison(&self) {
        rcu_assign_pointer(&self.ptr, core::ptr::dangling_mut());
    }
}

/// A read guard for an object managed by the RCU state machine.
///
/// The guard keeps an `RcuReadScope` alive, ensuring the object remains valid
/// until the guard is dropped.
pub struct RcuReadGuard<T> {
    /// The scope in which the object is valid.
    scope: RcuReadScope,

    /// The pointer to the object.
    ptr: *const T,
}

impl<T> RcuReadGuard<T> {
    /// Get the scope in which the object is valid.
    pub fn scope(&self) -> &RcuReadScope {
        &self.scope
    }

    /// Get the raw pointer to the object.
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }
}

impl<T> Deref for RcuReadGuard<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: The RCU state machine ensures the pointer is valid for reads
        // until we drop the `RcuReadScope` held by this guard.
        unsafe { &*self.ptr }
    }
}

/// A pointer to an object managed by the RCU state machine, valid for reading
/// until the `RcuReadScope` is dropped.
pub struct RcuPtrRef<'a, T> {
    /// The pointer to the object.
    ptr: *const T,

    /// The scope in which the pointer is valid.
    _marker: PhantomData<&'a T>,
}

impl<'a, T> Clone for RcuPtrRef<'a, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, T> Copy for RcuPtrRef<'a, T> {}

impl<'a, T> RcuPtrRef<'a, T> {
    /// Create a new `RcuPtrRef` from a pointer and a scope.
    ///
    /// # Safety
    ///
    /// The pointer must be valid for reading until the `RcuReadScope` is
    /// dropped.
    pub unsafe fn new(_scope: &'a RcuReadScope, ptr: *const T) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Create a null `RcuPtrRef`.
    pub fn null() -> Self {
        Self {
            ptr: core::ptr::null(),
            _marker: PhantomData,
        }
    }

    /// Check if the pointer is null.
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    /// Create a new `RcuPtrRef` from a reference.
    pub fn from_ref(object: &'a T) -> Self {
        Self {
            ptr: object as *const T,
            _marker: PhantomData,
        }
    }

    /// Get a reference to the object, or `None` if the pointer is null.
    pub fn as_ref(&self) -> Option<&'a T> {
        if self.is_null() {
            None
        } else {
            // SAFETY: The RCU state machine ensures the pointer is valid for
            // reads until we drop the `RcuReadScope` whose lifetime is described
            // by the lifetime parameter `'a`.
            Some(unsafe { &*self.ptr })
        }
    }

    /// Get the raw pointer to the object.
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    /// Get the raw mutable pointer to the object.
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr as *mut T
    }

    /// Add a byte offset to the pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure the offset is within the bounds of the object and
    /// points to a valid object of type `U`.
    pub unsafe fn add_byte_offset<U>(&self, offset: usize) -> RcuPtrRef<'a, U> {
        let ptr = self.ptr as *const u8;
        // SAFETY: The caller guarantees the offset is in bounds and yields a
        // valid `U`.
        RcuPtrRef {
            ptr: unsafe { ptr.add(offset) } as *const U,
            _marker: PhantomData,
        }
    }

    /// Subtract a byte offset from the pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure the offset is within the bounds of the object and
    /// points to a valid object of type `U`.
    pub unsafe fn sub_byte_offset<U>(&self, offset: usize) -> RcuPtrRef<'a, U> {
        let ptr = self.ptr as *const u8;
        // SAFETY: The caller guarantees the offset is in bounds and yields a
        // valid `U`.
        RcuPtrRef {
            ptr: unsafe { ptr.sub(offset) } as *const U,
            _marker: PhantomData,
        }
    }
}
