// Copyright 2023 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// M6: ported from Fuchsia starnix_types::ownership. std:: -> core::/alloc::,
// zx::Futex/Status come from the local `zx_time` shim.

//! This crates introduces a framework to handle explicit ownership.
//!
//! Explicit ownership is used for object that needs to be cleaned, but cannot use `Drop` because
//! the release operation requires a context.

// Not all instance of OwnedRef and Releasable are used in non test code yet.
#![allow(dead_code)]

use crate::zx_time as zx;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::hash::Hash;
use core::hash::Hasher;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

/// The base trait for explicit ownership. Any `Releasable` object must call `release` before
/// being dropped.
pub trait Releasable {
    type Context<'a>;

    fn release<'a>(self, c: Self::Context<'a>);
}

/// Releasing an option calls release if the option is not empty.
impl<T: Releasable> Releasable for Option<T> {
    type Context<'a> = T::Context<'a>;

    fn release<'a>(self, c: Self::Context<'a>) {
        if let Some(v) = self {
            v.release(c);
        }
    }
}

/// Releasing a vec calls release on each element
impl<T: Releasable> Releasable for Vec<T>
where
    for<'a> T::Context<'a>: Clone,
{
    type Context<'a> = T::Context<'a>;

    fn release<'a>(self, c: Self::Context<'a>) {
        for v in self {
            v.release(c.clone());
        }
    }
}

/// Releasing a result calls release on the value if the result is ok.
impl<T: Releasable, E> Releasable for Result<T, E> {
    type Context<'a> = T::Context<'a>;

    fn release<'a>(self, c: Self::Context<'a>) {
        if let Ok(v) = self {
            v.release(c);
        }
    }
}

impl<T: Releasable> Releasable for ReleaseGuard<T> {
    type Context<'a> = T::Context<'a>;

    fn release<'a>(self, c: Self::Context<'a>) {
        self.drop_guard.disarm();
        self.value.release(c);
    }
}

/// Trait for object that can be shared. This is an equivalent of `Clone` for objects that require
/// to be released.
pub trait Share {
    fn share(&self) -> Self;
}

impl<T: Share> Share for Option<T> {
    fn share(&self) -> Self {
        match self {
            None => None,
            Some(t) => Some(t.share()),
        }
    }
}

/// An owning reference to a shared owned object. Each instance must call `release` before being
/// dropped.
#[must_use = "OwnedRef must be released"]
pub struct OwnedRef<T> {
    /// The shared data.
    inner: Option<Arc<RefInner<T>>>,

    /// A guard that will ensure a panic on drop if the ref has not been released.
    drop_guard: DropGuard,
}

impl<T> OwnedRef<T> {
    pub fn new(value: T) -> Self {
        Self { inner: Some(Arc::new(RefInner::new(value))), drop_guard: Default::default() }
    }

    pub fn new_cyclic<F>(data_fn: F) -> Self
    where
        F: FnOnce(WeakRef<T>) -> T,
    {
        let inner = Arc::new_cyclic(|weak_inner| {
            let weak = WeakRef(weak_inner.clone());
            RefInner::new(data_fn(weak))
        });
        Self { inner: Some(inner), drop_guard: Default::default() }
    }

    /// Provides a raw pointer to the data.
    pub fn as_ptr(this: &Self) -> *const T {
        &Self::inner(this).value.value as *const T
    }

    /// Returns true if the two objects point to the same allocation
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Self::as_ptr(this) == Self::as_ptr(other)
    }

    /// Produce a `WeakRef` from a `OwnedRef`.
    pub fn downgrade(this: &Self) -> WeakRef<T> {
        WeakRef(Arc::downgrade(Self::inner(this)))
    }

    /// Produce a `TempRef` from a `OwnedRef`.
    pub fn temp(this: &Self) -> TempRef<'_, T> {
        TempRef::new(Arc::clone(Self::inner(this)))
    }

    fn inner(this: &Self) -> &Arc<RefInner<T>> {
        this.inner.as_ref().unwrap_or_else(|| {
            panic!("OwnedRef<{}> has been released.", core::any::type_name::<T>())
        })
    }

    fn re_own(inner: Arc<RefInner<T>>) -> Option<Self> {
        let mut owned_refs = inner.owned_refs_count.load(Ordering::Relaxed);
        loop {
            if owned_refs == 0 {
                return None;
            }
            match inner.owned_refs_count.compare_exchange(
                owned_refs,
                owned_refs + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(Self { inner: Some(inner), drop_guard: Default::default() });
                }
                Err(v) => {
                    owned_refs = v;
                }
            }
        }
    }
}

impl<T: Releasable> OwnedRef<T> {
    /// Take the releasable from the `OwnedRef`. Returns None if the `OwnedRef` is not the last
    /// reference to the data.
    pub fn take(this: &mut Self) -> Option<ReleaseGuard<T>> {
        this.drop_guard.disarm();
        let inner = this.inner.take().unwrap_or_else(|| {
            panic!("OwnedRef<{}> has been released.", core::any::type_name::<T>())
        });
        let previous_count = inner.owned_refs_count.fetch_sub(1, Ordering::Release);
        if previous_count == 1 {
            fence(Ordering::Acquire);
            Some(Self::wait_and_take_value(inner))
        } else {
            None
        }
    }

    fn wait_and_take_value(mut inner: Arc<RefInner<T>>) -> ReleaseGuard<T> {
        loop {
            debug_assert_eq!(inner.owned_refs_count.load(Ordering::Acquire), 0);
            match Arc::try_unwrap(inner) {
                Ok(value) => return value.value,
                Err(value) => inner = value,
            }
            inner.wait_for_no_ref_once();
        }
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for OwnedRef<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Self::inner(self).value.fmt(f)
    }
}

impl<T: Releasable> Share for OwnedRef<T> {
    fn share(&self) -> Self {
        let inner = Self::inner(self);
        let previous_count = inner.owned_refs_count.fetch_add(1, Ordering::Relaxed);
        debug_assert!(previous_count > 0, "OwnedRef should not be used after being released.");
        Self { inner: Some(Arc::clone(inner)), drop_guard: Default::default() }
    }
}

impl<T: Releasable> Releasable for OwnedRef<T> {
    type Context<'a> = T::Context<'a>;

    #[allow(unused_mut)]
    fn release<'a>(mut self, c: Self::Context<'a>) {
        OwnedRef::take(&mut self).release(c);
    }
}

impl<T: Default> Default for OwnedRef<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> core::ops::Deref for OwnedRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &Self::inner(self).deref().value
    }
}

impl<T> core::borrow::Borrow<T> for OwnedRef<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T> core::convert::AsRef<T> for OwnedRef<T> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T: PartialEq> PartialEq<TempRef<'_, T>> for OwnedRef<T> {
    fn eq(&self, other: &TempRef<'_, T>) -> bool {
        Arc::ptr_eq(Self::inner(self), &other.0)
    }
}

impl<T: PartialEq> PartialEq for OwnedRef<T> {
    fn eq(&self, other: &OwnedRef<T>) -> bool {
        Arc::ptr_eq(Self::inner(self), Self::inner(other)) || **self == **other
    }
}

impl<T: Eq> Eq for OwnedRef<T> {}

impl<T: PartialOrd> PartialOrd for OwnedRef<T> {
    fn partial_cmp(&self, other: &OwnedRef<T>) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<T: Ord> Ord for OwnedRef<T> {
    fn cmp(&self, other: &OwnedRef<T>) -> core::cmp::Ordering {
        (**self).cmp(&**other)
    }
}

impl<T: Hash> Hash for OwnedRef<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl<T> From<&OwnedRef<T>> for WeakRef<T> {
    fn from(owner: &OwnedRef<T>) -> Self {
        OwnedRef::downgrade(owner)
    }
}

impl<'a, T> From<&'a OwnedRef<T>> for TempRef<'a, T> {
    fn from(owner: &'a OwnedRef<T>) -> Self {
        OwnedRef::temp(owner)
    }
}

impl<'a, T> From<&'a mut OwnedRef<T>> for TempRef<'a, T> {
    fn from(owner: &'a mut OwnedRef<T>) -> Self {
        OwnedRef::temp(owner)
    }
}

/// A weak reference to a shared owned object.
#[derive(Debug)]
pub struct WeakRef<T>(Weak<RefInner<T>>);

impl<T> WeakRef<T> {
    pub fn new() -> Self {
        Self(Weak::new())
    }

    pub fn upgrade(&self) -> Option<TempRef<'_, T>> {
        if let Some(value) = self.0.upgrade() {
            let temp_ref = TempRef::new(value);
            if temp_ref.0.owned_refs_count.load(Ordering::Acquire) > 0 {
                return Some(temp_ref);
            }
        }
        None
    }

    pub fn re_own(&self) -> Option<OwnedRef<T>> {
        self.0.upgrade().and_then(OwnedRef::re_own)
    }

    /// Returns a raw pointer to the object T pointed to by this WeakRef<T>.
    pub fn as_ptr(&self) -> *const T {
        let base = self.0.as_ptr();
        let value = memoffset::raw_field!(base, RefInner<T>, value);
        memoffset::raw_field!(value, ReleaseGuard<T>, value)
    }

    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Self::as_ptr(this) == Self::as_ptr(other)
    }
}

impl<T> Default for WeakRef<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for WeakRef<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> PartialEq for WeakRef<T> {
    fn eq(&self, other: &Self) -> bool {
        WeakRef::ptr_eq(self, other)
    }
}

/// Wrapper around `WeakRef` allowing to use it in a Set or as a key of a Map.
pub struct WeakRefKey<T>(pub WeakRef<T>);
impl<T> PartialEq for WeakRefKey<T> {
    fn eq(&self, other: &Self) -> bool {
        WeakRef::ptr_eq(&self.0, &other.0)
    }
}
impl<T> PartialOrd for WeakRefKey<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for WeakRefKey<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        WeakRef::as_ptr(&self.0).cmp(&WeakRef::as_ptr(&other.0))
    }
}
impl<T> From<WeakRef<T>> for WeakRefKey<T> {
    fn from(weak_ref: WeakRef<T>) -> Self {
        Self(weak_ref)
    }
}
impl<'a, T> From<&TempRef<'a, T>> for WeakRefKey<T> {
    fn from(temp_ref: &TempRef<'a, T>) -> Self {
        Self(WeakRef::from(temp_ref))
    }
}
impl<T> From<&OwnedRef<T>> for WeakRefKey<T> {
    fn from(owned_ref: &OwnedRef<T>) -> Self {
        Self(WeakRef::from(owned_ref))
    }
}
impl<T> Clone for WeakRefKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Eq for WeakRefKey<T> {}
impl<T> Hash for WeakRefKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        WeakRef::as_ptr(&self.0).hash(state);
    }
}
impl<T> core::ops::Deref for WeakRefKey<T> {
    type Target = WeakRef<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> core::fmt::Debug for WeakRefKey<T> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_tuple(core::any::type_name::<Self>()).field(&self.0.as_ptr()).finish()
    }
}

/// A temporary reference to a shared owned object.
// Until negative trait bound are implemented, using `*mut u8` to prevent transferring TempRef
// across threads.
pub struct TempRef<'a, T>(Arc<RefInner<T>>, core::marker::PhantomData<(&'a T, *mut u8)>);

impl<'a, T> core::fmt::Debug for TempRef<'a, T>
where
    T: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().fmt(f)
    }
}

impl<'a, T> Drop for TempRef<'a, T> {
    fn drop(&mut self) {
        self.0.dec_temp_ref();
    }
}

impl<'a, T> TempRef<'a, T> {
    fn new(inner: Arc<RefInner<T>>) -> Self {
        inner.inc_temp_ref();
        Self(inner, Default::default())
    }

    pub fn as_ptr(this: &Self) -> *const T {
        &this.0.value.value as *const T
    }

    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Self::as_ptr(this) == Self::as_ptr(other)
    }

    pub fn into_static(this: Self) -> TempRef<'static, T> {
        TempRef::new(this.0.clone())
    }

    pub fn re_own(&self) -> Option<OwnedRef<T>> {
        OwnedRef::re_own(Arc::clone(&self.0))
    }
}

impl<'a, T> From<&TempRef<'a, T>> for WeakRef<T> {
    fn from(temp_ref: &TempRef<'a, T>) -> Self {
        Self(Arc::downgrade(&temp_ref.0))
    }
}

impl<'a, T> From<TempRef<'a, T>> for WeakRef<T> {
    fn from(temp_ref: TempRef<'a, T>) -> Self {
        Self(Arc::downgrade(&temp_ref.0))
    }
}

impl<'a, T> core::ops::Deref for TempRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0.deref().value
    }
}

impl<'a, T> core::borrow::Borrow<T> for TempRef<'a, T> {
    fn borrow(&self) -> &T {
        &self.0.deref().value
    }
}

impl<'a, T> core::convert::AsRef<T> for TempRef<'a, T> {
    fn as_ref(&self) -> &T {
        &self.0.deref().value
    }
}

impl<'a, T: PartialEq> PartialEq for TempRef<'a, T> {
    fn eq(&self, other: &TempRef<'_, T>) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || **self == **other
    }
}

impl<'a, T: Eq> Eq for TempRef<'a, T> {}

impl<'a, T: PartialOrd> PartialOrd for TempRef<'a, T> {
    fn partial_cmp(&self, other: &TempRef<'_, T>) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<'a, T: Ord> Ord for TempRef<'a, T> {
    fn cmp(&self, other: &TempRef<'_, T>) -> core::cmp::Ordering {
        (**self).cmp(&**other)
    }
}

impl<'a, T: Hash> Hash for TempRef<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

/// Wrapper around `TempRef` allowing to use it in a Set or as a key of a Map.
pub struct TempRefKey<'a, T>(pub TempRef<'a, T>);
impl<'a, T> PartialEq for TempRefKey<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        TempRef::ptr_eq(&self.0, &other.0)
    }
}
impl<'a, T> Eq for TempRefKey<'a, T> {}
impl<'a, T> Hash for TempRefKey<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        TempRef::as_ptr(&self.0).hash(state);
    }
}
impl<'a, T> core::ops::Deref for TempRefKey<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

/// A wrapper around a Releasable object that will check, in test and when assertions are enabled,
/// that the value has been released before being dropped.
#[must_use = "ReleaseGuard must be released"]
pub struct ReleaseGuard<T> {
    /// The wrapped value.
    value: T,

    /// A guard that will ensure a panic on drop if the ref has not been released.
    drop_guard: DropGuard,
}

impl<T> ReleaseGuard<T> {
    pub fn new_released(value: T) -> Self {
        let result: Self = value.into();
        result.drop_guard.disarm();
        result
    }

    /// Disarm this release guard.
    pub fn take(this: ReleaseGuard<T>) -> T {
        this.drop_guard.disarm();
        this.value
    }
}

impl<T: Default> ReleaseGuard<T> {
    pub fn default_released() -> Self {
        Self::new_released(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for ReleaseGuard<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: Default> Default for ReleaseGuard<T> {
    fn default() -> Self {
        T::default().into()
    }
}

impl<T: Clone> Clone for ReleaseGuard<T> {
    fn clone(&self) -> Self {
        self.value.clone().into()
    }
}

impl<T> From<T> for ReleaseGuard<T> {
    fn from(value: T) -> Self {
        Self { value, drop_guard: Default::default() }
    }
}

impl<T> core::ops::Deref for ReleaseGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> core::ops::DerefMut for ReleaseGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T> core::borrow::Borrow<T> for ReleaseGuard<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T> core::convert::AsRef<T> for ReleaseGuard<T> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T: PartialEq> PartialEq for ReleaseGuard<T> {
    fn eq(&self, other: &ReleaseGuard<T>) -> bool {
        **self == **other
    }
}

impl<T: Eq> Eq for ReleaseGuard<T> {}

impl<T: PartialOrd> PartialOrd for ReleaseGuard<T> {
    fn partial_cmp(&self, other: &ReleaseGuard<T>) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<T: Ord> Ord for ReleaseGuard<T> {
    fn cmp(&self, other: &ReleaseGuard<T>) -> core::cmp::Ordering {
        (**self).cmp(&**other)
    }
}

impl<T: Hash> Hash for ReleaseGuard<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

#[derive(Default, Debug)]
pub struct DropGuard {
    #[cfg(any(test, debug_assertions))]
    released: core::sync::atomic::AtomicBool,
}

impl DropGuard {
    #[inline(always)]
    pub fn disarm(&self) {
        #[cfg(any(test, debug_assertions))]
        {
            if self
                .released
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                panic!("Guard was disarmed twice");
            }
        }
    }
}

#[cfg(any(test, debug_assertions))]
impl Drop for DropGuard {
    fn drop(&mut self) {
        assert!(*self.released.get_mut());
    }
}

// M6: upstream tracks a per-thread TempRef count via thread_local!, which is
// unavailable in no_std. We keep the public API but make it a no-op here.
/// Assert that no temp ref exist on the current thread.
pub fn debug_assert_no_local_temp_ref() {
    // M6: no thread-local accounting in no_std; intentionally a no-op.
}

/// The internal data of `OwnedRef`/`WeakRef`/`TempRef`.
struct RefInner<T> {
    /// The underlying value.
    value: ReleaseGuard<T>,
    /// The number of `OwnedRef` sharing this data.
    owned_refs_count: AtomicUsize,
    /// The number of `TempRef` sharing this data.
    temp_refs_count: zx::Futex,
}

impl<T> RefInner<T> {
    fn new(value: T) -> Self {
        Self {
            value: value.into(),
            owned_refs_count: AtomicUsize::new(1),
            temp_refs_count: zx::Futex::new(0),
        }
    }

    fn inc_temp_ref(&self) {
        self.temp_refs_count.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_temp_ref(&self) {
        let previous_count = self.temp_refs_count.fetch_sub(1, Ordering::Release);
        if previous_count == 1 {
            fence(Ordering::Acquire);
            self.temp_refs_count.wake_single_owner();
        }
    }

    fn wait_for_no_ref_once(self: &Arc<Self>) {
        let current_value = self.temp_refs_count.load(Ordering::Acquire);
        if current_value == 0 {
            return;
        }
        let result =
            self.temp_refs_count.wait(current_value, None, zx::MonotonicInstant::INFINITE);
        debug_assert!(
            result == Ok(()) || result == Err(zx::Status::BadState),
            "Unexpected result: {result:?}"
        );
    }
}

/// Macro that ensure the releasable is released with the given context if the body returns an
/// error.
#[macro_export]
macro_rules! release_on_error {
    ($releasable_name:ident, $context:expr, $body:block ) => {{
        #[allow(clippy::redundant_closure_call)]
        let result = { (|| $body)() };
        match result {
            Err(e) => {
                $releasable_name.release($context);
                return Err(e);
            }
            Ok(x) => x,
        }
    }};
}

/// Macro that ensure the releasable is released with the given context after the body returns.
#[macro_export]
macro_rules! release_after {
    ($releasable_name:ident, $context:expr, async || $($output_type:ty)? $body:block ) => {{
        #[allow(clippy::redundant_closure_call)]
        let result = { (async || $(-> $output_type)? { $body })().await };
        $releasable_name.release($context);
        result
    }};
    ($releasable_name:ident, $context:expr, $(|| -> $output_type:ty)? $body:block ) => {{
        #[allow(clippy::redundant_closure_call)]
        let result = { (|| $(-> $output_type)? { $body })() };
        $releasable_name.release($context);
        result
    }};
}

/// Macro that ensure the iterator of releasables are released with the given context after
/// the body returns.
#[macro_export]
macro_rules! release_iter_after {
    ($releasable_iter:ident, $context:expr, async || $(-> $output_type:ty)? $body:block ) => {{
        #[allow(clippy::redundant_closure_call)]
        let result = { (async || $(-> $output_type)? { $body })().await };
        for item in $releasable_iter.into_iter() {
            item.release($context);
        }
        result
    }};
    ($releasable_iter:ident, $context:expr, $(|| -> $output_type:ty)? $body:block ) => {{
        #[allow(clippy::redundant_closure_call)]
        let result = { (|| $(-> $output_type)? { $body })() };
        for item in $releasable_iter.into_iter() {
            item.release($context);
        }
        result
    }};
}

pub use {release_after, release_iter_after, release_on_error};
