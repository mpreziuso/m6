// Forked from Fuchsia's Starnix for M6 (no_std).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.
//
// Only the `ObjectReleaser`/`ReleaserAction` drop-wrapper types are ported here
// (the async deferred-drop queue from upstream `delayed_releaser` remains omitted
// pending the async strategy). These use only core + `ReleaseGuard`.

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use starnix_types::ownership::ReleaseGuard;

pub trait ReleaserAction<T> {
    fn release(t: ReleaseGuard<T>);
}

/// Wrapper that runs a `ReleaserAction` when the wrapped object is dropped.
pub struct ObjectReleaser<T, F: ReleaserAction<T>>(ManuallyDrop<ReleaseGuard<T>>, PhantomData<F>);

impl<T: Default, F: ReleaserAction<T>> Default for ObjectReleaser<T, F> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T, F: ReleaserAction<T>> From<T> for ObjectReleaser<T, F> {
    fn from(object: T) -> Self {
        Self(ManuallyDrop::new(object.into()), Default::default())
    }
}

impl<T, F: ReleaserAction<T>> Drop for ObjectReleaser<T, F> {
    fn drop(&mut self) {
        // SAFETY: The `ManuallyDrop` is only ever extracted in this `drop` method, so it is
        // guaranteed to still exist here.
        let object = unsafe { ManuallyDrop::take(&mut self.0) };
        F::release(object);
    }
}

impl<T: core::fmt::Debug, F: ReleaserAction<T>> core::fmt::Debug for ObjectReleaser<T, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().fmt(f)
    }
}

impl<T, F: ReleaserAction<T>> core::ops::Deref for ObjectReleaser<T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T, F: ReleaserAction<T>> core::borrow::Borrow<T> for ObjectReleaser<T, F> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T, F: ReleaserAction<T>> core::convert::AsRef<T> for ObjectReleaser<T, F> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}
