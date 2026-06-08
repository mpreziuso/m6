// Forked from Fuchsia's Starnix for M6 (no_std).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.
//
// `delayed_releaser` here provides only the `ObjectReleaser`/`ReleaserAction`
// drop-wrapper types (core-only). The async deferred-drop *queue* from upstream
// remains omitted pending the async strategy.

#![no_std]

extern crate alloc;

mod atomic_counter;
mod delayed_releaser;
mod drop_notifier;

pub use atomic_counter::*;
pub use delayed_releaser::*;
pub use drop_notifier::*;
