// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
mod registry;

pub use registry::*;

#[cfg(feature = "fuchsia")]
pub mod block;
pub mod kobject;
pub mod kobject_store;
pub mod mem;
#[cfg(feature = "fuchsia")]
pub mod remote_block_device;
#[cfg(feature = "fuchsia")]
pub mod serial;
pub mod terminal;
