// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
mod manager;
pub use manager::*;
// role_overrides uses `regex` and is only consumed by the gated FIDL
// `SchedulerManager`; gate it with the rest of the role-manager machinery.
#[cfg(feature = "fuchsia")]
mod role_overrides;
#[cfg(feature = "fuchsia")]
pub use role_overrides::*;
