// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// REMOVED(fidl) use fidl_fuchsia_kernel as fkernel;
// REMOVED(fuchsia_component) use fuchsia_component::client::connect_to_protocol_sync;
#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use m6_starnix_std::sync::LazyLock;

#[cfg(feature = "fuchsia")]
pub static VMEX_RESOURCE: LazyLock<zx::Resource> = LazyLock::new(|| {
    connect_to_protocol_sync::<fkernel::VmexResourceMarker>()
        .expect("couldn't connect to fuchsia.kernel.VmexResource")
        .get(zx::MonotonicInstant::INFINITE)
        .expect("couldn't talk to fuchsia.kernel.VmexResource")
});

// -- M6 has no VmexResource protocol; expose an invalid handle so callers that
// only need the type compile. Mapping executable VMOs is gated separately.
#[cfg(not(feature = "fuchsia"))]
pub static VMEX_RESOURCE: LazyLock<zx::Resource> = LazyLock::new(zx::Resource::default);
