// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// REMOVED(fuchsia_component) use fuchsia_component::client::connect_to_protocol_sync;
#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use m6_starnix_std::sync::OnceLock;

#[derive(Default)]
pub struct KernelStats(OnceLock<fidl_fuchsia_kernel::StatsSynchronousProxy>);

impl KernelStats {
    pub fn get(&self) -> &fidl_fuchsia_kernel::StatsSynchronousProxy {
        self.0.get_or_init(|| {
            connect_to_protocol_sync::<fidl_fuchsia_kernel::StatsMarker>()
                .expect("Failed to connect to fuchsia.kernel.Stats.")
        })
    }
}
