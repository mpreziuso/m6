// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
#[derive(Clone, Debug, Default)]
pub enum MlockPinFlavor {
    #[default]
    Noop,
    ShadowProcess,
    VmarAlwaysNeed,
}

impl MlockPinFlavor {
    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        Ok(match s {
            "noop" => Self::Noop,
            "shadow_process" => Self::ShadowProcess,
            "vmar_always_need" => Self::VmarAlwaysNeed,
            _ => anyhow::bail!(
                "unknown mlock_flavor {s}, known flavors: noop, shadow_process, vmar_always_need"
            ),
        })
    }
}
