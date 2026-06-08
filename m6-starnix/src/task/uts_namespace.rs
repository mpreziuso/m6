// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::vfs::FsString;
use starnix_sync::RwLock;
use m6_starnix_std::sync::Arc;

const DEFAULT_HOST_NAME: &str = "localhost";
const DEFAULT_DOMAIN_NAME: &str = "localdomain";

pub type UtsNamespaceHandle = Arc<RwLock<UtsNamespace>>;

// Unix Time-sharing Namespace (UTS) information.
// Stores the hostname and domainname for a specific process.
//
// See https://man7.org/linux/man-pages/man7/uts_namespaces.7.html
#[derive(Clone)]
pub struct UtsNamespace {
    pub hostname: FsString,
    pub domainname: FsString,
}

impl UtsNamespace {
    pub fn fork(&self) -> UtsNamespaceHandle {
        Arc::new(RwLock::new(self.clone()))
    }
}

impl Default for UtsNamespace {
    fn default() -> Self {
        Self { hostname: DEFAULT_HOST_NAME.into(), domainname: DEFAULT_DOMAIN_NAME.into() }
    }
}
