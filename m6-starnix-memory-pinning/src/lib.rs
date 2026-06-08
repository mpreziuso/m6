// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2025 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Tools for ensuring that memory managed by Starnix stays resident under
//! memory pressure.
//!
//! M6 adaptation: upstream pins memory by creating a "shadow process" whose VMAR
//! carries a high-priority scheduler role (via `fuchsia.scheduler.RoleManager`)
//! and mapping the target VMO pages into that VMAR. M6 has neither the role
//! manager nor a way to map into a shared VMAR through an `Arc<zx::Vmar>`
//! (the shim's `Vmar::map` requires `&mut self`). The types here therefore keep
//! the exact public API the fork calls but the actual residency-pinning is a
//! documented no-op: [`ShadowProcess::pin_pages`] returns a [`PinnedMapping`]
//! token that records the requested range without forcing the pages resident.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(unused)]

extern crate alloc;

use alloc::sync::{Arc, Weak};

use starnix_uapi::errors::Errno;

// -- ShadowProcess

/// Provides a hook for keeping memory resident under memory pressure.
///
/// M6 adaptation: this owns a VMAR (created over the calling VSpace) into which
/// upstream would map pinned pages. M6 cannot map into a shared VMAR yet, so the
/// VMAR is retained purely to satisfy callers that need an `Arc<zx::Vmar>`
/// (e.g. [`page_buf`]'s extra VMAR) and pinning itself is a no-op.
pub struct ShadowProcess {
    vmar: Arc<zx::Vmar>,
}

impl core::fmt::Debug for ShadowProcess {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `zx::Vmar` does not implement `Debug`; report by base/size instead.
        f.debug_struct("ShadowProcess")
            .field("vmar_base", &self.vmar.base())
            .field("vmar_size", &self.vmar.size())
            .finish()
    }
}

impl ShadowProcess {
    /// Create a new shadow process for pinning memory.
    ///
    /// M6 adaptation: there is no `fuchsia.scheduler.RoleManager` to connect to,
    /// so this simply allocates a VMAR placeholder and never fails for that
    /// reason.
    pub fn new(name: zx::Name) -> Result<Self, zx::Status> {
        let _ = name;
        // A root VMAR over a null VSpace; used only as an `Arc<zx::Vmar>` token.
        Ok(Self { vmar: Arc::new(zx::Vmar::new_root(0)) })
    }

    /// Pin the provided range of the provided VMO to ensure those pages stay
    /// resident under memory pressure.
    ///
    /// M6 adaptation: residency cannot be forced yet, so this records the range
    /// in the returned [`PinnedMapping`] token without mapping the pages.
    pub fn pin_pages(
        &self,
        vmo: &zx::Vmo,
        offset: u64,
        length: usize,
    ) -> Result<Arc<PinnedMapping>, Errno> {
        let _ = vmo;
        Ok(Arc::new(PinnedMapping {
            vmar: Arc::downgrade(&self.vmar),
            base: offset as usize,
            length,
        }))
    }

    /// Return a handle to the VMAR where all mappings are pinned.
    pub fn vmar(&self) -> Arc<zx::Vmar> {
        self.vmar.clone()
    }
}

// -- PinnedMapping

/// A token for a region of pinned memory.
///
/// M6 adaptation: upstream unmaps the pinned range on drop. Because
/// [`ShadowProcess::pin_pages`] does not map anything, dropping this token is a
/// no-op beyond releasing the weak VMAR reference.
#[derive(Clone)]
pub struct PinnedMapping {
    vmar: Weak<zx::Vmar>,
    base: usize,
    length: usize,
}

impl core::fmt::Debug for PinnedMapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `zx::Vmar` does not implement `Debug`; omit the weak VMAR handle.
        f.debug_struct("PinnedMapping")
            .field("base", &self.base)
            .field("length", &self.length)
            .finish()
    }
}

impl PartialEq for PinnedMapping {
    fn eq(&self, rhs: &Self) -> bool {
        Weak::ptr_eq(&self.vmar, &rhs.vmar) && self.base == rhs.base && self.length == rhs.length
    }
}

impl Eq for PinnedMapping {}
