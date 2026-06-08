// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module provides types and hook APIs supporting Linux Security Modules
//! functionality in Starnix.  LSM provides a generic set of hooks, and opaque
//! types, used to decouple the rest of the kernel from the details of any
//! specific security enforcement subsystem (e.g. SELinux, POSIX.1e, etc).
//!
//! M6 uses a capability-based security model rather than an in-kernel LSM, so
//! this layer is a permissive stub: every hook returns its "allowed" default
//! and no SELinux policy is ever consulted. The SELinux policy engine and the
//! `selinux_hooks` backend were never forked; the opaque per-object state types
//! below are therefore trivial placeholders that preserve the public API the
//! rest of the kernel relies upon.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::vfs::FsStr;
use starnix_sync::Mutex;

/// Common capabilities hook implementations called by the LSM hooks.
mod common_cap;

/// YAMA hook implementations used to restrict ptrace access.
pub mod yama;

/// Linux Security Modules hooks for use within the Starnix kernel.
mod hooks;
pub use hooks::*;

/// Audit logging to be used from different kernel components.
mod audit;
pub use audit::*;

/// Identifies the subject of an audit record for a permission check.
///
/// M6 does not emit SELinux-style audit records, but the VFS still constructs
/// these values at permission-check call sites, so the type is preserved.
#[derive(Clone, Copy, Debug)]
pub enum Auditable<'a> {
    /// The check concerns a named entry (e.g. a directory entry name).
    Name(&'a FsStr),
    /// The check is attributed to a source-code location.
    Location(&'a core::panic::Location<'static>),
    /// No additional context.
    Unspecified,
}

impl<'a> From<&'a core::panic::Location<'static>> for Auditable<'a> {
    fn from(location: &'a core::panic::Location<'static>) -> Self {
        Auditable::Location(location)
    }
}

impl<'a> From<&'a [Auditable<'a>]> for Auditable<'a> {
    fn from(items: &'a [Auditable<'a>]) -> Self {
        // The permissive layer does not record audit context, so collapse a list
        // of contexts down to the first item (or `Unspecified` when empty).
        items.first().copied().unwrap_or(Auditable::Unspecified)
    }
}

impl<'a, const N: usize> From<&'a [Auditable<'a>; N]> for Auditable<'a> {
    fn from(items: &'a [Auditable<'a>; N]) -> Self {
        Auditable::from(items.as_slice())
    }
}

// The VFS attributes permission checks to a DirEntry / NamespaceNode. The
// permissive layer records no audit context, so these collapse to Unspecified.
impl<'a> From<&'a m6_starnix_std::sync::Arc<crate::vfs::DirEntry>> for Auditable<'a> {
    fn from(_dir_entry: &'a m6_starnix_std::sync::Arc<crate::vfs::DirEntry>) -> Self {
        Auditable::Unspecified
    }
}

impl<'a> From<&'a crate::vfs::NamespaceNode> for Auditable<'a> {
    fn from(_node: &'a crate::vfs::NamespaceNode) -> Self {
        Auditable::Unspecified
    }
}

/// Opaque structure encapsulating security subsystem state for the whole system.
///
/// With no LSM backend this holds no state; it is constructed once per kernel.
#[derive(Default)]
pub struct KernelState;

impl KernelState {
    pub fn access_denial_count(&self) -> u64 {
        0
    }
}

/// Structure holding security state associated with a `ResolvedElf` instance.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolvedElfState;

impl ResolvedElfState {
    pub fn require_secure_exec(&self) -> bool {
        false
    }
}

/// The opaque type used by [`crate::vfs::FsNodeInfo`] to store security state.
#[derive(Debug, Default)]
pub struct FsNodeState(Mutex<()>);

impl FsNodeState {
    pub fn lock(&self) -> starnix_sync::MutexGuard<'_, ()> {
        self.0.lock()
    }
}

/// Opaque structure holding security state for a `binderfs::BinderConnection`.
#[derive(Debug, Default)]
pub struct BinderConnectionState;

/// Opaque structure holding security state for a [`crate::vfs::socket::Socket`].
#[derive(Debug, Default)]
pub struct SocketState;

/// Opaque structure holding security state for a [`crate::vfs::FileObject`].
#[derive(Debug, Default)]
pub struct FileObjectState;

/// Opaque structure holding security state for a [`crate::vfs::FileSystem`].
#[derive(Debug, Default)]
pub struct FileSystemState;

/// Opaque structure holding security state for a bpf map object.
#[derive(Debug, Default)]
pub struct BpfMapState;

/// Opaque structure holding security state for a bpf program object.
#[derive(Debug, Default)]
pub struct BpfProgState;

/// Opaque structure holding security state for a PerfEventFileState.
#[derive(Debug, Default)]
pub struct PerfEventState;
