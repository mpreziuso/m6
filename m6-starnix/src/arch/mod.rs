// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
pub mod execution;
pub mod signal_handling;
pub mod syscalls;
pub mod task;
pub mod vdso;

pub const ARCH_NAME: &'static [u8] = b"aarch64";
