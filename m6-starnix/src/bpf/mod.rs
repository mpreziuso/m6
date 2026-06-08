// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Minimal eBPF surface for the M6 Starnix fork.
//!
//! The upstream `bpf` subsystem (maps, programs, verifier, attachments) was not
//! forked. This module provides only the syscall entry point, which returns
//! `ENOSYS`, so the syscall dispatch table links. eBPF support is out of scope
//! for the initial static-binary bring-up target.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;

pub mod syscalls {
    #[allow(unused_imports)] use m6_starnix_std::prelude::*;
    use crate::task::CurrentTask;
    use starnix_sync::{Locked, Unlocked};
    use starnix_syscalls::SyscallResult;
    use starnix_uapi::errors::Errno;
    use starnix_uapi::error;
    use starnix_uapi::user_address::UserAddress;
    use linux_uapi::bpf_cmd;

    /// The `bpf(2)` syscall. M6 stub: eBPF is not implemented.
    pub fn sys_bpf(
        _locked: &mut Locked<Unlocked>,
        _current_task: &CurrentTask,
        _cmd: bpf_cmd,
        _attr_addr: UserAddress,
        _attr_size: u32,
    ) -> Result<SyscallResult, Errno> {
        error!(ENOSYS)
    }

    #[cfg(target_arch = "aarch64")]
    pub use sys_bpf as sys_arch32_bpf;
}
