// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::task::{CurrentTask, ThreadState};
use starnix_registers::RegisterStorage;
use starnix_syscalls::SyscallArg;
use starnix_syscalls::decls::{Syscall, SyscallDecl};

pub fn new_syscall_from_state<T: RegisterStorage>(
    syscall_decl: SyscallDecl,
    thread_state: &ThreadState<T>,
) -> Syscall {
    Syscall {
        decl: syscall_decl,
        arg0: SyscallArg::from_raw(thread_state.registers.r[0]),
        arg1: SyscallArg::from_raw(thread_state.registers.r[1]),
        arg2: SyscallArg::from_raw(thread_state.registers.r[2]),
        arg3: SyscallArg::from_raw(thread_state.registers.r[3]),
        arg4: SyscallArg::from_raw(thread_state.registers.r[4]),
        arg5: SyscallArg::from_raw(thread_state.registers.r[5]),
    }
}

pub fn new_syscall(syscall_decl: SyscallDecl, current_task: &CurrentTask) -> Syscall {
    new_syscall_from_state(syscall_decl, &current_task.thread_state)
}
