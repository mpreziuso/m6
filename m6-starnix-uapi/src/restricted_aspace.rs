// Copyright 2024 The Fuchsia Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// From //zircon/kernel/arch/x86/include/arch/kernel_aspace.h
#[cfg(target_arch = "x86_64")]
const USER_ASPACE_BASE: usize = 0x0000000000200000;
#[cfg(target_arch = "x86_64")]
const USER_RESTRICTED_ASPACE_SIZE: usize = (1 << 46) - USER_ASPACE_BASE;

// From //zircon/kernel/arch/arm64/include/arch/kernel_aspace.h
#[cfg(target_arch = "aarch64")]
const USER_ASPACE_BASE: usize = 0x0000000000200000;
// M6 bring-up: cap the restricted aspace at 2 GiB instead of Zircon's 1<<47.
// M6's restricted-mode page-table walk is currently exercised only at LOW
// addresses (the native loader's stack was at ~0x7fff_f000 = L1 index 1, which
// works); high L0/L1 indices fail in `map_frame`. A 2 GiB top places the Linux
// stack at L1 index 1 — the exact native-proven configuration — and is ample
// for first light. Raising this needs the kernel's high-index mapping path
// validated first.
#[cfg(target_arch = "aarch64")]
const USER_RESTRICTED_ASPACE_SIZE: usize = (1 << 31) - USER_ASPACE_BASE;

// From //zircon/kernel/arch/riscv64/include/arch/kernel_aspace.h
#[cfg(target_arch = "riscv64")]
const USER_ASPACE_BASE: usize = 0x0000000000200000;
#[cfg(target_arch = "riscv64")]
const USER_RESTRICTED_ASPACE_SIZE: usize = (1 << 37) - USER_ASPACE_BASE;

// From //zircon/kernel/object/process_dispatcher.cc
pub const RESTRICTED_ASPACE_BASE: usize = USER_ASPACE_BASE;
pub const RESTRICTED_ASPACE_SIZE: usize = USER_RESTRICTED_ASPACE_SIZE;
pub const RESTRICTED_ASPACE_HIGHEST_ADDRESS: usize =
    RESTRICTED_ASPACE_BASE + RESTRICTED_ASPACE_SIZE;

pub const RESTRICTED_ASPACE_RANGE: core::ops::Range<usize> =
    RESTRICTED_ASPACE_BASE..RESTRICTED_ASPACE_HIGHEST_ADDRESS;
