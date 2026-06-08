// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2025 The Fuchsia Authors. BSD license.
//
// M6 adaptation: upstream `clean_stack()` scrubs used stack pages via the
// Fuchsia VMAR `op_range(ZERO, ..)` operation, which has no M6 equivalent yet.
// It is a defence-in-depth hardening measure (zeroing stack residue), not a
// correctness requirement. We keep the public API and make it a no-op until an
// M6 "zero a VA range" primitive is available.

#![no_std]

/// Scrub recently-used stack memory.
///
/// TODO(m6): implement once M6 exposes a VSpace range-zero / decommit op.
/// Upstream zeroes ~1 MiB below the current stack pointer (safe + unsafe stacks)
/// to avoid leaking secrets left on the stack across syscalls.
#[inline]
pub fn clean_stack() {
    // no-op
}
