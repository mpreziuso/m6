// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

#![allow(non_camel_case_types)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, IntoBytes, KnownLayout, FromBytes, Immutable)]
pub struct user_regs_struct {
    pub regs: [u64; 31usize],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Default, Copy, Clone, IntoBytes, KnownLayout, FromBytes, Immutable)]
pub struct user_fpsimd_struct {
    pub vregs: [u128; 32usize],
    pub fpsr: u32,
    pub fpcr: u32,
    pub _padding_0: [u8; 8usize],
}
