//! # m6-common
//!
//! Shared types and constants for the M6 bootloader and kernel.
//!
//! This crate defines the ABI between bootloader and kernel:
//! - [`BootInfo`](boot::BootInfo): Boot handoff structure passed from bootloader to kernel
//! - [`MemoryMap`](memory::MemoryMap): Physical memory layout from UEFI
//! - [`FramebufferInfo`](boot::FramebufferInfo): Graphics framebuffer for early console
//!
//! All types use `#[repr(C)]` for stable ABI across compilation units.
//!
//! # no_std
//!
//! This crate is `#![no_std]` and has zero dependencies, making it suitable
//! as a foundation crate that all other M6 crates can depend on.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod addr;
pub mod boot;
pub mod memory;

// Re-export commonly used types
pub use addr::{PhysAddr, VirtAddr};