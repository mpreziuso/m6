//! M6 Syscall ABI
//!
//! Shared definitions for kernel-userspace communication.
//! This crate is `no_std` and has no dependencies, allowing it to be used
//! in both the kernel and userspace.
//!
//! # Modules
//!
//! - [`numbers`] - Syscall numbers
//! - [`error`] - Error codes
//! - [`invoke`] - Userspace syscall invocation (feature-gated)
//! - [`boot_info`] - Boot information passed from kernel to init

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod boot_info;
pub mod error;
#[cfg(feature = "userspace")]
pub mod invoke;
pub mod numbers;

// Re-export commonly used items
pub use boot_info::{
    CapSlot, UserBootInfo, USER_BOOT_INFO_ADDR, USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION,
};
pub use error::SyscallError;
pub use numbers::Syscall;
