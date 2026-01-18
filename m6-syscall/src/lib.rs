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
//! - [`ipc_buffer`] - IPC buffer for extended syscall arguments
//! - [`cptr`] - CPtr formatting utilities

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod boot_info;
pub mod cptr;
pub mod error;
#[cfg(feature = "userspace")]
pub mod invoke;
pub mod ipc_buffer;
pub mod numbers;

// Re-export commonly used items
pub use boot_info::{
    USER_BOOT_INFO_ADDR, USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION, UserBootInfo,
};
pub use cptr::{CptrContext, cptr_to_slot, slot_to_cptr};
pub use error::SyscallError;
#[cfg(feature = "userspace")]
pub use invoke::IpcRecvResult;
pub use ipc_buffer::{IPC_BUFFER_ADDR, IPC_BUFFER_SIZE, IpcBuffer, MintArgs};
pub use m6_cap::root_slots;
pub use numbers::Syscall;
