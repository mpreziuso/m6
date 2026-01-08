//! # m6-arch
//!
//! ARM64 architecture support for the M6 kernel.
//!
//! Provides low-level CPU and MMU operations:
//! - [`cpu`]: CPU control (halt, interrupts, feature detection)
//! - [`mmu`]: MMU configuration and TLB management
//! - [`cache`]: Data and instruction cache operations
//! - [`exceptions`]: Exception vector table and handlers
//! - [`registers`]: System register access (VBAR, TPIDR, ESR, etc.)
//!
//! # Safety
//!
//! This crate contains extensive `unsafe` code for hardware access.
//! All unsafe operations are documented with `// SAFETY:` comments
//! explaining the invariants that must be maintained.
//!
//! # Example
//!
//! ```ignore
//! use m6_arch::{halt, wait_for_interrupt};
//!
//! // Wait for an interrupt, then halt
//! wait_for_interrupt();
//! halt();
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod cache;
pub mod cpu;
pub mod exceptions;
pub mod mmu;
pub mod registers;
pub mod sync;

pub use cpu::{halt, wait_for_interrupt};
pub use mmu::Mmu;
pub use sync::IrqSpinMutex;
