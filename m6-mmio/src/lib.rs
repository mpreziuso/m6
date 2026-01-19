//! MMIO Abstraction Layer for M6 Device Drivers
//!
//! This crate provides reusable building blocks for userspace device drivers
//! in the M6 microkernel operating system.
//!
//! # Modules
//!
//! - [`region`]: Type-safe MMIO region access with offset-based reads/writes
//! - [`barrier`]: Memory barrier helpers for device memory ordering
//! - [`queue`]: Generic submission/completion queue engine with phase bit handling
//!
//! # Example
//!
//! ```ignore
//! use m6_mmio::{MmioRegion, barrier};
//!
//! // Create MMIO region for device at address 0x1000_0000
//! let mmio = unsafe { MmioRegion::new(0x1000_0000, 0x1000) };
//!
//! // Read device registers
//! let status = mmio.read32(0x00);
//! let config = mmio.read64(0x08);
//!
//! // Write with barrier
//! mmio.write32(0x10, 0x1234);
//! barrier::write_barrier();
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod barrier;
pub mod queue;
pub mod region;

// Re-exports for convenience
pub use barrier::{dsb, isb, read_barrier, write_barrier};
pub use queue::{CompletionQueue, QueueEntry, SubmissionQueue};
pub use region::MmioRegion;
