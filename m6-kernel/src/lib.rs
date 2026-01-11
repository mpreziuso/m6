//! # m6-kernel
//!
//! The M6 microkernel for ARM64.
//!
//! This is a minimal kernel that receives control from the bootloader
//! and provides basic system services.
//!
//! # Boot Requirements
//!
//! The kernel expects the following state when `_start` is called:
//! - MMU enabled with TTBR1 pointing to kernel page tables
//! - Stack pointer set to kernel stack (high-half virtual address)
//! - `x0` containing physical address of [`BootInfo`](m6_common::boot::BootInfo)
//! - Interrupts disabled (DAIF masked)
//!
//! # Memory Layout
//!
//! The kernel is linked at `KERNEL_VIRT_BASE` (0xFFFF_FFFF_8000_0000):
//! - `.text`: Executable code
//! - `.vectors`: Exception vector table (2KB aligned)
//! - `.rodata`: Read-only data
//! - `.data`: Initialised read-write data
//! - `.bss`: Zero-initialised data
//! - `.stack`: Kernel stack (64KB)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#![feature(alloc_error_handler)]

pub mod cap;
pub mod initrd;
pub mod ipc;
pub mod irq;
pub mod logging;
pub mod memory;
pub mod sched;
pub mod smp;
pub mod smmu;
pub mod syscall;
pub mod task;
pub mod user;