//! Platform Abstraction Layer
//!
//! Provides hardware abstraction for different platforms:
//! - QEMU virt machine (development)
//! - other platforms to be added in the future (Rasp Pi?)
//!
//! All platform-specific code is behind trait interfaces.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod platform;
pub mod dtb;
pub mod dtb_platform;
pub mod console;
pub mod boot_uart;
pub mod timer;
pub mod gic;
pub mod psci;

pub use platform::{Platform, PlatformInfo, current_platform};
pub use dtb::get_parsed_dtb;
pub use dtb_platform::{GicVersion, UartType};
