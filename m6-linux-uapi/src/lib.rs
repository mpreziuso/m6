// Forked from Fuchsia's linux_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2021 The Fuchsia Authors. BSD license.

#![no_std]
// Auto-generated bindgen output — suppress all style/transmute lints
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::all)]

mod types;
pub use types::*;

mod manual;
pub use manual::*;

pub mod macros;

pub mod arm64;
pub use arm64::*;

// ARM 32-bit variant (arch32 on aarch64)
mod arm;
pub mod arch32 {
    pub use crate::arm::*;
}

#[doc(hidden)]
pub use static_assertions as __static_assertions;
