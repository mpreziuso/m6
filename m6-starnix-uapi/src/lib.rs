// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

extern crate alloc;

pub mod arc_key;
pub mod as_any;
pub mod auth;
pub mod device_type;
pub mod elf;
pub mod errors;
pub mod file_lease;
pub mod file_mode;
pub mod inotify_mask;
pub mod iptables_flags;
pub mod kcmp;
pub mod math;
pub mod mount_flags;
pub mod open_flags;
pub mod personality;
pub mod range_ext;
pub mod resource_limits;
pub mod restricted_aspace;
pub mod seal_flags;
pub mod selinux;
pub mod signals;
pub mod syslog;
pub mod uapi;
pub mod union;
pub mod unmount_flags;
pub mod user_address;
pub mod user_value;
pub mod version;
pub mod vfs;

pub mod arm;
pub mod arm64;

pub use arm64::*;

pub mod arch32 {
    pub use super::arm::*;
    pub use super::uapi::arch32::*;
}

pub use uapi::*;

// M6: upstream re-exports the `zx_status` crate here as `__zx_status` for use by the
// `from_status_like_fdio!` macro. We back it with the M6 Zircon shim instead.
#[doc(hidden)]
pub use m6_zx_shim as __zx_status;
