//! M6 Standard Library
//!
//! A custom standard library for M6 microkernel userspace programs.
//! Mirrors Rust's std API where possible for familiarity.
//!
//! # Usage
//!
//! In your crate root, alias m6-std as `std`:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! extern crate m6_std as std;
//!
//! use std::println;
//!
//! #[no_mangle]
//! fn main() -> i32 {
//!     println!("Hello from M6!");
//!     0
//! }
//! ```
//!
//! # Modules
//!
//! - [`sync`]: Synchronisation primitives (Mutex, RwLock, Condvar, Once)
//! - [`thread`]: Thread spawning and management
//! - [`io`]: I/O traits (Read, Write, Seek)
//! - [`time`]: Time measurement (Instant, Duration)
//! - [`ipc`]: IPC abstractions (channels, endpoints, notifications)
//! - [`process`]: Process management (exit, abort)
//! - [`cap`]: Capability wrappers
//!
//! # Re-exports
//!
//! Common types are re-exported at the crate root:
//! - `Vec`, `Box`, `String` from alloc
//! - `println!`, `print!`, `eprintln!`, `eprint!` macros

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(linkage)]

// Re-export alloc crate
#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export core as a public module (like std does)
pub use core;

// Also expose core's primitive re-exports
pub use core::clone;
pub use core::cmp;
pub use core::convert;
pub use core::default;
pub use core::fmt;
pub use core::hash;
pub use core::iter;
pub use core::marker;
pub use core::mem;
pub use core::ops;
pub use core::option;
pub use core::ptr;
pub use core::result;
pub use core::slice;
pub use core::str;

// Runtime module (always included)
pub mod rt;

// Feature-gated modules
#[cfg(feature = "alloc")]
pub mod alloc_impl;

#[cfg(feature = "alloc")]
pub mod collections {
    //! Collection types.
    pub use alloc::collections::*;
}

#[cfg(feature = "io")]
pub mod io;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "process")]
pub mod process;

#[cfg(feature = "time")]
pub mod time;

#[cfg(feature = "thread")]
pub mod thread;

#[cfg(feature = "cap")]
pub mod cap;

#[cfg(feature = "ipc")]
pub mod ipc;

// Prelude for common imports
pub mod prelude;

// Re-export common types from alloc crate at the root (like std does)
#[cfg(feature = "alloc")]
pub use alloc::borrow;
#[cfg(feature = "alloc")]
pub use alloc::boxed;
#[cfg(feature = "alloc")]
pub use alloc::rc;
#[cfg(feature = "alloc")]
pub use alloc::string;
#[cfg(feature = "alloc")]
pub use alloc::vec;

// Convenience re-exports at root level
#[cfg(feature = "alloc")]
pub use alloc::boxed::Box;
#[cfg(feature = "alloc")]
pub use alloc::format;
#[cfg(feature = "alloc")]
pub use alloc::string::String;
#[cfg(feature = "alloc")]
pub use alloc::string::ToString;
#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;

// Print macros
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::io::stdout(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::io::stdout(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::io::stderr(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::eprint!("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::io::stderr(), $($arg)*);
    }};
}

/// Debug assertion macro (like std::debug_assert!).
#[macro_export]
macro_rules! dbg {
    () => {
        $crate::eprintln!("[{}:{}]", file!(), line!())
    };
    ($val:expr $(,)?) => {
        match $val {
            tmp => {
                $crate::eprintln!("[{}:{}] {} = {:?}", file!(), line!(), stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
