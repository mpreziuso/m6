//! std compatibility shim for Starnix
//!
//! Provides a `std`-like API surface built on `core` and `alloc` for use in
//! `no_std` environments. Starnix code uses `use std::...` throughout — by
//! aliasing this crate as `std`, the forked code compiles without
//! modification.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod borrow {
    pub use alloc::borrow::*;
}

pub mod boxed {
    pub use alloc::boxed::*;
}

pub mod cell {
    pub use core::cell::*;
}

pub mod clone {
    pub use core::clone::*;
}

pub mod cmp {
    pub use core::cmp::*;
}

pub mod collections;

pub mod convert {
    pub use core::convert::*;
}

pub mod default {
    pub use core::default::*;
}

pub mod ffi;

pub mod fmt {
    pub use alloc::fmt::*;
    pub use core::fmt::*;
}

pub mod future {
    pub use core::future::*;
}

pub mod hash {
    pub use core::hash::*;
}

pub mod io;

pub mod iter {
    pub use core::iter::*;
}

pub mod marker {
    pub use core::marker::*;
}

pub mod mem {
    pub use core::mem::*;
}

pub mod net;

pub mod num {
    pub use core::num::*;
}

pub mod ops {
    pub use core::ops::*;
}

pub mod option {
    pub use core::option::*;
}

pub mod path;

pub mod pin {
    pub use core::pin::*;
}

pub mod ptr {
    pub use core::ptr::*;
}

pub mod rc {
    pub use alloc::rc::*;
}

pub mod result {
    pub use core::result::*;
}

pub mod slice {
    pub use core::slice::*;
}

pub mod str {
    pub use alloc::str::*;
    pub use core::str::*;
}

pub mod string {
    pub use alloc::string::*;
}

pub mod sync;

pub mod task {
    pub use core::task::*;
}

pub mod thread;

pub mod time;

pub mod vec {
    pub use alloc::vec::*;
}

// Re-exports at root level (matching std)
pub use alloc::boxed::Box;
pub use alloc::format;
pub use alloc::string::String;
pub use alloc::string::ToString;
pub use alloc::vec::Vec;

// `panic` module (for `panic::Location`) and the diagnostic macros the std
// prelude provides at the crate root. The fork's fully-qualified `std::…`
// paths are rewritten to `m6_starnix_std::…`, so these must resolve here too.
pub use core::panic;
pub use core::{todo, unimplemented, unreachable};

/// Prelude of the alloc-specific items that the std prelude provides but the
/// `core` prelude (the only one auto-imported under `#![no_std]`) does not.
/// The fork script injects `use m6_starnix_std::prelude::*;` into every forked
/// file so upstream code using bare `Box`/`Vec`/`String`/`format!`/`vec!`
/// compiles unchanged. Glob import => no conflict with files that also import
/// these explicitly.
pub mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::{format, vec};
    // -- `thread_local!` is part of the std prelude upstream; re-export the
    //    crate-root macro so forked code's bare `thread_local! { … }` resolves.
    pub use crate::thread_local;
}
