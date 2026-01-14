//! The M6 prelude
//!
//! This module contains the most commonly used items from m6-std.
//! Rust automatically imports `std::prelude::rust_2024::*` for edition 2024.

// Edition-agnostic prelude
pub mod v1 {
    // Re-export from core
    pub use core::cmp::{Eq, Ord, PartialEq, PartialOrd};
    pub use core::convert::{AsMut, AsRef, From, Into, TryFrom, TryInto};
    pub use core::default::Default;
    pub use core::iter::{DoubleEndedIterator, ExactSizeIterator, Extend, IntoIterator, Iterator};
    pub use core::marker::{Copy, Send, Sized, Sync, Unpin};
    pub use core::mem::drop;
    pub use core::ops::{Drop, Fn, FnMut, FnOnce};
    pub use core::option::Option::{self, None, Some};
    pub use core::result::Result::{self, Err, Ok};
    pub use core::clone::Clone;
    pub use core::fmt::Debug;

    // Re-export from alloc when enabled
    #[cfg(feature = "alloc")]
    pub use alloc::borrow::ToOwned;
    #[cfg(feature = "alloc")]
    pub use alloc::boxed::Box;
    #[cfg(feature = "alloc")]
    pub use alloc::string::{String, ToString};
    #[cfg(feature = "alloc")]
    pub use alloc::vec::Vec;

    // Re-export I/O traits when enabled
    #[cfg(feature = "io")]
    pub use crate::io::{Read, Write};

    // Re-export print macros
    pub use crate::{print, println, eprint, eprintln};
}

// Edition-specific preludes (all re-export v1 for now)
pub mod rust_2015 {
    pub use super::v1::*;
}

pub mod rust_2018 {
    pub use super::v1::*;
}

pub mod rust_2021 {
    pub use super::v1::*;
}

pub mod rust_2024 {
    pub use super::v1::*;
}

// For `use std::prelude::*;`
pub use v1::*;
