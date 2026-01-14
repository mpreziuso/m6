//! The M6 prelude
//!
//! This module contains the most commonly used items from m6-std.
//! Import with `use m6_std::prelude::*;`

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
