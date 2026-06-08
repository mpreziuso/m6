// Copyright 2024 The Fuchsia Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A FutexAddress is a more limited form of UserAddress. FutexAddress values must be aligned
// to a 4 byte boundary and must be within the restricted address space range.

use crate::zx_time::sys::zx_vaddr_t;
use core::fmt;
use core::ops::Range;
use starnix_uapi::errors::{Errno, error};
use starnix_uapi::user_address::UserAddress;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// M6: `starnix_uapi::restricted_aspace` does not yet exist in m6-starnix-uapi
// (it is owned by a concurrently-evolving crate). We mirror the upstream aarch64
// constants locally so this module is self-contained; switch to
// `starnix_uapi::restricted_aspace::RESTRICTED_ASPACE_RANGE` once it lands.
const USER_ASPACE_BASE: usize = 0x0000_0000_0020_0000;
const RESTRICTED_ASPACE_BASE: usize = USER_ASPACE_BASE;
const RESTRICTED_ASPACE_SIZE: usize = (1 << 47) - USER_ASPACE_BASE;
const RESTRICTED_ASPACE_HIGHEST_ADDRESS: usize = RESTRICTED_ASPACE_BASE + RESTRICTED_ASPACE_SIZE;
const RESTRICTED_ASPACE_RANGE: Range<usize> =
    RESTRICTED_ASPACE_BASE..RESTRICTED_ASPACE_HIGHEST_ADDRESS;

#[derive(
    Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, IntoBytes, KnownLayout, FromBytes, Immutable,
)]
#[repr(transparent)]
pub struct FutexAddress(zx_vaddr_t);

impl FutexAddress {
    pub fn ptr(&self) -> zx_vaddr_t {
        self.0
    }
}

impl TryFrom<usize> for FutexAddress {
    type Error = Errno;

    fn try_from(value: usize) -> Result<Self, Errno> {
        // Futex addresses must be aligned to a 4 byte boundary.
        if value % 4 != 0 {
            return error!(EINVAL);
        }
        // Futex addresses cannot be outside of the restricted address space range.
        if !RESTRICTED_ASPACE_RANGE.contains(&value) {
            return error!(EFAULT);
        }
        Ok(FutexAddress(value))
    }
}

impl TryFrom<UserAddress> for FutexAddress {
    type Error = Errno;

    fn try_from(value: UserAddress) -> Result<Self, Errno> {
        value.ptr().try_into()
    }
}

impl From<FutexAddress> for UserAddress {
    fn from(value: FutexAddress) -> UserAddress {
        UserAddress::const_from(value.ptr() as u64)
    }
}

impl fmt::Display for FutexAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Debug for FutexAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FutexAddress").field(&format_args!("{:#x}", self.0)).finish()
    }
}
