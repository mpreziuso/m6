// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

use super::errors::{Errno, errno};

pub fn round_up_to_increment<N, M>(size: N, increment: M) -> Result<N, Errno>
where
    N: TryInto<u64>,
    N: TryFrom<u64>,
    M: TryInto<u64>,
{
    let size: u64 = size.try_into().map_err(|_| errno!(EINVAL))?;
    let increment: u64 = increment.try_into().map_err(|_| errno!(EINVAL))?;
    let spare = size % increment;
    let result = if spare > 0 {
        size.checked_add(increment - spare)
            .ok_or_else(|| errno!(EINVAL))?
    } else {
        size
    };
    N::try_from(result).map_err(|_| errno!(EINVAL))
}

pub fn round_down_to_increment<N, M>(size: N, increment: M) -> Result<N, Errno>
where
    N: TryInto<u64>,
    N: TryFrom<u64>,
    M: TryInto<u64>,
{
    let size: u64 = size.try_into().map_err(|_| errno!(EINVAL))?;
    let increment: u64 = increment.try_into().map_err(|_| errno!(EINVAL))?;
    let result = size - (size % increment);
    N::try_from(result).map_err(|_| errno!(EINVAL))
}
