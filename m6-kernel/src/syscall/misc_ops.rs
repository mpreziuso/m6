//! Miscellaneous syscall operations
//!
//! Handles syscalls that don't fit into other categories.

use crate::syscall::SyscallArgs;
use crate::syscall::error::{SyscallError, SyscallResult};

/// Maximum buffer size for GetRandom
const MAX_RANDOM_BYTES: usize = 256;

/// User space address limit (below TTBR1 region)
const USER_SPACE_MAX: usize = 0x0000_FFFF_FFFF_FFFF;

/// Handle GetRandom syscall.
///
/// Fills a userspace buffer with cryptographically random bytes.
///
/// # Arguments
///
/// * x0: buffer address (userspace pointer)
/// * x1: buffer length in bytes (max 256)
///
/// # Returns
///
/// Number of bytes written on success.
pub fn handle_get_random(args: &SyscallArgs) -> SyscallResult {
    let buf_addr = args.arg0 as usize;
    let buf_len = args.arg1 as usize;

    // Validate length
    if buf_len == 0 {
        return Ok(0);
    }
    if buf_len > MAX_RANDOM_BYTES {
        return Err(SyscallError::InvalidArg);
    }

    // Validate userspace buffer address
    if buf_addr == 0 {
        return Err(SyscallError::Range);
    }
    if buf_addr > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }
    if buf_addr.saturating_add(buf_len) > USER_SPACE_MAX {
        return Err(SyscallError::Range);
    }

    // Probe every page in [buf_addr, buf_addr+buf_len) with AT S1E0W before
    // writing. An unmapped or non-writable page would otherwise cause a data
    // abort at EL1 and panic the kernel.
    let first_page = buf_addr & !0xFFF;
    let last_page = (buf_addr + buf_len - 1) & !0xFFF;
    let mut page = first_page;
    while page <= last_page {
        if !probe_user_write(page as u64) {
            return Err(SyscallError::InvalidArg);
        }
        page = page.wrapping_add(0x1000);
    }

    // Generate random bytes
    let mut random_buf = [0u8; MAX_RANDOM_BYTES];
    fill_random(&mut random_buf[..buf_len]);

    // Copy to userspace
    // SAFETY: All pages in [buf_addr, buf_addr+buf_len) were verified mapped
    // and writable by AT S1E0W above.
    unsafe {
        let user_ptr = buf_addr as *mut u8;
        core::ptr::copy_nonoverlapping(random_buf.as_ptr(), user_ptr, buf_len);
    }

    Ok(buf_len as i64)
}

/// Probe a single user-space page for write accessibility from EL1.
///
/// Issues `AT S1E0W` which asks the hardware MMU to perform a stage-1
/// EL0-write translation of `vaddr`. PAR_EL1 bit 0 (F) is set when the
/// translation faulted. An ISB is required after AT to ensure PAR_EL1 is
/// updated before reading it.
#[inline]
fn probe_user_write(vaddr: u64) -> bool {
    let par: u64;
    // SAFETY: AT S1E0W and MRS are read-only system instructions that
    // cannot cause faults or affect memory.
    unsafe {
        core::arch::asm!(
            "at s1e0w, {addr}",
            "isb",
            "mrs {par}, par_el1",
            addr = in(reg) vaddr,
            par = out(reg) par,
            options(nostack, preserves_flags),
        );
    }
    // PAR_EL1.F (bit 0) = 0 means the translation succeeded.
    par & 1 == 0
}

/// Fill buffer with random bytes.
///
/// Uses ARMv8.5 RNDR instruction if available, with fallback to
/// timer-based entropy mixing.
fn fill_random(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let random_val = read_random_u64();
        let bytes = random_val.to_le_bytes();
        let copy_len = chunk.len().min(8);
        chunk.copy_from_slice(&bytes[..copy_len]);
    }
}

/// Read a random 64-bit value.
///
/// Tries RNDR first (ARMv8.5-RNG), falls back to timer-based entropy.
fn read_random_u64() -> u64 {
    // Try hardware RNG first
    if let Some(val) = m6_arch::cpu::read_random() {
        return val;
    }

    // Fallback to timer-based entropy
    fallback_entropy()
}

/// Generate entropy from timer counter.
///
/// This is a fallback when RNDR is not available. It provides
/// some entropy but should not be used for high-security purposes.
fn fallback_entropy() -> u64 {
    // Read generic timer counter
    let cntpct: u64;
    // SAFETY: Reading CNTPCT_EL0 is safe.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntpct_el0",
            out(reg) cntpct,
            options(nomem, nostack)
        );
    }

    // Mix with SplitMix64
    let mut z = cntpct;
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
