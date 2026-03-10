//! User pointer validation
//!
//! Provides safe probing of user-space virtual addresses before the kernel
//! dereferences them. Without probing, an unmapped address triggers a data
//! abort at EL1 and panics the kernel.
//!
//! The probes use `AT S1E0R` / `AT S1E0W` (Address Translate Stage 1, EL0
//! Read/Write) to ask the MMU whether the translation succeeds. The result
//! lands in PAR_EL1; bit 0 (F) indicates a fault.

use super::error::SyscallError;

/// Probe a single user-space page for read accessibility from EL1.
///
/// Issues `AT S1E0R` which performs a stage-1 EL0-read translation of
/// `vaddr`. An ISB ensures PAR_EL1 is updated before we read it.
#[inline]
pub fn probe_user_read(vaddr: u64) -> bool {
    let par: u64;
    // SAFETY: AT S1E0R and MRS are read-only system instructions. They
    // cannot cause faults themselves and do not affect memory.
    unsafe {
        core::arch::asm!(
            "at s1e0r, {addr}",
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

/// Probe a single user-space page for write accessibility from EL1.
///
/// Issues `AT S1E0W` which performs a stage-1 EL0-write translation of
/// `vaddr`. PAR_EL1 bit 0 (F) is set when the translation faulted.
#[inline]
pub fn probe_user_write(vaddr: u64) -> bool {
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

/// Probe all pages spanned by a user buffer for read accessibility.
///
/// Returns `Ok(())` if every page in `[addr, addr+len)` is readable at
/// EL0, or `Err(SyscallError::InvalidArg)` on the first unmapped /
/// non-readable page.
pub fn probe_user_buffer_read(addr: u64, len: usize) -> Result<(), SyscallError> {
    if len == 0 {
        return Ok(());
    }
    let first_page = addr & !0xFFF;
    let last_page = (addr + len as u64 - 1) & !0xFFF;
    let mut page = first_page;
    while page <= last_page {
        if !probe_user_read(page) {
            return Err(SyscallError::InvalidArg);
        }
        page = page.wrapping_add(0x1000);
    }
    Ok(())
}

/// Probe all pages spanned by a user buffer for write accessibility.
///
/// Returns `Ok(())` if every page in `[addr, addr+len)` is writable at
/// EL0, or `Err(SyscallError::InvalidArg)` on the first unmapped /
/// non-writable page.
pub fn probe_user_buffer_write(addr: u64, len: usize) -> Result<(), SyscallError> {
    if len == 0 {
        return Ok(());
    }
    let first_page = addr & !0xFFF;
    let last_page = (addr + len as u64 - 1) & !0xFFF;
    let mut page = first_page;
    while page <= last_page {
        if !probe_user_write(page) {
            return Err(SyscallError::InvalidArg);
        }
        page = page.wrapping_add(0x1000);
    }
    Ok(())
}
