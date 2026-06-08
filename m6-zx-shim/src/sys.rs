//! Low-level Zircon `sys` definitions
//!
#![allow(non_camel_case_types)]
//!
//! Mirrors the raw FFI surface (`zx::sys::*`) that forked Starnix code uses:
//! handle/time aliases, status constants, the restricted-mode register frame,
//! and a handful of raw syscall wrappers. These are not yet wired to M6
//! syscalls — the wrappers are stubs that return plausible status codes so the
//! fork links; they are documented as placeholders.

// -- Primitive aliases

/// A raw Zircon handle value.
pub type zx_handle_t = u32;
/// A timestamp in nanoseconds.
pub type zx_time_t = i64;
/// A duration in nanoseconds.
pub type zx_duration_t = i64;
/// A status code.
pub type zx_status_t = i32;
/// An exception type discriminator.
pub type zx_excp_type_t = u32;
/// A virtual address.
pub type zx_vaddr_t = usize;

/// CPSR bit selecting AArch32 (32-bit) execution state in restricted mode.
pub const ZX_REG_CPSR_ARCH_32_MASK: u64 = 0x10;
/// CPSR Thumb-mode bit.
pub const ZX_REG_CPSR_THUMB_MASK: u64 = 0x20;

/// The sentinel for an invalid handle.
pub const ZX_HANDLE_INVALID: zx_handle_t = 0;

// -- Status constants (subset referenced by the fork)

pub const ZX_OK: zx_status_t = 0;
pub const ZX_ERR_INTERNAL: zx_status_t = -1;
pub const ZX_ERR_NOT_SUPPORTED: zx_status_t = -2;
pub const ZX_ERR_NO_MEMORY: zx_status_t = -4;
pub const ZX_ERR_INVALID_ARGS: zx_status_t = -10;
pub const ZX_ERR_BAD_HANDLE: zx_status_t = -11;
pub const ZX_ERR_BAD_STATE: zx_status_t = -20;
pub const ZX_ERR_TIMED_OUT: zx_status_t = -21;
pub const ZX_ERR_SHOULD_WAIT: zx_status_t = -22;
pub const ZX_ERR_ACCESS_DENIED: zx_status_t = -30;

// -- Cache flush flags

pub const ZX_CACHE_FLUSH_DATA: u32 = 1 << 0;
pub const ZX_CACHE_FLUSH_INVALIDATE: u32 = 1 << 1;
pub const ZX_CACHE_FLUSH_INSN: u32 = 1 << 2;

// -- Exception codes

/// User exception code indicating a process name change.
pub const ZX_EXCP_USER_CODE_PROCESS_NAME_CHANGED: u32 = 0x0002;

// -- Clock rate

/// A ratio between synthetic and reference clock ticks.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_clock_rate_t {
    pub synthetic_ticks: u32,
    pub reference_ticks: u32,
}

// -- Pager page request command

/// The command of a pager page request.
#[repr(u32)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub enum zx_page_request_command_t {
    #[default]
    ZX_PAGER_VMO_READ = 0x0000,
    ZX_PAGER_VMO_COMPLETE = 0x0001,
    ZX_PAGER_VMO_DIRTY = 0x0002,
}

// -- I/O vector

/// A scatter/gather buffer descriptor.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct zx_iovec_t {
    pub buffer: *const u8,
    pub capacity: usize,
}

// -- Restricted-mode register frame (aarch64)
//
// Layout matches the upstream Zircon `zx_restricted_state_t` for aarch64: the
// 31 general registers (r[30] is `lr`), the stack and program counters, the
// per-thread pointer, and the user-controllable condition flags.

/// The restricted-mode register state for an aarch64 thread.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct zx_restricted_state_t {
    /// General-purpose registers x0..x30 (x30 = link register).
    pub r: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Thread pointer (TPIDR_EL0).
    pub tpidr_el0: u64,
    /// Condition flags; only the upper NZCV bits are user-controllable.
    pub cpsr: u32,
    /// Reserved padding to match the C struct size.
    padding1: [u8; 4],
}

// -- Raw syscall wrappers (placeholders — not yet wired to M6)

/// Draws random bytes into `buffer`.
///
/// Backed by the M6 kernel RNG (`GetRandom` self-invocation — ARMv8.5 RNDR when
/// available, timer-mixed entropy otherwise). The kernel caps each call at 256
/// bytes, so we fill in chunks. If a syscall ever fails (e.g. a transiently
/// unmapped page), the remaining bytes are zeroed so the buffer is always fully
/// initialised — callers (musl `getrandom`, ASLR seeding) treat this as their
/// sole entropy source.
///
/// # Safety
///
/// `buffer` must be valid to write `len` bytes to.
pub unsafe fn zx_cprng_draw(buffer: *mut u8, len: usize) {
    // SAFETY: The caller guarantees `buffer` is writable for `len` bytes, so the
    // whole slice is a valid mutable region for the lifetime of this call.
    let buf = unsafe { core::slice::from_raw_parts_mut(buffer, len) };
    for chunk in buf.chunks_mut(256) {
        if m6_syscall::invoke::get_random(chunk).is_err() {
            chunk.fill(0);
        }
    }
}

/// Flushes the data and/or instruction caches over a range.
///
/// Placeholder: returns `ZX_OK` without performing any cache maintenance.
///
/// # Safety
///
/// `addr` must point to a readable range of `len` bytes.
pub unsafe fn zx_cache_flush(_addr: *const u8, _len: usize, _flags: u32) -> zx_status_t {
    ZX_OK
}

/// Issues a system-wide barrier of the given type.
///
/// Placeholder: returns `ZX_OK`.
///
/// # Safety
///
/// Always sound to call; `unsafe` only to mirror the upstream FFI signature.
pub unsafe fn zx_system_barrier(_options: u32) -> zx_status_t {
    ZX_OK
}

/// Kicks a thread out of restricted mode.
///
/// Placeholder: returns `ZX_ERR_BAD_STATE`, matching the documented behaviour
/// for a thread that is not currently in restricted mode.
///
/// # Safety
///
/// `thread` must be a valid handle; mirrors the upstream FFI signature.
pub unsafe fn zx_restricted_kick(_thread: zx_handle_t, _options: u32) -> zx_status_t {
    ZX_ERR_BAD_STATE
}

/// Yields the current thread's remaining time slice.
///
/// Placeholder: returns `ZX_OK` without rescheduling. M6 cooperative yield is
/// not yet wired here.
///
/// # Safety
///
/// Always sound to call; `unsafe` only to mirror the upstream FFI signature.
pub unsafe fn zx_thread_legacy_yield(_options: u32) -> zx_status_t {
    ZX_OK
}

/// Creates a process that shares its address space and handle table with another.
///
/// Placeholder: returns `ZX_ERR_NOT_SUPPORTED` without producing handles.
///
/// # Safety
///
/// `name` must point to `name_len` readable bytes; the out-pointers must be
/// valid to write. Mirrors the upstream FFI signature.
#[allow(clippy::too_many_arguments)]
pub unsafe fn zx_process_create_shared(
    _shared_proc: zx_handle_t,
    _options: u32,
    _name: *const u8,
    _name_len: usize,
    _proc_handle_out: *mut zx_handle_t,
    _restricted_vmar_handle_out: *mut zx_handle_t,
) -> zx_status_t {
    ZX_ERR_NOT_SUPPORTED
}
