//! Syscall invocation primitives for userspace
//!
//! This module provides inline assembly wrappers for invoking M6 syscalls
//! from userspace. It is only available when the `userspace` feature is enabled.
//!
//! # ARM64 ABI
//!
//! - x7: syscall number
//! - x0-x5: arguments
//! - x0: return value (negative = error)

use crate::error::{SyscallResult, check_result};
use crate::numbers::Syscall;

/// Raw syscall with 0 arguments.
#[inline]
pub fn syscall0(num: Syscall) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall with no memory side effects.
    // The svc instruction traps to EL1 where the kernel handles it.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            lateout("x0") ret,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 1 argument.
#[inline]
pub fn syscall1(num: Syscall, arg0: u64) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall. x0 is used for both input and output.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 2 arguments.
#[inline]
pub fn syscall2(num: Syscall, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 3 arguments.
#[inline]
pub fn syscall3(num: Syscall, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 4 arguments.
#[inline]
pub fn syscall4(num: Syscall, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 5 arguments.
#[inline]
pub fn syscall5(num: Syscall, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            options(nostack)
        );
    }
    ret
}

/// Raw syscall with 6 arguments.
#[inline]
pub fn syscall6(
    num: Syscall,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let ret: i64;
    // SAFETY: Inline assembly for syscall.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") num as u64,
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            options(nostack)
        );
    }
    ret
}

// === Convenience Functions ===

/// Debug: print a character to console.
///
/// This is a debug-only syscall that prints a single byte to the kernel console.
/// It should not be used in production code.
#[inline]
pub fn debug_putc(c: u8) {
    syscall1(Syscall::DebugPutChar, c as u64);
}

/// Yield CPU time slice.
///
/// Voluntarily gives up the current time slice, allowing other tasks to run.
/// The calling task remains runnable and will be scheduled again.
#[inline]
pub fn sched_yield() {
    syscall0(Syscall::Yield);
}

/// Send a message to an endpoint.
///
/// Blocks until a receiver is ready.
///
/// # Arguments
/// * `dest` - Capability slot of the endpoint
/// * `msg0`-`msg3` - Message registers
#[inline]
pub fn send(dest: u64, msg0: u64, msg1: u64, msg2: u64, msg3: u64) -> SyscallResult {
    check_result(syscall5(Syscall::Send, dest, msg0, msg1, msg2, msg3))
}

/// Receive a message from an endpoint.
///
/// Blocks until a sender is ready.
///
/// # Arguments
/// * `src` - Capability slot of the endpoint
///
/// # Returns
/// Badge of the sender on success.
#[inline]
pub fn recv(src: u64) -> SyscallResult {
    check_result(syscall1(Syscall::Recv, src))
}

/// Non-blocking send.
///
/// Returns immediately if no receiver is ready.
#[inline]
pub fn nb_send(dest: u64, msg0: u64, msg1: u64, msg2: u64, msg3: u64) -> SyscallResult {
    check_result(syscall5(Syscall::NBSend, dest, msg0, msg1, msg2, msg3))
}

/// Non-blocking receive.
///
/// Returns immediately if no sender is ready.
#[inline]
pub fn nb_recv(src: u64) -> SyscallResult {
    check_result(syscall1(Syscall::NBRecv, src))
}

/// Signal a notification.
///
/// ORs the badge into the notification's signal word.
#[inline]
pub fn signal(dest: u64) -> SyscallResult {
    check_result(syscall1(Syscall::Signal, dest))
}

/// Wait on a notification.
///
/// Blocks until signalled, returns the signal word.
#[inline]
pub fn wait(src: u64) -> SyscallResult {
    check_result(syscall1(Syscall::Wait, src))
}

/// Poll a notification.
///
/// Non-blocking check of notification state.
#[inline]
pub fn poll(src: u64) -> SyscallResult {
    check_result(syscall1(Syscall::Poll, src))
}
