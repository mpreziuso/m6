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

// -- Capability Operations

/// Copy a capability from one slot to another.
///
/// Creates a copy of the source capability at the destination slot.
/// The CDT tracks the copy as a sibling of the source.
///
/// # Arguments
///
/// * `dest_cnode` - CPtr to the destination CNode
/// * `dest_index` - Slot index in the destination CNode
/// * `dest_depth` - Bits to consume resolving dest CNode (0 = auto)
/// * `src_cnode` - CPtr to the source CNode
/// * `src_index` - Slot index in the source CNode
/// * `src_depth` - Bits to consume resolving src CNode (0 = auto)
#[inline]
pub fn cap_copy(
    dest_cnode: u64,
    dest_index: u64,
    dest_depth: u64,
    src_cnode: u64,
    src_index: u64,
    src_depth: u64,
) -> SyscallResult {
    check_result(syscall6(
        Syscall::CapCopy,
        dest_cnode,
        dest_index,
        dest_depth,
        src_cnode,
        src_index,
        src_depth,
    ))
}

/// Move a capability from one slot to another.
///
/// Moves the source capability to the destination slot, leaving
/// the source slot empty. CDT membership transfers with the capability.
///
/// # Arguments
///
/// Same as `cap_copy`.
#[inline]
pub fn cap_move(
    dest_cnode: u64,
    dest_index: u64,
    dest_depth: u64,
    src_cnode: u64,
    src_index: u64,
    src_depth: u64,
) -> SyscallResult {
    check_result(syscall6(
        Syscall::CapMove,
        dest_cnode,
        dest_index,
        dest_depth,
        src_cnode,
        src_index,
        src_depth,
    ))
}

/// Mint a derived capability with reduced rights and optional badge.
///
/// Creates a derived capability at the destination slot. Rights can only
/// be reduced, never increased. The CDT tracks the new capability as a
/// child of the source.
///
/// Extended arguments (depths, rights, badge) are read from the IPC buffer
/// at `IPC_BUFFER_ADDR`. Use [`crate::IpcBuffer::get_mut()`] to set up the
/// mint arguments before calling this function.
///
/// # Arguments
///
/// * `dest_cnode` - CPtr to the destination CNode
/// * `dest_index` - Slot index in the destination CNode
/// * `src_cnode` - CPtr to the source CNode
/// * `src_index` - Slot index in the source CNode
///
/// # IPC Buffer (at IPC_BUFFER_ADDR)
///
/// The `mint_args` field must be set with:
/// - `dest_depth` - Bits to consume resolving dest CNode (0 = auto)
/// - `src_depth` - Bits to consume resolving src CNode (0 = auto)
/// - `new_rights` - Rights for the minted capability (subset of source)
/// - `set_badge` - Whether to set a badge (0 or 1)
/// - `badge_value` - Badge value (only used if set_badge != 0)
#[inline]
pub fn cap_mint(
    dest_cnode: u64,
    dest_index: u64,
    src_cnode: u64,
    src_index: u64,
) -> SyscallResult {
    check_result(syscall4(
        Syscall::CapMint,
        dest_cnode,
        dest_index,
        src_cnode,
        src_index,
    ))
}

/// Delete a capability from a slot.
///
/// Removes the capability from the specified slot. If the capability
/// has children in the CDT, they are reparented to the grandparent.
///
/// # Arguments
///
/// * `cnode` - CPtr to the CNode containing the capability
/// * `index` - Slot index to delete
/// * `depth` - Bits to consume resolving CNode (0 = auto)
#[inline]
pub fn cap_delete(cnode: u64, index: u64, depth: u64) -> SyscallResult {
    check_result(syscall3(Syscall::CapDelete, cnode, index, depth))
}

/// Revoke a capability and all its derivatives.
///
/// Recursively removes the capability and all capabilities derived from it
/// in the CDT. This is used to completely remove access to a resource.
///
/// # Arguments
///
/// * `cnode` - CPtr to the CNode containing the capability
/// * `index` - Slot index to revoke
/// * `depth` - Bits to consume resolving CNode (0 = auto)
///
/// # Returns
///
/// On success, returns the number of capabilities revoked (including the target).
#[inline]
pub fn cap_revoke(cnode: u64, index: u64, depth: u64) -> SyscallResult {
    check_result(syscall3(Syscall::CapRevoke, cnode, index, depth))
}

/// Reduce the rights of a capability in-place.
///
/// Modifies the capability to have reduced rights. The new rights must
/// be a subset of the current rights. This does not create a new CDT node.
///
/// # Arguments
///
/// * `cnode` - CPtr to the CNode containing the capability
/// * `index` - Slot index to mutate
/// * `depth` - Bits to consume resolving CNode (0 = auto)
/// * `new_rights` - New rights (must be subset of current)
#[inline]
pub fn cap_mutate(cnode: u64, index: u64, depth: u64, new_rights: u64) -> SyscallResult {
    check_result(syscall4(Syscall::CapMutate, cnode, index, depth, new_rights))
}

/// Atomically rotate capabilities between three slots.
///
/// Performs a three-way rotation:
/// - slot1 -> slot2
/// - slot2 -> slot3
/// - slot3 -> slot1
///
/// All slots must be in the same CNode.
///
/// # Arguments
///
/// * `cnode` - CPtr to the CNode containing all three slots
/// * `slot1` - First slot index
/// * `slot2` - Second slot index
/// * `slot3` - Third slot index
/// * `depth` - Bits to consume resolving CNode (0 = auto)
#[inline]
pub fn cap_rotate(cnode: u64, slot1: u64, slot2: u64, slot3: u64, depth: u64) -> SyscallResult {
    check_result(syscall5(Syscall::CapRotate, cnode, slot1, slot2, slot3, depth))
}
