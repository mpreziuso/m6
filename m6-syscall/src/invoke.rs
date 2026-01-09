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
use crate::IpcBuffer;

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

// -- Memory Operations

/// Retype untyped memory into new kernel objects.
///
/// Creates typed objects from a region of untyped memory. Multiple objects
/// can be created in a single call if they fit in the untyped region.
///
/// # Arguments
///
/// * `untyped` - CPtr to the untyped memory capability
/// * `object_type` - Type of objects to create (see ObjectType enum)
/// * `size_bits` - Log2 size for variable-size objects (e.g., CNode radix)
/// * `dest_cnode` - CPtr to the CNode for new capabilities
/// * `dest_index` - Starting slot index in the destination CNode
/// * `count` - Number of objects to create
///
/// # Returns
///
/// On success, returns the number of objects created.
#[inline]
pub fn retype(
    untyped: u64,
    object_type: u64,
    size_bits: u64,
    dest_cnode: u64,
    dest_index: u64,
    count: u64,
) -> SyscallResult {
    check_result(syscall6(
        Syscall::Retype,
        untyped,
        object_type,
        size_bits,
        dest_cnode,
        dest_index,
        count,
    ))
}

/// Map a frame into a VSpace.
///
/// # Arguments
///
/// * `vspace` - CPtr to the VSpace capability
/// * `frame` - CPtr to the frame capability
/// * `vaddr` - Virtual address to map at (must be aligned to frame size)
/// * `rights` - Access rights (bitmap: R=1, W=2, X=4)
/// * `attr` - Memory attributes (0=normal, 1=device)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn map_frame(vspace: u64, frame: u64, vaddr: u64, rights: u64, attr: u64) -> SyscallResult {
    check_result(syscall5(Syscall::MapFrame, vspace, frame, vaddr, rights, attr))
}

/// Unmap a frame from a VSpace.
///
/// # Arguments
///
/// * `frame` - CPtr to the frame capability to unmap
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn unmap_frame(frame: u64) -> SyscallResult {
    check_result(syscall1(Syscall::UnmapFrame, frame))
}

/// Map a page table into a VSpace.
///
/// # Arguments
///
/// * `vspace` - CPtr to the VSpace capability
/// * `page_table` - CPtr to the page table capability
/// * `vaddr` - Virtual address covered by this page table
/// * `level` - Page table level (1=L1, 2=L2, 3=L3)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn map_page_table(vspace: u64, page_table: u64, vaddr: u64, level: u64) -> SyscallResult {
    check_result(syscall4(Syscall::MapPageTable, vspace, page_table, vaddr, level))
}

/// Assign an ASID from a pool to a VSpace.
///
/// # Arguments
///
/// * `asid_pool` - CPtr to the ASID pool capability
/// * `vspace` - CPtr to the VSpace capability
///
/// # Returns
///
/// The assigned ASID on success, negative error code on failure.
#[inline]
pub fn asid_pool_assign(asid_pool: u64, vspace: u64) -> SyscallResult {
    check_result(syscall2(Syscall::AsidPoolAssign, asid_pool, vspace))
}

// -- TCB Operations

/// Configure a TCB with its execution environment.
///
/// Sets the CSpace root, VSpace, IPC buffer, and fault endpoint for a TCB.
/// The TCB must be in the Inactive state.
///
/// # Arguments
///
/// * `tcb` - CPtr to the TCB capability
/// * `fault_ep` - CPtr to the fault endpoint (or 0 for none)
/// * `cspace` - CPtr to the CSpace root CNode
/// * `vspace` - CPtr to the VSpace
/// * `ipc_buf_addr` - Virtual address of the IPC buffer
/// * `ipc_buf_frame` - CPtr to the frame containing the IPC buffer
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn tcb_configure(
    tcb: u64,
    fault_ep: u64,
    cspace: u64,
    vspace: u64,
    ipc_buf_addr: u64,
    ipc_buf_frame: u64,
) -> SyscallResult {
    check_result(syscall6(
        Syscall::TcbConfigure,
        tcb,
        fault_ep,
        cspace,
        vspace,
        ipc_buf_addr,
        ipc_buf_frame,
    ))
}

/// Write registers to a TCB.
///
/// Sets the initial register state for a TCB. Typically used to set the
/// program counter (PC) and stack pointer (SP) before resuming a thread.
///
/// # Arguments
///
/// * `tcb` - CPtr to the TCB capability
/// * `pc` - Program counter (entry point)
/// * `sp` - Stack pointer
/// * `arg0` - Value for x0 register (first argument)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn tcb_write_registers(tcb: u64, pc: u64, sp: u64, arg0: u64) -> SyscallResult {
    check_result(syscall4(Syscall::TcbWriteRegisters, tcb, pc, sp, arg0))
}

/// Resume a TCB, transitioning it to the Running state.
///
/// The TCB will be scheduled and begin executing at its configured PC.
///
/// # Arguments
///
/// * `tcb` - CPtr to the TCB capability
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn tcb_resume(tcb: u64) -> SyscallResult {
    check_result(syscall1(Syscall::TcbResume, tcb))
}

/// Suspend a TCB, removing it from the scheduler.
///
/// # Arguments
///
/// * `tcb` - CPtr to the TCB capability
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn tcb_suspend(tcb: u64) -> SyscallResult {
    check_result(syscall1(Syscall::TcbSuspend, tcb))
}

// -- IPC Buffer Helpers

/// Prepare IPC buffer for sending capabilities.
///
/// Sets up the IPC buffer to transfer capabilities during the next IPC operation.
/// The capabilities will be resolved in the sender's CSpace and copied to the
/// receiver's CSpace (requires Grant right on the endpoint).
///
/// # Arguments
///
/// * `cap_slots` - Array of capability slots (CPtrs) to send (max 4)
///
/// # Safety
///
/// Caller must ensure the IPC buffer is mapped and accessible at the address
/// configured in the TCB.
#[cfg(feature = "userspace")]
pub unsafe fn ipc_set_send_caps(cap_slots: &[u64]) {
    // SAFETY: Caller ensures IPC buffer is mapped and accessible
    let ipc_buf = unsafe { IpcBuffer::get_mut() };
    let count = cap_slots.len().min(4);
    ipc_buf.extra_caps = count as u8;
    for (i, &slot) in cap_slots.iter().take(count).enumerate() {
        ipc_buf.caps_or_badges[i] = slot;
    }
}

/// Prepare IPC buffer for receiving capabilities.
///
/// Provides hints for where received capabilities should be placed in the
/// receiver's CSpace. If slots are not empty, the kernel will try to place
/// capabilities there; otherwise it will find empty slots.
///
/// # Arguments
///
/// * `dest_slots` - Hint slots where capabilities should be placed (max 4)
///
/// # Safety
///
/// Caller must ensure the IPC buffer is mapped and accessible.
#[cfg(feature = "userspace")]
pub unsafe fn ipc_set_recv_slots(dest_slots: &[u64]) {
    // SAFETY: Caller ensures IPC buffer is mapped and accessible
    let ipc_buf = unsafe { IpcBuffer::get_mut() };
    let count = dest_slots.len().min(4);
    for (i, &slot) in dest_slots.iter().take(count).enumerate() {
        ipc_buf.caps_or_badges[i] = slot;
    }
}

/// Get received capability slots after IPC.
///
/// Returns the slots where capabilities were placed in the receiver's CSpace.
/// The number of valid slots is indicated by `recv_extra_caps` field.
///
/// # Returns
///
/// Array of capability slots where capabilities were placed. Check
/// `IpcBuffer::get().recv_extra_caps` to see how many are valid.
///
/// # Safety
///
/// Caller must ensure the IPC buffer is mapped and accessible.
#[cfg(feature = "userspace")]
pub unsafe fn ipc_get_recv_caps() -> [u64; 4] {
    // SAFETY: Caller ensures IPC buffer is mapped and accessible
    let ipc_buf = unsafe { IpcBuffer::get() };
    let mut caps = [0u64; 4];
    let count = ipc_buf.recv_extra_caps as usize;
    for i in 0..count.min(4) {
        caps[i] = ipc_buf.caps_or_badges[i];
    }
    caps
}
