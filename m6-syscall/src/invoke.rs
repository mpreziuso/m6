//! Syscall invocation primitives for userspace
//!
//! This module provides inline assembly wrappers for invoking M6 syscalls
//! from userspace. It is only available when the `userspace` feature is enabled.
//!
//! # ARM64 ABI
//!
//! - x7: syscall number
//! - x0-x5: arguments (x0 = endpoint cptr for IPC)
//! - x0: return value (negative = error)
//!
//! # IPC Message Layout
//!
//! On send/call: message is in x1-x5 (x0 = endpoint cptr)
//! On recv: message is delivered to x0-x4, badge in x6

use crate::IpcBuffer;
use crate::error::{SyscallResult, check_result};
use crate::numbers::Syscall;

/// Result of an IPC receive operation.
///
/// Contains both the sender badge and the message payload.
#[derive(Clone, Copy, Debug)]
pub struct IpcRecvResult {
    /// Badge identifying the sender.
    pub badge: u64,
    /// Message label (first word, typically request type).
    pub label: u64,
    /// Additional message words.
    pub msg: [u64; 4],
}

impl IpcRecvResult {
    /// Get message word by index (0 = label, 1-4 = additional words).
    #[inline]
    pub fn get(&self, index: usize) -> Option<u64> {
        match index {
            0 => Some(self.label),
            1..=4 => Some(self.msg[index - 1]),
            _ => None,
        }
    }
}

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

/// Debug: print a string to console.
///
/// This is a debug-only syscall that prints a string to the kernel console.
/// More efficient than `debug_putc` in a loop as it requires only one syscall.
#[inline]
pub fn debug_puts(s: &str) {
    syscall2(Syscall::DebugPuts, s.as_ptr() as u64, s.len() as u64);
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
/// On success, returns the badge and message. On error, returns the syscall error.
#[inline]
pub fn recv(src: u64) -> Result<IpcRecvResult, crate::error::SyscallError> {
    let x0: i64;
    let x1: u64;
    let x2: u64;
    let x3: u64;
    let x4: u64;
    let badge: u64;
    // SAFETY: Inline assembly for syscall. Capture all message registers and badge.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") Syscall::Recv as u64,
            inlateout("x0") src as i64 => x0,
            lateout("x1") x1,
            lateout("x2") x2,
            lateout("x3") x3,
            lateout("x4") x4,
            lateout("x6") badge,
            options(nostack)
        );
    }
    // If x0 is negative, it's an error code from the kernel
    // If x0 is non-negative, the message was delivered
    if x0 < 0 {
        Err(crate::error::SyscallError::from_i64(x0)
            .unwrap_or(crate::error::SyscallError::InvalidArg))
    } else {
        Ok(IpcRecvResult {
            badge,
            label: x0 as u64,
            msg: [x1, x2, x3, x4],
        })
    }
}

/// Perform a call operation (send + wait for reply).
///
/// This is the client side of RPC. The caller sends a message and blocks
/// waiting for the server to reply. The reply message is delivered directly
/// to the caller's registers when it arrives.
///
/// # Arguments
///
/// * `dest` - Endpoint capability pointer (requires WRITE + GRANT_REPLY rights)
/// * `msg0`-`msg3` - Message payload (x1-x4)
///
/// # Returns
///
/// The full reply message including label and payload registers.
#[inline]
pub fn call(
    dest: u64,
    msg0: u64,
    msg1: u64,
    msg2: u64,
    msg3: u64,
) -> Result<IpcRecvResult, crate::error::SyscallError> {
    let x0: i64;
    let x1: u64;
    let x2: u64;
    let x3: u64;
    let x4: u64;
    let badge: u64;
    // SAFETY: Inline assembly for syscall. Capture all reply registers.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") Syscall::Call as u64,
            inlateout("x0") dest as i64 => x0,
            inlateout("x1") msg0 => x1,
            inlateout("x2") msg1 => x2,
            inlateout("x3") msg2 => x3,
            inlateout("x4") msg3 => x4,
            lateout("x6") badge,
            options(nostack)
        );
    }
    // If x0 is negative, it's an error code from the kernel
    // If x0 is non-negative, the reply was delivered
    if x0 < 0 {
        Err(crate::error::SyscallError::from_i64(x0)
            .unwrap_or(crate::error::SyscallError::InvalidArg))
    } else {
        Ok(IpcRecvResult {
            badge,
            label: x0 as u64,
            msg: [x1, x2, x3, x4],
        })
    }
}

/// Perform a reply-receive operation (reply + wait for next message).
///
/// This is the server side of RPC. The server replies to the previous caller
/// (if any) and then blocks waiting for the next message.
///
/// # Arguments
///
/// * `ep` - Endpoint capability pointer (requires READ + WRITE rights)
/// * `msg0`-`msg3` - Reply message payload (x1-x4)
///
/// # Returns
///
/// On success, returns the badge and message from the new sender.
#[inline]
pub fn reply_recv(
    ep: u64,
    msg0: u64,
    msg1: u64,
    msg2: u64,
    msg3: u64,
) -> Result<IpcRecvResult, crate::error::SyscallError> {
    let x0: i64;
    let x1: u64;
    let x2: u64;
    let x3: u64;
    let x4: u64;
    let badge: u64;
    // SAFETY: Inline assembly for syscall. Capture all message registers and badge.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") Syscall::ReplyRecv as u64,
            inlateout("x0") ep as i64 => x0,
            inlateout("x1") msg0 => x1,
            inlateout("x2") msg1 => x2,
            inlateout("x3") msg2 => x3,
            inlateout("x4") msg3 => x4,
            lateout("x6") badge,
            options(nostack)
        );
    }
    // If x0 is negative, it's an error code from the kernel
    // If x0 is non-negative, the message was delivered
    if x0 < 0 {
        Err(crate::error::SyscallError::from_i64(x0)
            .unwrap_or(crate::error::SyscallError::InvalidArg))
    } else {
        Ok(IpcRecvResult {
            badge,
            label: x0 as u64,
            msg: [x1, x2, x3, x4],
        })
    }
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
pub fn nb_recv(src: u64) -> Result<IpcRecvResult, crate::error::SyscallError> {
    let x0: i64;
    let x1: u64;
    let x2: u64;
    let x3: u64;
    let x4: u64;
    let badge: u64;
    // SAFETY: Inline assembly for syscall. Capture all message registers and badge.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") Syscall::NBRecv as u64,
            inlateout("x0") src as i64 => x0,
            lateout("x1") x1,
            lateout("x2") x2,
            lateout("x3") x3,
            lateout("x4") x4,
            lateout("x6") badge,
            options(nostack)
        );
    }
    // If x0 is negative, it's an error code from the kernel
    // If x0 is non-negative, the message was delivered
    if x0 < 0 {
        Err(crate::error::SyscallError::from_i64(x0)
            .unwrap_or(crate::error::SyscallError::InvalidArg))
    } else {
        Ok(IpcRecvResult {
            badge,
            label: x0 as u64,
            msg: [x1, x2, x3, x4],
        })
    }
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
pub fn cap_mint(dest_cnode: u64, dest_index: u64, src_cnode: u64, src_index: u64) -> SyscallResult {
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
    check_result(syscall4(
        Syscall::CapMutate,
        cnode,
        index,
        depth,
        new_rights,
    ))
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
    check_result(syscall5(
        Syscall::CapRotate,
        cnode,
        slot1,
        slot2,
        slot3,
        depth,
    ))
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
    check_result(syscall5(
        Syscall::MapFrame,
        vspace,
        frame,
        vaddr,
        rights,
        attr,
    ))
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
    check_result(syscall4(
        Syscall::MapPageTable,
        vspace,
        page_table,
        vaddr,
        level,
    ))
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

/// Write data from userspace into a frame capability.
///
/// This syscall allows writing data into a frame without needing to map it
/// into the caller's address space. The kernel copies data from the source
/// buffer directly into the frame's physical memory.
///
/// # Arguments
///
/// * `frame` - CPtr to the frame capability (must have Write right)
/// * `offset` - Byte offset within the frame to start writing
/// * `src` - Pointer to source data in userspace
/// * `len` - Number of bytes to write
///
/// # Returns
///
/// Number of bytes written on success, negative error code on failure.
#[inline]
pub fn frame_write(frame: u64, offset: u64, src: *const u8, len: usize) -> SyscallResult {
    check_result(syscall4(
        Syscall::FrameWrite,
        frame,
        offset,
        src as u64,
        len as u64,
    ))
}

/// Get the physical address of a frame.
///
/// Returns the physical address of the frame, suitable for DMA programming
/// on platforms without IOMMU.
///
/// # Arguments
///
/// * `frame` - CPtr to the frame capability (Frame or DeviceFrame)
///
/// # Returns
///
/// Physical address of the frame on success, or error code on failure.
#[inline]
pub fn frame_get_phys(frame: u64) -> SyscallResult {
    check_result(syscall1(Syscall::FrameGetPhys, frame))
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
    // The kernel expects a buffer of register values:
    // [x0..x30, sp, pc, spsr] as u64 array
    // We write: x0, sp (index 31), pc (index 32), spsr (index 33)
    let mut regs = [0u64; 34];
    regs[0] = arg0; // x0
    regs[31] = sp; // SP
    regs[32] = pc; // ELR (PC)
    regs[33] = 0; // SPSR (EL0 AArch64 = 0)

    // Syscall ABI:
    // x0: TCB cptr
    // x1: resume flag (0 = don't resume)
    // x2: arch flags (reserved, must be 0)
    // x3: number of registers
    // x4: buffer address
    check_result(syscall5(
        Syscall::TcbWriteRegisters,
        tcb,
        0,                    // resume = false
        0,                    // arch_flags = 0
        34,                   // count = 34 registers
        regs.as_ptr() as u64, // buffer address
    ))
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

/// Exit the current thread with an exit code.
///
/// This syscall terminates the calling thread, setting it to Inactive state
/// and storing the exit code. If the thread has a bound notification, it will
/// be signalled with the exit code as the badge.
///
/// This syscall never returns.
///
/// # Arguments
///
/// * `code` - Exit code (conventionally 0 = success, non-zero = failure)
#[inline]
pub fn tcb_exit(code: i32) -> ! {
    syscall1(Syscall::TcbExit, code as u64);
    // The syscall should never return, but in case of an error,
    // loop indefinitely (the kernel should have removed us from the scheduler)
    loop {
        sched_yield();
    }
}

/// Sleep the current thread for a specified duration.
///
/// The thread is suspended and will be woken by the kernel's timer
/// system after the specified number of nanoseconds have elapsed.
///
/// # Arguments
///
/// * `nanoseconds` - Duration to sleep in nanoseconds
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the syscall fails.
#[inline]
pub fn tcb_sleep(nanoseconds: u64) -> SyscallResult {
    check_result(syscall1(Syscall::TcbSleep, nanoseconds))
}

// -- IRQ Operations

/// Claim an IRQ from IRQControl and create an IRQHandler capability.
///
/// This syscall allocates an IRQHandler object for the specified hardware
/// interrupt and places the capability in the destination CNode slot.
///
/// # Arguments
///
/// * `irq_control` - CPtr to the IRQControl capability
/// * `irq` - Hardware IRQ number to claim
/// * `dest_cnode` - CPtr to the destination CNode
/// * `dest_index` - Slot index in the destination CNode
/// * `depth` - Bits to consume resolving dest CNode (0 = auto)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn irq_control_get(
    irq_control: u64,
    irq: u32,
    dest_cnode: u64,
    dest_index: u64,
    depth: u64,
) -> SyscallResult {
    check_result(syscall5(
        Syscall::IrqControlGet,
        irq_control,
        irq as u64,
        dest_cnode,
        dest_index,
        depth,
    ))
}

/// Bind an IRQ handler to a notification.
///
/// When the hardware interrupt fires, the kernel will signal the
/// notification with the specified badge.
///
/// # Arguments
///
/// * `irq_handler` - CPtr to the IRQHandler capability
/// * `notification` - CPtr to the Notification capability
/// * `badge` - Badge value to OR into notification on interrupt
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn irq_set_handler(irq_handler: u64, notification: u64, badge: u64) -> SyscallResult {
    check_result(syscall3(
        Syscall::IrqSetHandler,
        irq_handler,
        notification,
        badge,
    ))
}

/// Acknowledge an IRQ, allowing it to fire again.
///
/// Must be called after handling an interrupt to re-enable it.
/// The IRQ handler must be in the Masked state (after receiving
/// a notification from the kernel).
///
/// # Arguments
///
/// * `irq_handler` - CPtr to the IRQHandler capability
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn irq_ack(irq_handler: u64) -> SyscallResult {
    check_result(syscall1(Syscall::IrqAck, irq_handler))
}

/// Unbind an IRQ handler from its notification.
///
/// Disables the IRQ and clears the handler binding.
/// After this call, the IRQ will no longer generate notifications.
///
/// # Arguments
///
/// * `irq_handler` - CPtr to the IRQHandler capability
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn irq_clear_handler(irq_handler: u64) -> SyscallResult {
    check_result(syscall1(Syscall::IrqClearHandler, irq_handler))
}

/// Result of MSI allocation.
#[derive(Clone, Copy, Debug)]
pub struct MsiAllocResult {
    /// Physical address to write for MSI (GICD_SETSPI_NSR).
    pub target_addr: u64,
    /// Base SPI number (message data for first vector).
    pub base_spi: u32,
    /// Number of vectors actually allocated.
    pub vector_count: u32,
}

/// Allocate MSI vectors for a device.
///
/// Allocates SPIs for MSI-X interrupt delivery and returns the
/// configuration needed to programme the device's MSI-X table.
///
/// # Arguments
///
/// * `irq_control` - CPtr to the IRQControl capability
/// * `vector_count` - Number of MSI vectors requested
///
/// # Returns
///
/// On success, returns MsiAllocResult with MSI configuration.
/// On error, returns the syscall error.
#[inline]
pub fn msi_allocate(
    irq_control: u64,
    vector_count: u32,
) -> Result<MsiAllocResult, crate::error::SyscallError> {
    let x0: i64;
    let x1: u64;
    let x2: u64;
    let x3: u64;
    // SAFETY: Inline assembly for syscall. Capture all return registers.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x7") Syscall::MsiAllocate as u64,
            inlateout("x0") irq_control as i64 => x0,
            inlateout("x1") vector_count as u64 => x1,
            lateout("x2") x2,
            lateout("x3") x3,
            options(nostack)
        );
    }
    if x0 < 0 {
        Err(crate::error::SyscallError::from_i64(x0)
            .unwrap_or(crate::error::SyscallError::InvalidArg))
    } else {
        Ok(MsiAllocResult {
            target_addr: x1,
            base_spi: x2 as u32,
            vector_count: x3 as u32,
        })
    }
}

// -- IOSpace and DMA Operations

/// Create an IOSpace from untyped memory.
///
/// An IOSpace represents an IOMMU translation domain with its own page tables.
/// Requires an SMMU Control capability to allocate a unique IOASID.
///
/// # Arguments
///
/// * `smmu_control` - CPtr to the SmmuControl capability
/// * `untyped` - CPtr to untyped memory for page tables (requires 4KB)
/// * `dest_cnode` - CPtr to the destination CNode
/// * `dest_index` - Slot index for the new IOSpace capability
/// * `dest_depth` - Bits to consume resolving dest CNode (0 = auto)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn iospace_create(
    smmu_control: u64,
    untyped: u64,
    dest_cnode: u64,
    dest_index: u64,
    dest_depth: u64,
) -> SyscallResult {
    check_result(syscall5(
        Syscall::IOSpaceCreate,
        smmu_control,
        untyped,
        dest_cnode,
        dest_index,
        dest_depth,
    ))
}

/// Map a frame into an IOSpace at a given IOVA.
///
/// Creates an I/O page table mapping for DMA. The frame's physical address
/// will be mapped at the specified IOVA within the IOSpace's translation tables.
///
/// # Arguments
///
/// * `iospace` - CPtr to the IOSpace capability
/// * `frame` - CPtr to the Frame capability to map
/// * `iova` - I/O virtual address (must be page-aligned)
/// * `rights` - Access rights (R=1, W=2, RW=3)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn iospace_map_frame(iospace: u64, frame: u64, iova: u64, rights: u64) -> SyscallResult {
    check_result(syscall4(
        Syscall::IOSpaceMapFrame,
        iospace,
        frame,
        iova,
        rights,
    ))
}

/// Unmap a frame from an IOSpace.
///
/// Removes the I/O page table mapping at the given IOVA.
///
/// # Arguments
///
/// * `iospace` - CPtr to the IOSpace capability
/// * `iova` - I/O virtual address to unmap (must be page-aligned)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn iospace_unmap_frame(iospace: u64, iova: u64) -> SyscallResult {
    check_result(syscall2(Syscall::IOSpaceUnmapFrame, iospace, iova))
}

/// Bind a PCIe stream ID to an IOSpace.
///
/// Configures the SMMU to translate DMA from the specified stream ID
/// using this IOSpace's page tables. The stream ID typically comes from
/// the PCIe Requester ID (bus:device:function).
///
/// # Arguments
///
/// * `iospace` - CPtr to the IOSpace capability
/// * `smmu_control` - CPtr to the SmmuControl capability
/// * `stream_id` - PCIe stream ID to bind
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn iospace_bind_stream(iospace: u64, smmu_control: u64, stream_id: u32) -> SyscallResult {
    check_result(syscall3(
        Syscall::IOSpaceBindStream,
        iospace,
        smmu_control,
        stream_id as u64,
    ))
}

/// Unbind a PCIe stream ID from an IOSpace.
///
/// Removes the stream binding and sets the stream to bypass mode.
///
/// # Arguments
///
/// * `iospace` - CPtr to the IOSpace capability
/// * `smmu_control` - CPtr to the SmmuControl capability
/// * `stream_id` - PCIe stream ID to unbind
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn iospace_unbind_stream(iospace: u64, smmu_control: u64, stream_id: u32) -> SyscallResult {
    check_result(syscall3(
        Syscall::IOSpaceUnbindStream,
        iospace,
        smmu_control,
        stream_id as u64,
    ))
}

/// Create a DmaPool for IOVA allocation.
///
/// A DmaPool manages a range of IOVAs within an IOSpace, providing
/// bump/watermark allocation for DMA buffers.
///
/// # Arguments
///
/// * `iospace` - CPtr to the parent IOSpace capability
/// * `iova_base` - Base IOVA of the pool range
/// * `iova_size` - Size of the pool range in bytes
/// * `dest_cnode` - CPtr to the destination CNode
/// * `dest_index` - Slot index for the new DmaPool capability
/// * `dest_depth` - Bits to consume resolving dest CNode (0 = auto)
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn dma_pool_create(
    iospace: u64,
    iova_base: u64,
    iova_size: u64,
    dest_cnode: u64,
    dest_index: u64,
    dest_depth: u64,
) -> SyscallResult {
    check_result(syscall6(
        Syscall::DmaPoolCreate,
        iospace,
        iova_base,
        iova_size,
        dest_cnode,
        dest_index,
        dest_depth,
    ))
}

/// Allocate an IOVA range from a DmaPool.
///
/// Uses bump/watermark allocation to return an aligned IOVA address.
/// The caller is responsible for mapping actual frames at this IOVA
/// using `iospace_map_frame`.
///
/// # Arguments
///
/// * `dma_pool` - CPtr to the DmaPool capability
/// * `size` - Size to allocate in bytes
/// * `alignment` - Required alignment (must be power of 2)
///
/// # Returns
///
/// IOVA address on success, negative error code on failure.
#[inline]
pub fn dma_pool_alloc(
    dma_pool: u64,
    size: u64,
    alignment: u64,
) -> Result<u64, crate::error::SyscallError> {
    let result = syscall3(Syscall::DmaPoolAlloc, dma_pool, size, alignment);
    if result < 0 {
        Err(crate::error::SyscallError::from_i64(result)
            .unwrap_or(crate::error::SyscallError::InvalidSyscall))
    } else {
        Ok(result as u64)
    }
}

/// Free an IOVA range back to a DmaPool.
///
/// Note: Current implementation uses bump allocation, so individual
/// frees are not supported. This syscall is reserved for future use.
///
/// # Arguments
///
/// * `dma_pool` - CPtr to the DmaPool capability
/// * `iova` - Base IOVA to free
/// * `size` - Size to free in bytes
///
/// # Returns
///
/// 0 on success, negative error code on failure.
#[inline]
pub fn dma_pool_free(dma_pool: u64, iova: u64, size: u64) -> SyscallResult {
    check_result(syscall3(Syscall::DmaPoolFree, dma_pool, iova, size))
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
    caps[..count.min(4)].copy_from_slice(&ipc_buf.caps_or_badges[..count.min(4)]);
    caps
}

// -- Miscellaneous Operations

/// Get cryptographically random bytes from the kernel.
///
/// This syscall provides random bytes suitable for security-sensitive
/// operations like stack canaries, ASLR, and heap allocator secrets.
///
/// # Arguments
///
/// * `buf` - Buffer to fill with random bytes (max 256 bytes)
///
/// # Returns
///
/// Number of bytes written on success.
///
/// # Errors
///
/// * `InvalidArg` - Buffer length exceeds 256 bytes
/// * `Range` - Buffer address is invalid
///
/// # Example
///
/// ```ignore
/// let mut secret = [0u8; 8];
/// let bytes = get_random(&mut secret)?;
/// assert_eq!(bytes, 8);
/// ```
#[cfg(feature = "userspace")]
#[inline]
pub fn get_random(buf: &mut [u8]) -> SyscallResult {
    if buf.len() > 256 {
        return Err(crate::error::SyscallError::InvalidArg);
    }
    check_result(syscall2(
        Syscall::GetRandom,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ))
}

// -- Cache Maintenance Operations

/// DMA transfer direction for cache maintenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes data, device reads (e.g., TX buffer).
    ToDevice,
    /// Device writes data, CPU reads (e.g., RX buffer).
    FromDevice,
    /// Both CPU and device may read/write.
    Bidirectional,
}

/// Clean cache range (write back dirty lines to memory).
///
/// Use before DMA to device to ensure memory has the latest CPU writes.
///
/// # Arguments
///
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Returns
///
/// 0 on success.
///
/// # Errors
///
/// * `InvalidArg` - Size exceeds 16MB limit
/// * `Range` - Address is outside userspace range
#[inline]
pub fn cache_clean(vaddr: u64, size: usize) -> SyscallResult {
    check_result(syscall2(Syscall::CacheClean, vaddr, size as u64))
}

/// Invalidate cache range (discard cache lines without writing back).
///
/// Use after DMA from device to ensure CPU reads fresh data from memory.
///
/// # Arguments
///
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Returns
///
/// 0 on success.
///
/// # Errors
///
/// * `InvalidArg` - Size exceeds 16MB limit
/// * `Range` - Address is outside userspace range
///
/// # Safety Note
///
/// Only use when you're certain no dirty data needs to be preserved.
/// Typically used after a device has written new data via DMA.
#[inline]
pub fn cache_invalidate(vaddr: u64, size: usize) -> SyscallResult {
    check_result(syscall2(Syscall::CacheInvalidate, vaddr, size as u64))
}

/// Flush cache range (clean + invalidate).
///
/// Use for bidirectional DMA or when the coherency direction is uncertain.
///
/// # Arguments
///
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
///
/// # Returns
///
/// 0 on success.
///
/// # Errors
///
/// * `InvalidArg` - Size exceeds 16MB limit
/// * `Range` - Address is outside userspace range
#[inline]
pub fn cache_flush(vaddr: u64, size: usize) -> SyscallResult {
    check_result(syscall2(Syscall::CacheFlush, vaddr, size as u64))
}

/// Synchronise cache for DMA with direction awareness.
///
/// This is a convenience wrapper that selects the appropriate cache
/// operation based on DMA direction:
///
/// - `ToDevice`: Clean (CPU -> Device)
/// - `FromDevice`: Invalidate (Device -> CPU)
/// - `Bidirectional`: Flush (both directions)
///
/// # Arguments
///
/// * `vaddr` - Virtual address of buffer
/// * `size` - Size of buffer in bytes
/// * `direction` - DMA transfer direction
///
/// # Returns
///
/// 0 on success.
#[inline]
pub fn dma_sync(vaddr: u64, size: usize, direction: DmaDirection) -> SyscallResult {
    match direction {
        DmaDirection::ToDevice => cache_clean(vaddr, size),
        DmaDirection::FromDevice => cache_invalidate(vaddr, size),
        DmaDirection::Bidirectional => cache_flush(vaddr, size),
    }
}
