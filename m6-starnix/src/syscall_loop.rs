//! Syscall loop for Linux binary emulation
//!
//! This module implements the restricted-mode enter/exit loop that
//! intercepts Linux syscalls and dispatches them to handlers.
//!
//! The loop structure mirrors Fuchsia Starnix's `restricted_enter_loop`
//! but uses M6's RestrictedEnter/RestrictedBind syscalls.

extern crate alloc;

use crate::mm::MemoryManager;
use m6_syscall::invoke::{debug_puts, restricted_enter};

// Fault → Linux signal delivery (used by the forked dispatch loop's EXCEPTION arm).
use crate::signals::{SignalDetail, SignalInfo, dequeue_signal, send_standard_signal};
use crate::task::{ExceptionResult, ExitStatus};
use starnix_uapi::SI_KERNEL;
use starnix_uapi::signals::{SIGILL, SIGSEGV};

/// Exit reasons from restricted mode (matches kernel definitions).
pub mod exit_reason {
    pub const SYSCALL: i64 = 0;
    pub const EXCEPTION: i64 = 1;
    pub const KICK: i64 = 2;
}

/// Size of the ExceptionContext structure in the state frame.
const EXCEPTION_CONTEXT_SIZE: usize = 832;

/// Offset of the exit_reason field within the state frame.
const EXIT_REASON_OFFSET: usize = EXCEPTION_CONTEXT_SIZE;

// -- ExceptionContext field offsets (all u64 unless noted)
// gpr[0..31]    : offset 0   (31 * 8 = 248 bytes)
// sp            : offset 248
// elr           : offset 256
// spsr          : offset 264
// esr           : offset 272
// far           : offset 280
// tpidr_el0     : offset 288

const OFF_SP: usize = 31 * 8;
const OFF_ELR: usize = 32 * 8;
const OFF_SPSR: usize = 33 * 8;
const OFF_ESR: usize = 34 * 8;
const OFF_FAR: usize = 35 * 8;
#[allow(dead_code)]
const OFF_TPIDR: usize = 36 * 8;

/// State frame layout (4KB page):
/// - offset 0:   ExceptionContext (832 bytes) — Linux register state
/// - offset 832: u64 exit_reason
/// - offset 840: reserved
///
/// The state frame is mapped into both the Starnix process and accessible
/// to the kernel. When restricted mode exits, the kernel writes the Linux
/// register state and exit reason into this frame.
pub struct StateFrame {
    /// Virtual address of the state frame in the Starnix process
    pub vaddr: u64,
    /// Frame capability slot (not CPtr — caller uses mm.frame_cptr if needed)
    pub frame_slot: u64,
}

impl StateFrame {
    /// Read a general-purpose register (x0-x30).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_gpr(&self, index: usize) -> u64 {
        debug_assert!(index < 31);
        let ptr = self.vaddr as *const u64;
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ptr.add(index).read_volatile() }
    }

    /// Write a general-purpose register (x0-x30).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_gpr(&self, index: usize, value: u64) {
        debug_assert!(index < 31);
        let ptr = self.vaddr as *mut u64;
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ptr.add(index).write_volatile(value) }
    }

    /// Read the stack pointer.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_sp(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_SP as u64) as *const u64).read_volatile() }
    }

    /// Write the stack pointer.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_sp(&self, value: u64) {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_SP as u64) as *mut u64).write_volatile(value) }
    }

    /// Read the program counter (ELR).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_pc(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_ELR as u64) as *const u64).read_volatile() }
    }

    /// Write the program counter (ELR).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_pc(&self, value: u64) {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_ELR as u64) as *mut u64).write_volatile(value) }
    }

    /// Write the SPSR (initial processor state).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_spsr(&self, value: u64) {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_SPSR as u64) as *mut u64).write_volatile(value) }
    }

    /// Read the fault address (FAR).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_far(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_FAR as u64) as *const u64).read_volatile() }
    }

    /// Read the ESR (Exception Syndrome Register).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_esr(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_ESR as u64) as *const u64).read_volatile() }
    }

    /// Read the exit reason from the state frame.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_exit_reason(&self) -> i64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr as usize + EXIT_REASON_OFFSET) as *const u64).read_volatile() as i64 }
    }

    /// Read the Linux syscall number (x8).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_syscall_number(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { self.read_gpr(8) }
    }

    /// Read Linux syscall arguments (x0-x5).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_syscall_args(&self) -> [u64; 6] {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe {
            [
                self.read_gpr(0),
                self.read_gpr(1),
                self.read_gpr(2),
                self.read_gpr(3),
                self.read_gpr(4),
                self.read_gpr(5),
            ]
        }
    }

    /// Write the syscall return value (x0).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_return_value(&self, value: u64) {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { self.write_gpr(0, value) }
    }

    /// Read the TPIDR_EL0 (thread pointer) register.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_tpidr(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_TPIDR as u64) as *const u64).read_volatile() }
    }

    /// Write the TPIDR_EL0 (thread pointer) register.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_tpidr(&self, value: u64) {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_TPIDR as u64) as *mut u64).write_volatile(value) }
    }

    /// Read the SPSR_EL1 (saved program status / condition flags).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_spsr(&self) -> u64 {
        // SAFETY: Caller guarantees the mapping is valid.
        unsafe { ((self.vaddr + OFF_SPSR as u64) as *const u64).read_volatile() }
    }

    // -- Register-frame seam (M3 #2): M6 `ExceptionContext` ↔ Zircon
    //    `zx_restricted_state_t`, the register frame the forked Starnix core uses.
    //
    //    The layouts AGREE on gpr[0..31] (@0), sp (@248) and pc/elr (@256) — these
    //    map by raw offset — but DISAGREE on the rest:
    //      field         M6 ExceptionContext   zx_restricted_state_t
    //      cpsr/spsr     spsr  @264            cpsr        @272
    //      tpidr_el0     @288                  tpidr_el0   @264
    //    so those two fields MUST be mapped by meaning, not by offset. A raw
    //    `memcpy` would silently corrupt the condition flags and thread pointer.

    /// Convert the M6 exception context at `self.vaddr` into the Zircon
    /// restricted-state frame the Starnix core consumes.
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn read_zx_state(&self) -> zx::sys::zx_restricted_state_t {
        let mut s = zx::sys::zx_restricted_state_t::default();
        // SAFETY: caller guarantees the mapping is valid; each accessor reads
        // within the 832-byte ExceptionContext.
        unsafe {
            for i in 0..31 {
                s.r[i] = self.read_gpr(i);
            }
            s.sp = self.read_sp();
            s.pc = self.read_pc(); // ExceptionContext.elr
            s.tpidr_el0 = self.read_tpidr();
            s.cpsr = self.read_spsr() as u32; // ExceptionContext.spsr
        }
        s
    }

    /// Write a Zircon restricted-state frame back into the M6 exception context
    /// at `self.vaddr` (the inverse of [`read_zx_state`](Self::read_zx_state)).
    ///
    /// # Safety
    /// The state frame must be mapped and valid at `self.vaddr`.
    pub unsafe fn write_zx_state(&self, s: &zx::sys::zx_restricted_state_t) {
        // SAFETY: caller guarantees the mapping is valid; each accessor writes
        // within the 832-byte ExceptionContext.
        unsafe {
            for i in 0..31 {
                self.write_gpr(i, s.r[i]);
            }
            self.write_sp(s.sp);
            self.write_pc(s.pc); // ExceptionContext.elr
            self.write_tpidr(s.tpidr_el0);
            self.write_spsr(s.cpsr as u64); // ExceptionContext.spsr
        }
    }
}

/// Run the restricted-mode syscall loop.
///
/// This is the main entry point for Linux binary emulation. It:
/// 1. Binds the state frame to the current thread
/// 2. Enters restricted mode (Linux code runs at EL0 in the restricted VSpace)
/// 3. On exit, reads the reason and dispatches accordingly
/// 4. Re-enters restricted mode
///
/// The loop runs until the Linux process exits (exit_group syscall).
pub fn run_syscall_loop(state: &StateFrame, mm: &mut MemoryManager) -> i32 {
    let vspace_cptr = mm.vspace_cptr();

    loop {
        // Enter restricted mode — Linux code runs until SVC, fault, or kick.
        let reason = match restricted_enter(vspace_cptr) {
            Ok(r) => r,
            Err(_) => return -1,
        };

        match reason {
            exit_reason::SYSCALL => {
                // SAFETY: state frame is mapped and valid (bound earlier).
                let syscall_nr = unsafe { state.read_syscall_number() };
                let args = unsafe { state.read_syscall_args() };

                let result = dispatch_linux_syscall(syscall_nr, &args, mm);

                // Write return value to x0
                // SAFETY: state frame is mapped and valid.
                unsafe { state.write_return_value(result as u64) };

                // Check for exit
                if syscall_nr == 94 || syscall_nr == 93 {
                    // exit_group (94) or exit (93)
                    return args[0] as i32;
                }
            }
            exit_reason::EXCEPTION => {
                // SAFETY: state frame is mapped and valid.
                let far = unsafe { state.read_far() };
                let esr = unsafe { state.read_esr() };

                if !handle_exception(far, esr, mm) {
                    // Unhandled exception — terminate with signal
                    return -1;
                }
            }
            exit_reason::KICK => {
                // Check for pending signals or exit requests
                // TODO: signal delivery
            }
            _ => {
                return -1;
            }
        }
    }
}

// -- Syscall dispatch (Phase 1: minimal set for static hello-world)

fn dispatch_linux_syscall(nr: u64, args: &[u64; 6], mm: &mut MemoryManager) -> i64 {
    match nr {
        // ioctl(fd, cmd, arg) — NR 29
        29 => 0, // Stub

        // write(fd, buf, count) — NR 64
        64 => handle_write(args[0], args[1], args[2], mm),

        // writev(fd, iov, iovcnt) — NR 66
        66 => handle_writev(args[0], args[1], args[2], mm),

        // exit(status) — NR 93
        93 => 0,

        // exit_group(status) — NR 94
        94 => 0,

        // set_tid_address(tidptr) — NR 96
        96 => 1, // Return tid=1

        // clock_gettime(clk_id, tp) — NR 113
        113 => 0, // Stub

        // rt_sigaction(signum, act, oldact, sigsetsize) — NR 134
        134 => 0, // Stub

        // rt_sigprocmask(how, set, oldset, sigsetsize) — NR 135
        135 => 0, // Stub

        // brk(addr) — NR 214
        214 => mm.handle_brk(args[0]) as i64,

        // munmap(addr, length) — NR 215
        215 => mm.handle_munmap(args[0], args[1]),

        // mmap(addr, length, prot, flags, fd, offset) — NR 222
        222 => mm.handle_mmap(args[0], args[1], args[2], args[3], args[4], args[5]),

        // mprotect(addr, len, prot) — NR 226
        226 => mm.handle_mprotect(args[0], args[1], args[2]),

        // prlimit64(pid, resource, new_rlim, old_rlim) — NR 261
        261 => 0, // Stub

        // getrandom(buf, buflen, flags) — NR 278
        278 => handle_getrandom(args[0], args[1], args[2], mm),

        // Unknown syscall — return ENOSYS
        _ => -38,
    }
}

// -- Syscall implementations

fn handle_write(fd: u64, buf: u64, count: u64, mm: &MemoryManager) -> i64 {
    if fd != 1 && fd != 2 {
        return -9; // EBADF
    }

    if count == 0 {
        return 0;
    }

    // Cap at 4KB per call to avoid huge allocations
    let len = (count as usize).min(4096);
    let mut local_buf = alloc::vec![0u8; len];

    match mm.read_from_linux(buf, &mut local_buf) {
        Ok(()) => {
            // Route Linux fd 1/2 to the kernel debug console.
            // PTY emulation lands in stage 3; see docs/review-2026-05-24.md.
            let s = core::str::from_utf8(&local_buf).unwrap_or("<non-utf8>");
            debug_puts(s);
            len as i64
        }
        Err(_) => -14, // EFAULT
    }
}

fn handle_writev(fd: u64, iov_addr: u64, iovcnt: u64, mm: &mut MemoryManager) -> i64 {
    if fd != 1 && fd != 2 {
        return -9; // EBADF
    }

    if iovcnt == 0 {
        return 0;
    }

    // Each iovec is { void *iov_base; size_t iov_len; } = 16 bytes on 64-bit
    let cnt = (iovcnt as usize).min(16); // Cap to prevent excessive reads
    let iov_size = cnt * 16;
    let mut iov_buf = alloc::vec![0u8; iov_size];

    if mm.read_from_linux(iov_addr, &mut iov_buf).is_err() {
        return -14; // EFAULT
    }

    let mut total = 0i64;
    for i in 0..cnt {
        let base_off = i * 16;
        let base = u64::from_le_bytes(iov_buf[base_off..base_off + 8].try_into().unwrap());
        let len = u64::from_le_bytes(iov_buf[base_off + 8..base_off + 16].try_into().unwrap());

        if len > 0 {
            let result = handle_write(fd, base, len, mm);
            if result < 0 {
                return if total > 0 { total } else { result };
            }
            total += result;
        }
    }

    total
}

fn handle_getrandom(buf: u64, buflen: u64, _flags: u64, mm: &mut MemoryManager) -> i64 {
    if buflen == 0 {
        return 0;
    }

    let len = (buflen as usize).min(256);
    let mut local_buf = alloc::vec![0u8; len];

    // Fill from the M6 kernel RNG (GetRandom: RNDR when available, else
    // timer-mixed entropy). Capped at 256 bytes per call by the kernel, which we
    // already respect via the .min(256) above. On failure leave the buffer zero.
    let _ = m6_syscall::invoke::get_random(&mut local_buf);

    // Write back to Linux address space
    // We need to find the frame for each page and use frame_write
    let mut written = 0usize;
    let mut addr = buf;
    while written < len {
        let page_addr = addr & !0xFFF;
        let page_offset = (addr - page_addr) as usize;
        let remaining = len - written;
        let available = 4096 - page_offset;
        let copy_len = remaining.min(available);

        if let Some(frame_slot) = mm.find_frame(page_addr) {
            let cptr = mm.frame_cptr(frame_slot);
            if m6_syscall::invoke::frame_write(
                cptr,
                page_offset as u64,
                local_buf[written..].as_ptr(),
                copy_len,
            )
            .is_err()
            {
                return -14; // EFAULT
            }
        } else {
            return -14; // EFAULT — page not mapped
        }

        written += copy_len;
        addr += copy_len as u64;
    }

    len as i64
}

// -- Exception handling

fn handle_exception(far: u64, esr: u64, mm: &mut MemoryManager) -> bool {
    // ESR exception class is bits [31:26]
    let ec = (esr >> 26) & 0x3F;

    match ec {
        // 0x20: instruction abort from lower EL
        // 0x24: data abort from lower EL
        0x20 | 0x24 => {
            // DFSC/IFSC is bits [5:0]
            let fsc = esr & 0x3F;

            match fsc {
                // Translation fault (levels 0-3): demand paging
                0x04..=0x07 => {
                    let is_write = ec == 0x24 && (esr & (1 << 6)) != 0; // WnR bit
                    mm.handle_page_fault(far, is_write)
                }
                // Permission fault (levels 1-3): could be COW
                0x09..=0x0F => {
                    let is_write = (esr & (1 << 6)) != 0;
                    if is_write {
                        // TODO: COW resolution
                        false
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

// -- Forked-Starnix dispatch loop (M3 #1 + M4)
//
// The faithful path: run a Linux thread in restricted mode and route each
// syscall trap through the *forked* Starnix `dispatch_syscall` against a real
// `CurrentTask`, instead of the native hand-coded `dispatch_linux_syscall`.
//
// `state` must be the StateFrame bound to the current M6 thread (via
// `restricted_bind_state`) and mapped read/write in this service's VSpace.
// `current_task` must already be constructed (mm bound to its process VSpace, an
// fd table, etc.) and its `thread_state.registers` initialised with the entry
// point and stack pointer.
//
// Returns the process exit code (from `exit`/`exit_group`).
/// Collapse a Linux `ExitStatus` into the single exit code the loop returns to
/// svc-starnix. A normal exit yields its code; death by signal yields the shell
/// convention `128 + signo` so a SIGSEGV-killed binary is distinguishable.
fn exit_code_from_status(status: &ExitStatus) -> i32 {
    match status {
        ExitStatus::Exit(code) => *code as i32,
        ExitStatus::Kill(si) | ExitStatus::CoreDump(si) => 128 + si.signal.number() as i32,
        _ => -1,
    }
}

pub fn run_starnix_task_loop(
    locked: &mut starnix_sync::Locked<starnix_sync::Unlocked>,
    current_task: &mut crate::task::CurrentTask,
    state: &StateFrame,
) -> i32 {
    use m6_syscall::invoke::restricted_enter;
    use starnix_syscalls::decls::SyscallDecl;

    let vspace_cptr = current_task.thread_group().process.vspace_cptr();

    loop {
        // Load the task's register state into the hardware restricted-mode frame.
        // SAFETY: `state` is bound and mapped read/write (caller invariant).
        unsafe {
            state.write_zx_state(&current_task.thread_state.registers);
        }

        let reason = match restricted_enter(vspace_cptr) {
            Ok(r) => r,
            Err(_) => return -1,
        };

        // Sync the hardware frame back into the task's register state.
        // SAFETY: `state` is bound and mapped read/write (caller invariant).
        let regs = unsafe { state.read_zx_state() };
        current_task.thread_state.registers.load(regs);

        match reason {
            exit_reason::SYSCALL => {
                let nr = current_task.thread_state.registers.syscall_register();
                // Capture the exit code (x0 at the `svc`) before the return value
                // overwrites it.
                let exit_code = current_task.thread_state.registers.return_register() as i32;

                let decl = SyscallDecl::from_number(nr, current_task.thread_state.arch_width());
                let syscall = crate::arch::execution::new_syscall(decl, current_task);

                let result = crate::syscall_table::dispatch_syscall(locked, current_task, &syscall);

                #[cfg(feature = "starnix-debug")]
                {
                    let rv = match &result {
                        Ok(v) => v.value() as i64,
                        Err(e) => e.return_value() as i64,
                    };
                    let msg = m6_starnix_std::format!(
                        "[starnix] syscall {} {} ({:#x}, {:#x}, {:#x}) -> {:#x}\n",
                        nr,
                        decl.name(),
                        syscall.arg0.raw(),
                        syscall.arg1.raw(),
                        syscall.arg2.raw(),
                        rv,
                    );
                    debug_puts(&msg);
                }

                match result {
                    Ok(rv) => {
                        current_task
                            .thread_state
                            .registers
                            .set_return_register(rv.value());
                    }
                    Err(errno) => {
                        // An errno return is the normal syscall-failure path
                        // (e.g. ioctl -> ENOTTY when probing a non-tty), not a
                        // fault — hand it back to the caller without tracing.
                        current_task
                            .thread_state
                            .registers
                            .set_return_register(errno.return_value());
                    }
                }

                // exit (93) / exit_group (94) terminate the thread.
                if nr == 93 || nr == 94 {
                    return exit_code;
                }
            }
            exit_reason::EXCEPTION => {
                // Translate the M6 CPU fault (FAR/ESR) into a Linux signal and
                // deliver it through the forked signal machinery: a memory abort
                // runs the real `MemoryManager::handle_page_fault` (which also
                // grows GROWSDOWN stacks), and an uncaught fatal signal
                // terminates the task with the correct wait status.
                // SAFETY: `state` is bound and mapped read/write (caller invariant).
                let (far, esr, pc) =
                    unsafe { (state.read_far(), state.read_esr(), state.read_pc()) };
                #[cfg(feature = "starnix-debug")]
                {
                    let msg = m6_starnix_std::format!(
                        "[starnix] EXCEPTION far={:#x} esr={:#x} pc={:#x}\n",
                        far,
                        esr,
                        pc
                    );
                    debug_puts(&msg);
                }
                let _ = pc;

                let arch = zx::ExceptionArchData {
                    esr: esr as u32,
                    far,
                };
                let ec = ((esr >> 26) & 0b11_1111) as u8;
                // Instruction abort (0x20/0x21) or data abort (0x24/0x25) from a
                // lower EL — i.e. a guest memory fault.
                let is_abort = matches!(ec, 0x20 | 0x21 | 0x24 | 0x25);

                let siginfo = if is_abort {
                    let decoded = crate::arch::task::decode_page_fault_exception_report(&arch);
                    // Synthesise the Zircon-style error code the forked handler
                    // keys on: permission faults (DFSC 0b0011xx) → ACCESS_DENIED;
                    // alignment fault (0b100001) → OUT_OF_RANGE (SIGBUS); other
                    // (translation) faults → NOT_FOUND.
                    let dfsc = (esr as u32) & 0b11_1111;
                    let error_code = match dfsc {
                        0b00_1100..=0b00_1111 => zx::Status::ACCESS_DENIED,
                        0b10_0001 => zx::Status::OUT_OF_RANGE,
                        _ => zx::Status::NOT_FOUND,
                    };
                    match current_task.mm() {
                        Ok(mm) => match mm.handle_page_fault(locked, decoded, error_code) {
                            // Resolved in-handler (e.g. growsdown stack extended):
                            // retry the faulting instruction by re-entering.
                            ExceptionResult::Handled => continue,
                            ExceptionResult::Signal(si) => si,
                        },
                        Err(_) => SignalInfo::with_detail(
                            SIGSEGV,
                            SI_KERNEL as i32,
                            SignalDetail::SigFault { addr: far },
                        ),
                    }
                } else if let Some(sig) = crate::arch::task::get_signal_for_general_exception(&arch)
                {
                    // Floating-point / SIMD exception → SIGFPE.
                    SignalInfo::with_detail(
                        sig,
                        SI_KERNEL as i32,
                        SignalDetail::SigFault { addr: far },
                    )
                } else {
                    // Undefined instruction or any other unexpected class → SIGILL.
                    SignalInfo::with_detail(
                        SIGILL,
                        SI_KERNEL as i32,
                        SignalDetail::SigFault { addr: far },
                    )
                };

                send_standard_signal(locked, &current_task.task, siginfo);
                dequeue_signal(locked, current_task);

                if current_task.is_exitted() {
                    return current_task
                        .exit_status()
                        .map_or(-1, |s| exit_code_from_status(&s));
                }
                // Otherwise a handler was installed; the loop re-enters at it.
            }
            exit_reason::KICK => {
                // TODO(M4): deliver pending signals before resuming.
            }
            _ => return -1,
        }
    }
}
