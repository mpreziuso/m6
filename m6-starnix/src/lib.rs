//! m6-starnix — Linux binary compatibility layer
//!
//! This crate provides Linux ABI emulation for M6, based on a fork of
//! Google Fuchsia's Starnix. It intercepts Linux syscalls from binaries
//! running in restricted mode and translates them into M6 capability
//! operations.
//!
//! # Architecture
//!
//! A static `aarch64-linux-musl` ELF runs at EL0 in a restricted VSpace; on a
//! Linux syscall trap the M6 kernel returns control to this service, which
//! translates the Linux syscall into M6 capability operations and resumes the
//! guest.
//!
//! # Modules
//!
//! Two layers coexist during bring-up:
//!
//! - **M6-native bring-up** (`loader`, `mm`, `syscall_loop`, [`run_linux_binary`])
//!   — the minimal hand-written enter/exit loop used by `svc_starnix` today.
//! - **Forked Starnix core** (`arch`, `task`, `vfs`, `mm_ref`, `signals`,
//!   `time`, `fs`, `device`, `security`, `ptrace`, `execution`, …) — the ported
//!   Fuchsia Starnix, behind the M6 shim crates. This is the production target;
//!   the M3 seams (register frame, VMO↔frame memory, VFS↔FAT32) and the M4 boot
//!   path will migrate `svc_starnix` onto it.

#![no_std]
#![recursion_limit = "512"]
// The forked Starnix tree is a large vendored port that is not yet warning-clean
// for the M6 target; silence the bring-up noise crate-wide for now.
#![allow(unused_imports, dead_code, unused_variables, unused_mut)]

extern crate alloc;
// The forked code uses the std module layout (`std::collections`, `std::sync`,
// …); `m6-starnix-std` mirrors it for no_std.
extern crate m6_starnix_std as std;

// -- Forked Starnix core (ported Fuchsia)
pub mod arch;
pub mod bpf;
pub mod device;
pub mod execution;
pub mod fs;
pub mod mm_ref;
pub mod mutable_state;
pub mod perf;
pub mod power;
pub mod ptrace;
pub mod security;
pub mod signals;
pub mod syscalls;
pub mod task;
pub mod time;
pub mod vdso;
pub mod vfs;
pub mod syscall_table;

// -- M4 first-light bootstrap (run a Linux ELF via the forked Starnix core)
pub mod boot;

// -- M6-native bring-up (used by svc_starnix until the M4 boot path lands)
pub mod loader;
pub mod mm;
pub mod syscall_loop;

use m6_syscall::invoke::restricted_bind_state;
use m6_syscall::slot_to_cptr;
use mm::MemoryManager;
use syscall_loop::StateFrame;

/// Configuration for running a Linux binary.
pub struct LinuxProcessConfig {
    /// VSpace capability for the Linux address space
    pub vspace_cptr: u64,
    /// Root CNode capability
    pub root_cnode: u64,
    /// Untyped memory capability
    pub ram_untyped: u64,
    /// CNode radix (log2 of number of slots)
    pub cnode_radix: u8,
    /// Next free capability slot
    pub next_free_slot: u64,
    /// Virtual address where the state frame is mapped in Starnix's VSpace
    pub state_frame_vaddr: u64,
    /// Frame capability slot for the state frame
    pub state_frame_slot: u64,
}

/// Run a Linux ELF binary to completion.
///
/// This is the bring-up entry point for Linux binary emulation. It:
/// 1. Loads the ELF binary into the Linux VSpace
/// 2. Builds the initial Linux user stack
/// 3. Sets up the state frame with entry point and stack pointer
/// 4. Runs the restricted-mode syscall loop until the process exits
///
/// Returns the process exit code.
pub fn run_linux_binary(
    config: &LinuxProcessConfig,
    elf_data: &[u8],
    args: &[&[u8]],
    env: &[&[u8]],
) -> Result<i32, &'static str> {
    // -- Set up the memory manager for the Linux VSpace
    let mut mm = MemoryManager::new(
        config.vspace_cptr,
        config.root_cnode,
        config.ram_untyped,
        config.cnode_radix,
        config.next_free_slot,
        0, // brk will be set after ELF load
    );

    // -- Load the ELF binary
    let loaded = loader::load_elf(&mut mm, elf_data)?;

    // Set brk base to top of loaded segments
    mm.set_brk(loaded.brk_base);

    // -- Build the Linux user stack
    let sp = loader::build_linux_stack(&mut mm, args, env, &loaded)?;

    // -- Set up the state frame
    let state = StateFrame {
        vaddr: config.state_frame_vaddr,
        frame_slot: config.state_frame_slot,
    };

    // Bind the state frame to the current thread for restricted mode
    let frame_cptr = slot_to_cptr(config.state_frame_slot, config.cnode_radix);
    restricted_bind_state(frame_cptr).map_err(|_| "restricted_bind_state failed")?;

    // Set initial register state: ELR = entry, SP = stack top
    // SPSR = EL0t (0x0) — run in EL0 with interrupts enabled
    // SAFETY: The state frame is mapped at config.state_frame_vaddr by the caller.
    unsafe {
        state.write_pc(loaded.entry);
        state.write_sp(sp);
        state.write_spsr(0); // EL0t
    }

    // -- Run the syscall loop
    Ok(syscall_loop::run_syscall_loop(&state, &mut mm))
}
