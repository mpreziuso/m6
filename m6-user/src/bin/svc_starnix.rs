//! svc-starnix — Linux binary supervisor.
//!
//! One M6 process per Linux binary. The shell resolves the Linux ELF from the
//! initrd and maps it (plus a small boot-info page) into our VSpace before
//! resuming us — see `m6_system::STARNIX_BOOTELF_*`. This avoids depending on
//! the NVMe being provisioned, which it is not at flash time. We then allocate
//! a fresh VSpace + ASID + state-frame for the Linux client and enter the
//! m6-starnix syscall loop (restricted-mode trap path).
//!
//! Spawned by `shell` with these inherited caps:
//!   slot 13 = ASID_POOL     (to assign ASID to the Linux VSpace)
//!   slot 15 = UNTYPED       (shell-granted; backs BOTH our heap — m6-std's
//!                            M6PagePool also draws from slot 15 — and the Linux
//!                            process we run. The shell revokes+resets this
//!                            untyped after we exit, so repeated `linux …` runs
//!                            in one boot do not drain init's one-way memory
//!                            server.)
//!
//! Layout of svc-starnix's own CSpace:
//!   slot 18 = L2 PT for state-frame mapping (svc-starnix's own VSpace)
//!   slot 19 = L3 PT for state-frame mapping
//!   slot 20 = state-frame Frame
//!   slot 21+ = m6-starnix MemoryManager allocates here (grows down from the
//!              top slot; heap grows up from slot 136 — no collision)

#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate std;

use std::println;

use m6_cap::ObjectType;
use m6_starnix::boot::{StarnixBootConfig, run_linux_binary_via_starnix};
use m6_system::{invoke, slot_to_cptr};

// -- Capability slot layout

const CNODE_RADIX: u8 = 12;

const ASID_POOL_SLOT: u64 = 13;

// The untyped backing all of svc-starnix's allocations. The shell grants this at
// slot 15 (the same slot m6-std's heap allocator uses), so our heap, the Linux
// ELF/stack/brk, and the state frame all draw from one region the shell revokes
// after we exit. We do NOT request a separate untyped from init's memory server.
const UNTYPED_SLOT: u64 = 15;
const STATE_FRAME_L2_SLOT: u64 = 18;
const STATE_FRAME_L3_SLOT: u64 = 19;
const STATE_FRAME_SLOT: u64 = 20;
const FIRST_FREE_SLOT: u64 = 21;

/// Where the state-frame is mapped in svc-starnix's OWN VSpace so the
/// syscall loop can read x8 / write x0 directly via pointer.
///
/// The m6-std heap covers [0x4000_0000, 0x4800_0000). 0x8000_0000 is
/// well clear of it; the L1 page table for the [0, 512GB) region is
/// already installed (the heap lives there), so we only need to
/// allocate L2 + L3 + the Frame itself.
const STATE_FRAME_VADDR: u64 = 0x8000_0000;

fn cptr(slot: u64) -> u64 {
    slot_to_cptr(slot, CNODE_RADIX)
}

// -- argv parsing (matches cat.rs / echo.rs convention)

/// Return argv[1..] from the page mapped by the shell at startup_arg().
///
/// The shell builds the page as `argv[0]="svc-starnix"`, `argv[1..]=<command>`.
/// Dropping argv[0] yields the Linux command line: `linux busybox ls /` becomes
/// `["busybox", "ls", "/"]`. The ELF itself is resolved by the shell and handed
/// over via [`read_boot_elf`].
///
/// # Safety
/// `startup_arg()` must be 0 or a valid ARGS_PAGE_ADDR from the shell.
unsafe fn get_linux_argv() -> std::vec::Vec<&'static [u8]> {
    let mut out: std::vec::Vec<&'static [u8]> = std::vec::Vec::new();
    let args_ptr = std::rt::startup_arg();
    if args_ptr == 0 {
        return out;
    }
    // SAFETY: shell maps the argv page before resuming us
    let argc = unsafe { *(args_ptr as *const u64) } as usize;
    // Skip argv[0] (= "svc-starnix"); argv[1..] is the Linux command line.
    for i in 1..argc {
        // SAFETY: argv pointers live at offset 8 + i*8 in the page
        let ptr = unsafe { *((args_ptr + 8 + (i as u64) * 8) as *const *const u8) };
        if ptr.is_null() {
            continue;
        }
        let mut len = 0usize;
        // SAFETY: null-terminated string in argv page
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` bytes of valid string data in the argv page
        out.push(unsafe { core::slice::from_raw_parts(ptr, len) });
    }
    out
}

// -- Boot ELF hand-off

/// Read the Linux ELF the shell mapped into our VSpace.
///
/// The shell resolves the binary from the initrd and maps it at
/// `STARNIX_BOOTELF_DATA_ADDR`, with a boot-info page at
/// `STARNIX_BOOTELF_INFO_ADDR` holding `[magic, elf vaddr, elf len]`.
fn read_boot_elf() -> Result<&'static [u8], &'static str> {
    let info = m6_system::STARNIX_BOOTELF_INFO_ADDR as *const u64;
    // SAFETY: the shell maps the info page R before resuming us.
    let (magic, data_addr, len) = unsafe { (*info, *info.add(1), *info.add(2) as usize) };
    if magic != m6_system::STARNIX_BOOTELF_MAGIC {
        return Err("boot-info magic mismatch (shell did not hand over an ELF)");
    }
    // SAFETY: the shell maps `len` bytes of the ELF at `data_addr` R.
    Ok(unsafe { core::slice::from_raw_parts(data_addr as *const u8, len) })
}

// -- Capability allocation for the Linux process

/// Retype + map the Linux VSpace, ASID, and state-frame.
///
/// The L1 page table covering [0, 512 GB) in svc-starnix's VSpace
/// already exists (m6-std heap at 0x4000_0000 lives in the same L1).
/// We allocate L2 and L3 page tables for STATE_FRAME_VADDR and map
/// the state-frame as R+W normal memory.
fn allocate_linux_resources() -> Result<(), &'static str> {
    // The Linux VSpace + ASID are created by the forked Starnix bootstrap
    // (`zx::mem_context::create_vspace`); here we only set up the restricted-mode
    // state frame in svc-starnix's OWN VSpace so the syscall loop can read/write
    // the trapped register state by pointer.

    // 3) L2 page table in svc-starnix's OWN VSpace (slot 2) for state-frame
    invoke::retype(
        cptr(UNTYPED_SLOT),
        ObjectType::PageTableL2 as u64,
        0,
        cptr(0),
        STATE_FRAME_L2_SLOT,
        1,
    )
    .map_err(|_| "retype state-frame L2 failed")?;
    invoke::map_page_table(cptr(2), cptr(STATE_FRAME_L2_SLOT), STATE_FRAME_VADDR, 2)
        .map_err(|_| "map_page_table L2 failed")?;

    // 4) L3 page table
    invoke::retype(
        cptr(UNTYPED_SLOT),
        ObjectType::PageTableL3 as u64,
        0,
        cptr(0),
        STATE_FRAME_L3_SLOT,
        1,
    )
    .map_err(|_| "retype state-frame L3 failed")?;
    invoke::map_page_table(cptr(2), cptr(STATE_FRAME_L3_SLOT), STATE_FRAME_VADDR, 3)
        .map_err(|_| "map_page_table L3 failed")?;

    // 5) State-frame (4 KiB), mapped R+W in svc-starnix's VSpace
    invoke::retype(
        cptr(UNTYPED_SLOT),
        ObjectType::Frame as u64,
        12, // 4 KiB
        cptr(0),
        STATE_FRAME_SLOT,
        1,
    )
    .map_err(|_| "retype state-frame Frame failed")?;
    invoke::map_frame(
        cptr(2),
        cptr(STATE_FRAME_SLOT),
        STATE_FRAME_VADDR,
        0b011, // R+W
        0,     // default cacheable attributes
    )
    .map_err(|_| "map_frame state-frame failed")?;

    // 6) Zero the state frame so kernel reads of unset registers see 0.
    // SAFETY: we just mapped 4 KiB at STATE_FRAME_VADDR.
    unsafe {
        core::ptr::write_bytes(STATE_FRAME_VADDR as *mut u8, 0, 4096);
    }

    Ok(())
}

// -- Entry point

#[unsafe(no_mangle)]
fn main() -> i32 {
    // SAFETY: startup_arg() is 0 or valid ARGS_PAGE_ADDR from the shell
    let linux_argv = unsafe { get_linux_argv() };
    let Some(&first) = linux_argv.first() else {
        println!("usage: linux <binary> [args...]");
        return 1;
    };
    let filename = core::str::from_utf8(first).unwrap_or("<binary>");

    println!("[svc-starnix] Loading Linux binary: {}", filename);

    let elf_data = match read_boot_elf() {
        Ok(b) => b,
        Err(e) => {
            println!("[svc-starnix] {}", e);
            return 1;
        }
    };

    if let Err(e) = allocate_linux_resources() {
        println!("[svc-starnix] {}", e);
        return 1;
    }

    // Run the Linux binary via the FORKED Starnix core (the faithful ABI path).
    let config = StarnixBootConfig {
        untyped_slot: UNTYPED_SLOT,
        root_cnode_slot: 0, // self-ref CNode
        asid_pool_slot: ASID_POOL_SLOT,
        cnode_radix: CNODE_RADIX,
        first_free_slot: FIRST_FREE_SLOT,
        state_frame_vaddr: STATE_FRAME_VADDR,
        state_frame_slot: STATE_FRAME_SLOT,
    };

    let env: &[&[u8]] = &[b"PATH=/bin", b"HOME=/", b"TERM=linux", b"PWD=/"];

    match run_linux_binary_via_starnix(&config, elf_data, &linux_argv, env) {
        Ok(code) => {
            println!("[svc-starnix] Linux process exited with code {}", code);
            code
        }
        Err(e) => {
            println!("[svc-starnix] starnix error: {:?}", e);
            1
        }
    }
}
