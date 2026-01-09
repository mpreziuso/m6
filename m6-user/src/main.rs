//! M6 Init Process
//!
//! The initial userspace process that receives all system capabilities
//! from the kernel and bootstraps the rest of the system.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

mod io;

use core::panic::PanicInfo;
use m6_syscall::{
    invoke::sched_yield,
    UserBootInfo, USER_BOOT_INFO_ADDR, USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION,
};

/// Entry point - called by kernel with UserBootInfo address in x0.
///
/// # Safety
///
/// This function must be called only once as the entry point, with a valid
/// UserBootInfo pointer passed in x0.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    // The kernel passes UserBootInfo address in x0
    // We use a fixed address since the kernel maps it there
    let boot_info = unsafe { &*(USER_BOOT_INFO_ADDR as *const UserBootInfo) };

    // Validate boot info
    if boot_info.magic != USER_BOOT_INFO_MAGIC {
        io::puts("[init] ERROR: Invalid boot info magic!\n");
        loop {
            sched_yield();
        }
    }

    if boot_info.version != USER_BOOT_INFO_VERSION {
        io::puts("[init] ERROR: Boot info version mismatch!\n");
        loop {
            sched_yield();
        }
    }

    // Print banner
    io::puts("\n");
    io::puts("\x1b[32m"); // Green
    io::puts("[init] M6 Init starting\n");
    io::puts("\x1b[0m");  // Reset

    // Print platform info
    io::puts("[init] Platform ID: ");
    io::put_u64(boot_info.platform_id as u64);
    match boot_info.platform_id {
        1 => io::puts(" (QEMU ARM Virtual Machine)"),
        2 => io::puts(" (Radxa Rock 5B+)"),
        _ => io::puts(" (Unknown)"),
    }
    io::newline();

    // Print memory info
    io::puts("[init] Memory: ");
    io::put_u64(boot_info.free_memory / (1024 * 1024));
    io::puts(" MiB free / ");
    io::put_u64(boot_info.total_memory / (1024 * 1024));
    io::puts(" MiB total\n");

    // Print CPU info
    io::puts("[init] CPUs: ");
    io::put_u64(boot_info.cpu_count as u64);
    io::newline();

    // Print CNode info
    io::puts("[init] CNode radix: ");
    io::put_u64(boot_info.cnode_radix as u64);
    io::puts(" (");
    io::put_u64(1 << boot_info.cnode_radix);
    io::puts(" slots)\n");

    // Print untyped info
    if boot_info.untyped_count > 0 {
        io::puts("[init] Untyped regions: ");
        io::put_u64(boot_info.untyped_count as u64);
        io::newline();
    }

    io::puts("[init] Initialisation complete, entering idle loop\n");

    // Enter idle loop
    loop {
        sched_yield();
    }
}

/// Panic handler - print message and loop forever.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    io::puts("\n\x1b[31m*** INIT PANIC ***\x1b[0m\n");
    if let Some(location) = info.location() {
        io::puts("  at ");
        io::puts(location.file());
        io::puts(":");
        io::put_u64(location.line() as u64);
        io::newline();
    }
    if let Some(msg) = info.message().as_str() {
        io::puts("  ");
        io::puts(msg);
        io::newline();
    }
    loop {
        sched_yield();
    }
}
