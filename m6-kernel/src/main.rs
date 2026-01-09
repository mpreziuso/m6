//! Kernel Initialisation
//!
//! This module contains the kernel entry point and initialisation sequence.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;
use m6_arch::{cpu, exceptions};
use m6_common::boot::BootInfo;
use m6_kernel::logging::logger;
use m6_kernel::memory;
use m6_pal::{console, gic, platform, timer};


/// Panic handler for the kernel
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // TODO: Log panic info when we have a logger
    loop {
        cpu::halt();
    }
}


/// Kernel entry point called by the bootloader
///
/// # Safety
/// This function is called directly by the bootloader with a valid BootInfo pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(boot_info: *const BootInfo) -> ! {
    let boot_info = unsafe { &*boot_info };
    if !boot_info.is_valid() {
        #[allow(clippy::never_loop)]
        loop {
            cpu::halt();
        }
    }

    platform::init(boot_info);
    console::init_with_base(boot_info.uart_virt_base.0);

    print_banner();

    // Initialise timer before logging (for timestamps)
    timer::init();

    logger::init();

    log::info!("M6 Kernel starting...");

    // Initialise memory management (heap + frame allocator)
    // SAFETY: Called once during early init, boot_info is valid
    unsafe {
        memory::init_memory_from_boot_info(boot_info);
    }

    // Initialise exception vectors
    exceptions::init();
    log::info!(
        "Exception vectors installed at {:#x}",
        exceptions::vector_table_address()
    );

    // Initialise GIC with kernel virtual address from bootloader
    // SAFETY: Called once during init, gic_virt_base is valid kernel-mapped address
    unsafe {
        gic::init(boot_info.gic_virt_base.0);
    }
    log::info!("GIC initialised");

    // Set up timer IRQ
    let timer_irq = platform::platform().timer_irq();
    gic::register_handler(timer_irq, timer_irq_handler);
    gic::set_priority(timer_irq, 0x80);
    gic::enable_irq(timer_irq);
    log::info!("Timer IRQ {} enabled", timer_irq);

    // Register IRQ dispatcher with exception system
    exceptions::set_irq_handler(irq_handler);

    // Enable IRQs at CPU level
    gic::irq_enable();

    // Arm the timer
    timer::set_timer_ms(10);

    log::info!("Entering idle loop with interrupts enabled");

    loop {
        cpu::wait_for_interrupt();
    }
}


fn print_banner() {
    console::puts("\n");
    console::puts("\x1b[36m");  // Cyan
    console::puts("\n");
    console::puts("  ███╗   ███╗ ██████╗ \n");
    console::puts("  ████╗ ████║██╔════╝ \n");
    console::puts("  ██╔████╔██║███████╗ \n");
    console::puts("  ██║╚██╔╝██║██╔═══██╗\n");
    console::puts("  ██║ ╚═╝ ██║╚██████╔╝\n");
    console::puts("  ╚═╝     ╚═╝ ╚═════╝ \n");
    console::puts("\x1b[0m");
    console::puts("\n");
    console::puts(" m6 - version 0.1.0\n");
    console::puts("\n");
}


/// Main IRQ handler called from exception vector
fn irq_handler(_ctx: &mut exceptions::ExceptionContext) {
    gic::dispatch_irq();
}


/// Timer interrupt handler
fn timer_irq_handler(_intid: u32) {
    // Clear the timer interrupt
    timer::clear_timer();

    // Re-arm for 10ms tick
    timer::set_timer_ms(10);

    // TODO: Process sleeping tasks that need to be woken
}
