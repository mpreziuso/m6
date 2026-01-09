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
fn panic(info: &PanicInfo) -> ! {
    // Print panic info if we have a console
    console::puts("\n\x1b[31m*** KERNEL PANIC ***\x1b[0m\n");
    if let Some(location) = info.location() {
        console::puts("  at ");
        console::puts(location.file());
        console::puts(":");
        // Print line number (simple decimal conversion)
        let line = location.line();
        let mut buf = [0u8; 10];
        let mut n = line;
        let mut i = 0;
        loop {
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
            if n == 0 { break; }
        }
        for j in (0..i).rev() {
            console::putc(buf[j]);
        }
        console::puts("\n");
    }
    if let Some(msg) = info.message().as_str() {
        console::puts("  ");
        console::puts(msg);
        console::puts("\n");
    }
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

    // Initialise scheduler
    m6_kernel::sched::init();

    // Create idle task for CPU 0
    let idle_ref = m6_kernel::sched::idle::create_idle_task(0)
        .expect("Failed to create idle task");
    m6_kernel::sched::init_cpu(0, idle_ref);

    // Initialise exception vectors
    exceptions::init();
    log::info!(
        "Exception vectors installed at {:#x}",
        exceptions::vector_table_address()
    );

    // Install syscall handler
    m6_kernel::syscall::init();

    // Initialise GIC with kernel virtual address from bootloader
    // SAFETY: Called once during init, gic_virt_base is valid kernel-mapped address
    unsafe {
        gic::init(boot_info.gic_virt_base.0);
    }
    log::info!("GIC initialised");

    // Initialise SMMU if present
    if let Some(smmu_config) = platform::platform().smmu_config() {
        log::info!(
            "SMMU detected at {:#x}, size {:#x}",
            smmu_config.base_addr,
            smmu_config.size
        );
        // Map SMMU registers to kernel address space
        let smmu_virt = memory::translate::phys_to_virt(smmu_config.base_addr);
        // SAFETY: Called once during init with valid platform-provided SMMU address
        match unsafe { m6_kernel::smmu::init(smmu_config.base_addr, smmu_virt) } {
            Ok(()) => {
                log::info!("SMMU initialised successfully");
                // TODO: Register event queue IRQ handler
                // gic::register_handler(smmu_config.event_irq, smmu_event_handler);
                // gic::enable_irq(smmu_config.event_irq);
            }
            Err(e) => {
                log::error!("SMMU initialisation failed: {:?}", e);
            }
        }
    } else {
        log::info!("No SMMU detected");
    }

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

    // Bootstrap root task from initrd
    match m6_kernel::cap::bootstrap::bootstrap_root_task_from_initrd(boot_info) {
        Ok(root_task) => {
            log::info!(
                "Root task bootstrapped: entry={:#x} caps={}",
                root_task.entry_point,
                root_task.cap_count
            );
            // Add root task to the scheduler's run queue
            m6_kernel::sched::insert_task(root_task.tcb_ref);
        }
        Err(e) => {
            log::error!("Failed to bootstrap root task: {:?}", e);
            log::warn!("Continuing without root task (kernel-only mode)");
        }
    }

    // Arm the timer
    timer::set_timer_ms(10);

    log::info!("Entering scheduler");

    // Pick the first task to run (root task if bootstrapped, otherwise idle)
    m6_kernel::sched::schedule();

    // Check if we have a real user task to run (not just idle)
    if let Some(tcb_ref) = m6_kernel::sched::current_task() {
        // Check if this is a user task (has a VSpace)
        let has_vspace = m6_kernel::cap::object_table::with_object(tcb_ref, |obj| {
            if obj.obj_type == m6_kernel::cap::object_table::KernelObjectType::Tcb {
                // SAFETY: We verified this is a TCB.
                let tcb = unsafe { &*obj.data.tcb_ptr };
                tcb.tcb.vspace.is_valid()
            } else {
                false
            }
        }).unwrap_or(false);

        if has_vspace {
            log::info!("Entering userspace for root task");
            // This doesn't return - jumps to userspace via eret
            m6_kernel::sched::enter_userspace();
        }
    }

    // Fallback: run idle loop if no user task
    log::info!("No user task, entering idle loop");
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
fn irq_handler(ctx: &mut exceptions::ExceptionContext) {
    // Dispatch to GIC (this calls timer_irq_handler, etc.)
    gic::dispatch_irq();

    // After handling all interrupts, check if we need to reschedule
    if m6_kernel::sched::should_reschedule() {
        m6_kernel::sched::timer_context_switch(ctx);
    }
}


/// Timer interrupt handler
fn timer_irq_handler(_intid: u32) {
    // Clear the timer interrupt
    timer::clear_timer();

    // Re-arm for 10ms tick
    timer::set_timer_ms(10);

    // Process sleeping tasks that need to be woken
    m6_kernel::sched::sleep::process_wakeups();

    // Process expired Timer kernel objects
    m6_kernel::sched::timer_queue::process_expirations();

    // Charge CPU time to current thread
    m6_kernel::sched::charge_current_thread();

    // Check if preemption is needed and request reschedule
    if m6_kernel::sched::should_preempt() {
        m6_kernel::sched::request_reschedule();
    }
}
