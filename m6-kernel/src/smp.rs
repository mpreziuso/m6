//! Kernel SMP (Symmetric Multi-Processing) Initialisation
//!
//! Handles bringing up secondary CPUs and their scheduler state.
//! Uses PSCI to start secondary CPUs and coordinates their initialisation.

use m6_arch::smp;
use m6_common::boot::BootInfo;
use m6_pal::psci;

/// Boot secondary CPUs.
///
/// Called from BSP (CPU 0) after basic kernel initialisation is complete.
/// This function:
/// 1. Issues PSCI CPU_ON for each secondary CPU
/// 2. Waits for all CPUs to come online
/// 3. Releases them to complete initialisation
///
/// # Arguments
/// * `boot_info` - Boot information with CPU count and stack addresses
pub fn start_secondary_cpus(boot_info: &'static BootInfo) {
    let cpu_count = boot_info.cpu_count();

    if cpu_count <= 1 {
        log::info!("Single CPU system, skipping secondary CPU startup");
        return;
    }

    // Check PSCI availability
    let (major, minor) = psci::version();
    log::info!("PSCI version: {}.{}", major, minor);

    if major == 0 {
        log::warn!("PSCI not available, cannot start secondary CPUs");
        return;
    }

    log::info!("Starting {} secondary CPUs", cpu_count - 1);

    // Start each secondary CPU
    for cpu in 1..cpu_count {
        if let Err(e) = start_cpu(cpu, boot_info) {
            log::error!("Failed to start CPU {}: {:?}", cpu, e);
        }
    }

    // Wait for all CPUs to come online
    log::debug!("Waiting for secondary CPUs...");
    let mut spin_count = 0u32;
    while smp::cpus_online() < cpu_count as u32 {
        core::hint::spin_loop();
        spin_count += 1;
        if spin_count.is_multiple_of(1_000_000) {
            log::debug!(
                "Still waiting... {} of {} CPUs online",
                smp::cpus_online(),
                cpu_count
            );
        }
    }

    log::info!("All {} CPUs online", cpu_count);

    // Release secondary CPUs to complete initialisation
    smp::release_barrier(1);
}

/// Start a single secondary CPU.
fn start_cpu(cpu: usize, boot_info: &'static BootInfo) -> Result<(), psci::PsciError> {
    // Get stack info for this CPU
    let stack_info = boot_info
        .cpu_stack(cpu)
        .expect("CPU stack info not found");

    if !stack_info.is_valid() {
        log::error!("CPU {} has invalid stack info", cpu);
        return Err(psci::PsciError::InvalidParameters);
    }

    // Get the physical entry point for secondary CPUs
    // This is the secondary_entry function which will be linked at a known address
    let entry_phys = secondary_entry_phys(boot_info);

    // Encode boot info and CPU ID in context
    // The secondary CPU will decode this to find its stack and proceed
    let context = encode_secondary_context(cpu, boot_info);

    log::debug!(
        "Starting CPU {}: entry={:#x} stack_top={:#x} context={:#x}",
        cpu,
        entry_phys,
        stack_info.virt_top.as_u64(),
        context
    );

    // SAFETY: entry_phys is the address of secondary_entry_stub which is
    // valid executable code. The context encodes the CPU ID and boot_info
    // pointer for the secondary CPU to use.
    unsafe { psci::cpu_on(cpu as u64, entry_phys, context) }
}

/// Get the physical address of the secondary entry point.
///
/// The secondary entry stub is linked with the kernel, so we need to
/// convert its virtual address to physical.
fn secondary_entry_phys(boot_info: &BootInfo) -> u64 {
    // The secondary_entry_stub function's virtual address
    let entry_virt = secondary_entry_stub as *const () as u64;

    // Convert virtual to physical using kernel base addresses
    // Kernel virtual base: boot_info.kernel_virt_base
    // Kernel physical base: boot_info.kernel_phys_base
    let offset = entry_virt - boot_info.kernel_virt_base.as_u64();
    boot_info.kernel_phys_base.as_u64() + offset
}

/// Encode context passed to secondary CPU.
///
/// Format: | boot_info_phys (upper 48 bits) | cpu_id (lower 16 bits) |
fn encode_secondary_context(cpu: usize, boot_info: &BootInfo) -> u64 {
    // boot_info is accessed via TTBR0 identity mapping, so its pointer IS the physical address
    let boot_info_phys = boot_info as *const _ as u64;

    (boot_info_phys << 16) | (cpu as u64 & 0xFFFF)
}

// Constants for secondary_entry_stub (must be outside the naked function)
use m6_common::boot::{
    BOOTINFO_PAGE_TABLE_BASE_OFFSET, BOOTINFO_PER_CPU_STACKS_OFFSET,
    BOOTINFO_TTBR0_OFFSET, PER_CPU_STACK_INFO_SIZE, PER_CPU_STACK_VIRT_TOP_OFFSET,
    MAIR_VALUE, TCR_VALUE, KERNEL_PHYS_MAP_BASE,
};

/// Secondary CPU entry stub (called by PSCI after CPU_ON).
///
/// This is a naked function that sets up the MMU and stack, then jumps to Rust.
/// PSCI starts the CPU with MMU disabled, so we must:
/// 1. Read BootInfo using physical addresses (MMU is off)
/// 2. Set up MMU with the same page tables as BSP
/// 3. Enable MMU
/// 4. Set stack pointer (now using virtual address)
/// 5. Jump to Rust entry point
///
/// # Safety
/// This is called directly by PSCI firmware with x0 containing our context.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.smp")]
pub unsafe extern "C" fn secondary_entry_stub() -> ! {
    core::arch::naked_asm!(
        // x0 = context from PSCI (encodes cpu_id and boot_info_phys)
        // Registers used:
        //   x19 = cpu_id (preserved across calls)
        //   x20 = boot_info_phys (preserved across calls)
        //   x21 = scratch / TTBR1
        //   x22 = scratch / TTBR0
        //   x23 = scratch / stack_virt_top
        //   x24 = scratch

        // -- Extract context
        "and x19, x0, #0xFFFF",        // x19 = cpu_id (lower 16 bits)
        "lsr x20, x0, #16",            // x20 = boot_info_phys (upper 48 bits)

        // -- Read MMU configuration from BootInfo (using physical addresses)
        // TTBR1 = boot_info.page_table_base
        "mov x24, {pt_offset}",
        "add x24, x20, x24",
        "ldr x21, [x24]",              // x21 = TTBR1 (page_table_base)

        // TTBR0 = boot_info.ttbr0_el1
        "mov x24, {ttbr0_offset}",
        "add x24, x20, x24",
        "ldr x22, [x24]",              // x22 = TTBR0

        // -- Read stack virt_top for this CPU (save for after MMU enable)
        // Offset = per_cpu_stacks + cpu_id * 16 + 8
        "mov x24, {stack_offset}",
        "mov x23, {stack_size}",
        "mul x23, x19, x23",           // cpu_id * 16
        "add x24, x24, x23",
        "add x24, x24, {virt_top_offset}",
        "add x24, x20, x24",
        "ldr x23, [x24]",              // x23 = stack virt_top (save for later)

        // -- Set up MMU registers
        // Set MAIR_EL1
        "ldr x24, ={mair}",
        "msr MAIR_EL1, x24",

        // Set TCR_EL1
        "ldr x24, ={tcr}",
        "msr TCR_EL1, x24",

        // Set TTBR0_EL1 (identity mapping for transition)
        "msr TTBR0_EL1, x22",

        // Set TTBR1_EL1 (kernel mapping)
        "msr TTBR1_EL1, x21",

        // Ensure all writes complete before enabling MMU
        "isb",
        "dsb sy",

        // Invalidate TLB
        "tlbi vmalle1",
        "dsb sy",
        "isb",

        // -- Enable MMU via SCTLR_EL1
        "mrs x24, SCTLR_EL1",
        "orr x24, x24, #(1 << 0)",     // M bit (MMU enable)
        "orr x24, x24, #(1 << 2)",     // C bit (data cache enable)
        "orr x24, x24, #(1 << 12)",    // I bit (instruction cache enable)
        "msr SCTLR_EL1, x24",
        "isb",

        // -- MMU is now enabled, we can use virtual addresses

        // Set stack pointer (virtual address)
        "mov sp, x23",

        // Convert boot_info_phys to virtual address
        "ldr x24, ={phys_map_base}",
        "add x20, x20, x24",           // x20 = boot_info_virt

        // Call Rust entry point: secondary_entry_rust(cpu_id, boot_info_virt)
        "mov x0, x19",
        "mov x1, x20",
        "bl {secondary_entry_rust}",

        // Should never return
        "b .",

        pt_offset = const BOOTINFO_PAGE_TABLE_BASE_OFFSET,
        ttbr0_offset = const BOOTINFO_TTBR0_OFFSET,
        stack_offset = const BOOTINFO_PER_CPU_STACKS_OFFSET,
        stack_size = const PER_CPU_STACK_INFO_SIZE,
        virt_top_offset = const PER_CPU_STACK_VIRT_TOP_OFFSET,
        mair = const MAIR_VALUE,
        tcr = const TCR_VALUE,
        phys_map_base = const KERNEL_PHYS_MAP_BASE,
        secondary_entry_rust = sym secondary_entry_rust,
    );
}

/// Secondary CPU Rust entry point.
///
/// Called from assembly after stack and MMU are set up.
///
/// # Safety
/// Must be called with valid stack and MMU enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secondary_entry_rust(cpu_id: u64, boot_info_virt: u64) -> ! {
    let cpu = cpu_id as usize;

    // Enable FP/SIMD access before any other code (CPACR_EL1.FPEN = 0b11)
    // PSCI starts secondary CPUs with CPACR_EL1 = 0 which traps FP/SIMD
    m6_arch::cpu::enable_fp_simd();

    // Get boot_info reference
    // SAFETY: boot_info_virt was passed from BSP and is valid
    let boot_info = unsafe { &*(boot_info_virt as *const BootInfo) };

    // Initialise exception vectors for this CPU
    m6_arch::exceptions::init();

    // Signal that we're online
    smp::mark_cpu_online();

    log::info!("CPU {} online, waiting for barrier", cpu);

    // Wait for BSP to release us
    smp::wait_for_barrier(1);

    // Now complete full kernel initialisation for this CPU
    secondary_kernel_init(cpu, boot_info);
}

/// Complete kernel initialisation for a secondary CPU.
///
/// Called after the barrier is released, when it's safe to access
/// all kernel data structures.
fn secondary_kernel_init(cpu: usize, _boot_info: &BootInfo) -> ! {
    log::info!("CPU {} completing initialisation", cpu);

    // Initialise GIC redistributor for this CPU
    // SAFETY: This CPU's redistributor hasn't been initialised yet
    unsafe {
        m6_pal::gic::init_secondary_cpu(cpu);
    }

    // Create idle task for this CPU
    let idle_ref = crate::sched::idle::create_idle_task(cpu)
        .expect("Failed to create idle task for secondary CPU");
    crate::sched::init_cpu(cpu, idle_ref);

    // Enable interrupts
    m6_pal::gic::irq_enable();

    log::info!("CPU {} entering idle loop", cpu);

    // Enter idle loop - handle interrupts and scheduling
    loop {
        m6_arch::cpu::wait_for_interrupt();

        // Check for reschedule after interrupt
        if crate::sched::should_reschedule() {
            crate::sched::schedule();
        }
    }
}
