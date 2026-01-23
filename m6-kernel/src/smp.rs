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
    let stack_info = boot_info.cpu_stack(cpu).expect("CPU stack info not found");

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
    // boot_info is accessed via physmap (virtual address 0xFFFF_8000_xxxx_xxxx)
    // Convert back to physical address for secondary CPUs (they start with MMU off)
    let boot_info_virt = boot_info as *const _ as u64;
    let boot_info_phys = boot_info_virt - m6_common::boot::KERNEL_PHYS_MAP_BASE;

    (boot_info_phys << 16) | (cpu as u64 & 0xFFFF)
}

// Constants for secondary_entry_stub (must be outside the naked function)
use m6_common::boot::{
    BOOTINFO_PAGE_TABLE_BASE_OFFSET, BOOTINFO_PER_CPU_STACKS_OFFSET, BOOTINFO_TCR_OFFSET,
    BOOTINFO_TTBR0_OFFSET, KERNEL_PHYS_MAP_BASE, MAIR_VALUE, PER_CPU_STACK_INFO_SIZE,
    PER_CPU_STACK_VIRT_TOP_OFFSET,
};

/// Secondary CPU entry stub (called by PSCI after CPU_ON).
///
/// This is a naked function that sets up the MMU and stack, then jumps to Rust.
/// PSCI starts the CPU with MMU disabled, so we must:
/// 1. Detect exception level (EL1 or EL2)
/// 2. If EL2, configure for EL1 and drop to EL1
/// 3. Read BootInfo using physical addresses (MMU is off)
/// 4. Set up MMU with the same page tables as BSP
/// 5. Enable MMU
/// 6. Set stack pointer (now using virtual address)
/// 7. Jump to Rust entry point
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
        //   x21 = TTBR1
        //   x22 = TTBR0
        //   x23 = stack_virt_top
        //   x24 = scratch
        //   x25 = current EL
        //   x26 = TCR value (from boot_info)

        // -- Extract context
        "and x19, x0, #0xFFFF",        // x19 = cpu_id (lower 16 bits)
        "lsr x20, x0, #16",            // x20 = boot_info_phys (upper 48 bits)

        // -- Detect current exception level
        "mrs x25, CurrentEL",
        "lsr x25, x25, #2",            // x25 = current EL (2 bits)

        // -- Read MMU configuration from BootInfo (using physical addresses)
        // TTBR1 = boot_info.page_table_base
        "mov x24, {pt_offset}",
        "add x24, x20, x24",
        "ldr x21, [x24]",              // x21 = TTBR1 (page_table_base)

        // TTBR0 = boot_info.ttbr0_el1
        "mov x24, {ttbr0_offset}",
        "add x24, x20, x24",
        "ldr x22, [x24]",              // x22 = TTBR0

        // TCR = boot_info.tcr_el1 (has correct IPS for this CPU)
        "mov x24, {tcr_offset}",
        "add x24, x20, x24",
        "ldr x26, [x24]",              // x26 = TCR

        // -- Read stack virt_top for this CPU (save for after MMU enable)
        // Offset = per_cpu_stacks + cpu_id * 16 + 8
        "mov x24, {stack_offset}",
        "mov x23, {stack_size}",
        "mul x23, x19, x23",           // cpu_id * 16
        "add x24, x24, x23",
        "add x24, x24, {virt_top_offset}",
        "add x24, x20, x24",
        "ldr x23, [x24]",              // x23 = stack virt_top (save for later)

        // -- Branch based on exception level
        "cmp x25, #2",
        "b.eq 1f",                     // If EL2, go to EL2 path
        "b 2f",                        // Otherwise, EL1 path

        // ============================================================
        // EL2 path: Configure EL2 for EL1 and drop to EL1
        // ============================================================
        "1:",
        // Disable interrupts at EL2
        "msr daifset, #0xf",

        // HCR_EL2: RW=1 (EL1 is AArch64), SWIO=1
        "mov x24, #(1 << 31)",         // RW bit
        "orr x24, x24, #(1 << 1)",     // SWIO bit
        "msr hcr_el2, x24",

        // Enable EL1 timer access
        "mov x24, #3",
        "msr cnthctl_el2, x24",
        "msr cntvoff_el2, xzr",

        // Enable EL1 GIC access (ICC_SRE_EL2)
        "mov x24, #0xf",
        "msr s3_4_c12_c9_5, x24",
        "isb",

        // Set up EL1 MMU registers
        "ldr x24, ={mair}",
        "msr mair_el1, x24",

        "msr tcr_el1, x26",            // TCR from boot_info (in x26)

        "msr ttbr0_el1, x22",
        "msr ttbr1_el1, x21",

        "dsb sy",
        "isb",

        // Invalidate TLB
        "tlbi vmalle1",
        "dsb sy",
        "isb",

        // Invalidate instruction cache
        "ic iallu",
        "dsb sy",
        "isb",

        // Set up SCTLR_EL1 with MMU enabled
        "mov x24, #0",
        "orr x24, x24, #(1 << 0)",     // M bit (MMU enable)
        "orr x24, x24, #(1 << 2)",     // C bit (data cache)
        "orr x24, x24, #(1 << 12)",    // I bit (instruction cache)
        "orr x24, x24, #(1 << 26)",    // UCI bit (user cache instructions)
        "msr sctlr_el1, x24",

        // Set SP_EL1 for kernel stack
        "msr sp_el1, x23",

        // SPSR_EL2: Return to EL1h with interrupts masked
        "mov x24, #0x3c5",
        "msr spsr_el2, x24",

        // Calculate EL1 entry address (after the EL2 block)
        "adr x24, 3f",
        "msr elr_el2, x24",

        // Return to EL1
        "eret",

        // ============================================================
        // EL1 path: Direct MMU setup (QEMU or after EL2 drop)
        // ============================================================
        "2:",
        // -- Set up MMU registers at EL1
        "ldr x24, ={mair}",
        "msr MAIR_EL1, x24",

        "msr TCR_EL1, x26",            // TCR from boot_info (in x26)

        "msr TTBR0_EL1, x22",
        "msr TTBR1_EL1, x21",

        "isb",
        "dsb sy",

        // Invalidate TLB
        "tlbi vmalle1",
        "dsb sy",
        "isb",

        // Enable MMU via SCTLR_EL1
        "mrs x24, SCTLR_EL1",
        "orr x24, x24, #(1 << 0)",     // M bit
        "orr x24, x24, #(1 << 2)",     // C bit
        "orr x24, x24, #(1 << 12)",    // I bit
        "orr x24, x24, #(1 << 26)",    // UCI bit (user cache instructions)
        "msr SCTLR_EL1, x24",
        "isb",

        // Set stack pointer
        "mov sp, x23",

        // ============================================================
        // Common path: MMU enabled, at EL1
        // ============================================================
        "3:",
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
        tcr_offset = const BOOTINFO_TCR_OFFSET,
        stack_offset = const BOOTINFO_PER_CPU_STACKS_OFFSET,
        stack_size = const PER_CPU_STACK_INFO_SIZE,
        virt_top_offset = const PER_CPU_STACK_VIRT_TOP_OFFSET,
        mair = const MAIR_VALUE,
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
