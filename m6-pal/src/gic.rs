//! GIC (Generic Interrupt Controller) Management
//!
//! Provides interrupt controller abstraction supporting both GICv2 and GICv3.
//! The GIC version is detected at runtime from the Device Tree Blob.

use core::ptr::NonNull;

use arm_gic::gicv2::GicV2;
use arm_gic::gicv3::{GicCpuInterface, GicV3, InterruptGroup};
use arm_gic::{IntId, Trigger, UniqueMmioPointer};
use spin::Mutex;

use crate::dtb_platform::GicVersion;
use crate::platform;

/// Maximum number of interrupt handlers that can be registered
const MAX_HANDLERS: usize = 1024;

/// Interrupt handler function type
pub type IrqHandler = fn(intid: u32);

/// Userspace IRQ dispatcher function type
type UserspaceDispatcher = Option<fn(u32) -> bool>;

/// Static storage for registered interrupt handlers
/// Index is the interrupt ID (INTID)
static IRQ_HANDLERS: Mutex<[Option<IrqHandler>; MAX_HANDLERS]> =
    Mutex::new([None; MAX_HANDLERS]);

/// Callback for userspace IRQ dispatch.
///
/// When set, this function is called for interrupts that don't have
/// a kernel-registered handler. Returns true if the interrupt was handled.
static USERSPACE_DISPATCHER: Mutex<UserspaceDispatcher> = Mutex::new(None);

/// GIC driver abstraction supporting both v2 and v3
enum GicDriver {
    V2(GicV2<'static>),
    V3(GicV3<'static>),
    Uninitialised,
}

// SAFETY: GIC registers are accessed through proper synchronisation.
// GicV2 and GicV3 contain raw pointers but we protect access with a Mutex.
unsafe impl Send for GicDriver {}
unsafe impl Sync for GicDriver {}

/// Global GIC driver instance
static GIC: Mutex<GicDriver> = Mutex::new(GicDriver::Uninitialised);

/// Re-export CPU-level IRQ control from arm_gic
pub use arm_gic::{irq_disable, irq_enable};

/// Initialise the GIC based on detected version
///
/// # Arguments
/// * `gic_virt_base` - Kernel virtual address where GIC is mapped (from BootInfo)
///
/// # Safety
///
/// - Must be called exactly once during kernel initialisation
/// - Must be called after `platform::init()`
/// - `gic_virt_base` must be a valid kernel-mapped address for the GIC
pub unsafe fn init(gic_virt_base: u64) {
    let plat = platform::platform();
    let version = plat.gic_version();

    // Calculate virtual addresses for GIC components
    let gicd_phys = plat.gic_distributor_base();
    let gicc_phys = plat.gic_cpu_base();
    let gicr_phys = plat.gic_redistributor_base();

    let gicd_virt = gic_virt_base;
    let gicc_virt = gic_virt_base.wrapping_add(gicc_phys.wrapping_sub(gicd_phys));
    let gicr_virt = gic_virt_base.wrapping_add(gicr_phys.wrapping_sub(gicd_phys));

    let mut gic = GIC.lock();

    match version {
        GicVersion::V2 => {
            // SAFETY: Addresses are kernel-mapped device memory from bootloader.
            // No other code accesses these registers. Caller guarantees valid addresses.
            let driver = unsafe { init_gicv2(gicd_virt, gicc_virt) };
            *gic = GicDriver::V2(driver);
        }
        GicVersion::V3 => {
            // SAFETY: Addresses are kernel-mapped device memory from bootloader.
            // No other code accesses these registers. Caller guarantees valid addresses.
            let driver = unsafe { init_gicv3(gicd_virt, gicr_virt) };
            *gic = GicDriver::V3(driver);
        }
        GicVersion::Unknown => {
            panic!("Unknown GIC version - cannot initialise interrupt controller");
        }
    }
}

/// Initialise GICv2
///
/// # Safety
/// - `gicd_virt` and `gicc_virt` must be valid kernel-mapped device memory addresses
unsafe fn init_gicv2(gicd_virt: u64, gicc_virt: u64) -> GicV2<'static> {
    use arm_gic::gicv2::registers::{Gicc, Gicd};

    let gicd_ptr = gicd_virt as *mut Gicd;
    let gicc_ptr = gicc_virt as *mut Gicc;

    // SAFETY: Pointers are to kernel-mapped device memory.
    // Caller guarantees exclusive access and valid mapping.
    let mut gic = unsafe { GicV2::new(gicd_ptr, gicc_ptr) };

    gic.setup();
    gic.set_priority_mask(0xFF); // Accept all priorities

    gic
}

/// Initialise GICv3
///
/// # Safety
/// - `gicd_virt` and `gicr_virt` must be valid kernel-mapped device memory addresses
unsafe fn init_gicv3(gicd_virt: u64, gicr_virt: u64) -> GicV3<'static> {
    use arm_gic::gicv3::registers::{Gicd, GicrSgi};

    let gicd_ptr = NonNull::new(gicd_virt as *mut Gicd)
        .expect("GIC distributor address is null");
    let gicr_ptr = NonNull::new(gicr_virt as *mut GicrSgi)
        .expect("GIC redistributor address is null");

    // SAFETY: Pointers are to kernel-mapped device memory.
    // Caller guarantees exclusive access and valid mapping.
    let gicd = unsafe { UniqueMmioPointer::new(gicd_ptr) };

    // cpu_count = 1 for boot CPU, gic_v4 = false (no virtualisation support needed)
    let mut gic = unsafe { GicV3::new(gicd, gicr_ptr, 1, false) };

    // Setup for boot CPU (cpu 0)
    gic.setup(0);

    // Configure CPU interface via system registers
    GicCpuInterface::set_priority_mask(0xFF); // Accept all priorities
    GicCpuInterface::enable_group1(true);

    gic
}

/// Initialise GIC for a secondary CPU.
///
/// Called by secondary CPUs during their initialisation to set up their
/// redistributor (GICv3) or CPU interface (GICv2).
///
/// # Arguments
/// * `cpu_id` - The CPU ID (0-7)
///
/// # Safety
/// Must be called once per secondary CPU during its init sequence,
/// after the primary CPU has initialised the GIC.
pub unsafe fn init_secondary_cpu(cpu_id: usize) {
    let mut gic = GIC.lock();

    match &mut *gic {
        GicDriver::V3(driver) => {
            // Set up redistributor for this CPU
            driver.setup(cpu_id);
            // Enable CPU interface via system registers
            GicCpuInterface::set_priority_mask(0xFF);
            GicCpuInterface::enable_group1(true);
        }
        GicDriver::V2(_) => {
            // GICv2 CPU interface is banked per-CPU, accessed at same address
            // Just need to configure the local CPU interface
            // The distributor was already configured by CPU 0
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised - cannot init secondary CPU");
        }
    }
}

/// Enable an interrupt
///
/// # Arguments
/// * `intid` - The interrupt ID (INTID) to enable
pub fn enable_irq(intid: u32) {
    let mut gic = GIC.lock();
    let int_id = intid_from_raw(intid);

    match &mut *gic {
        GicDriver::V2(driver) => {
            let _ = driver.enable_interrupt(int_id, true);
        }
        GicDriver::V3(driver) => {
            let _ = driver.enable_interrupt(int_id, Some(0), true);
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Disable an interrupt
///
/// # Arguments
/// * `intid` - The interrupt ID (INTID) to disable
pub fn disable_irq(intid: u32) {
    let mut gic = GIC.lock();
    let int_id = intid_from_raw(intid);

    match &mut *gic {
        GicDriver::V2(driver) => {
            let _ = driver.enable_interrupt(int_id, false);
        }
        GicDriver::V3(driver) => {
            let _ = driver.enable_interrupt(int_id, Some(0), false);
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Set interrupt priority
///
/// # Arguments
/// * `intid` - The interrupt ID
/// * `priority` - Priority value (0 = highest, 255 = lowest)
pub fn set_priority(intid: u32, priority: u8) {
    let mut gic = GIC.lock();
    let int_id = intid_from_raw(intid);

    match &mut *gic {
        GicDriver::V2(driver) => {
            driver.set_interrupt_priority(int_id, priority);
        }
        GicDriver::V3(driver) => {
            let _ = driver.set_interrupt_priority(int_id, Some(0), priority);
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Set interrupt trigger mode
///
/// # Arguments
/// * `intid` - The interrupt ID
/// * `edge` - true for edge-triggered, false for level-sensitive
pub fn set_trigger(intid: u32, edge: bool) {
    let mut gic = GIC.lock();
    let int_id = intid_from_raw(intid);
    let trigger = if edge { Trigger::Edge } else { Trigger::Level };

    match &mut *gic {
        GicDriver::V2(driver) => {
            driver.set_trigger(int_id, trigger);
        }
        GicDriver::V3(driver) => {
            let _ = driver.set_trigger(int_id, Some(0), trigger);
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Acknowledge an interrupt and return its ID
///
/// Returns None if no interrupt is pending
fn acknowledge_interrupt() -> Option<u32> {
    let mut gic = GIC.lock();

    match &mut *gic {
        GicDriver::V2(driver) => driver.get_and_acknowledge_interrupt().map(|id| id.into()),
        GicDriver::V3(_) => {
            // GICv3 uses system registers via GicCpuInterface
            GicCpuInterface::get_and_acknowledge_interrupt(InterruptGroup::Group1)
                .map(|id| id.into())
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Signal end of interrupt processing
///
/// # Arguments
/// * `intid` - The interrupt ID that was acknowledged
fn end_interrupt(intid: u32) {
    let mut gic = GIC.lock();
    let int_id = intid_from_raw(intid);

    match &mut *gic {
        GicDriver::V2(driver) => {
            driver.end_interrupt(int_id);
        }
        GicDriver::V3(_) => {
            // GICv3 uses system registers via GicCpuInterface
            GicCpuInterface::end_interrupt(int_id, InterruptGroup::Group1);
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Register an interrupt handler
///
/// # Arguments
/// * `intid` - The interrupt ID to handle
/// * `handler` - Function to call when interrupt fires
pub fn register_handler(intid: u32, handler: IrqHandler) {
    if intid as usize >= MAX_HANDLERS {
        panic!("Interrupt ID {} exceeds maximum {}", intid, MAX_HANDLERS);
    }

    let mut handlers = IRQ_HANDLERS.lock();
    handlers[intid as usize] = Some(handler);
}

/// Unregister an interrupt handler
pub fn unregister_handler(intid: u32) {
    if (intid as usize) < MAX_HANDLERS {
        let mut handlers = IRQ_HANDLERS.lock();
        handlers[intid as usize] = None;
    }
}

/// Register a userspace IRQ dispatcher callback.
///
/// This callback is invoked for interrupts that don't have a kernel
/// handler registered. Typically used to dispatch IRQs to userspace
/// drivers via the capability system.
///
/// # Arguments
///
/// * `dispatcher` - Function that takes an INTID and returns true if handled
pub fn register_userspace_dispatcher(dispatcher: fn(u32) -> bool) {
    *USERSPACE_DISPATCHER.lock() = Some(dispatcher);
}

/// Dispatch an IRQ to its registered handler
///
/// This function is called from the IRQ exception handler.
/// It acknowledges the interrupt, calls the registered handler,
/// and signals end of interrupt.
pub fn dispatch_irq() {
    // Acknowledge and get interrupt ID
    let intid = match acknowledge_interrupt() {
        Some(id) => id,
        None => {
            // No pending interrupt - spurious
            return;
        }
    };

    // Check for special interrupt IDs (spurious)
    // INTIDs 1020-1023 are reserved/spurious
    if intid >= 1020 {
        return;
    }

    // Look up and call handler
    let handler = {
        let handlers = IRQ_HANDLERS.lock();
        handlers.get(intid as usize).and_then(|h| *h)
    };

    if let Some(handler) = handler {
        // Handler is called without holding any locks
        handler(intid);
    } else {
        // No kernel handler - try userspace dispatcher
        let dispatcher = { *USERSPACE_DISPATCHER.lock() };
        if let Some(dispatch_fn) = dispatcher {
            dispatch_fn(intid);
        }
    }

    // Signal end of interrupt
    end_interrupt(intid);
}

/// Convert raw interrupt ID to IntId type
///
/// IntId ranges:
/// - 0-15: SGI (Software Generated Interrupts)
/// - 16-31: PPI (Private Peripheral Interrupts)
/// - 32+: SPI (Shared Peripheral Interrupts)
fn intid_from_raw(intid: u32) -> IntId {
    if intid < 16 {
        IntId::sgi(intid)
    } else if intid < 32 {
        IntId::ppi(intid - 16)
    } else {
        IntId::spi(intid - 32)
    }
}

// -- IPI (Inter-Processor Interrupt) Support via SGIs

/// IPI types for inter-CPU communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpiType {
    /// Reschedule request - wake target CPU to check its run queue
    Reschedule = 0,
    /// Function call - reserved for future use
    CallFunction = 1,
    /// TLB shootdown - reserved for future use
    TlbShootdown = 2,
}

/// Send an IPI to a specific CPU.
///
/// Uses SGI (Software Generated Interrupt) to signal the target CPU.
///
/// # Arguments
/// * `target_cpu` - The CPU ID to send the IPI to (0-7)
/// * `ipi_type` - The type of IPI to send
pub fn send_ipi(target_cpu: usize, ipi_type: IpiType) {
    let sgi_id = ipi_type as u32;
    send_sgi_to_cpu(target_cpu, sgi_id);
}

/// Send an IPI to all other CPUs (broadcast).
///
/// # Arguments
/// * `ipi_type` - The type of IPI to send
pub fn send_ipi_broadcast(ipi_type: IpiType) {
    let sgi_id = ipi_type as u32;
    send_sgi_broadcast(sgi_id);
}

/// Send SGI to a specific CPU
fn send_sgi_to_cpu(target_cpu: usize, sgi_id: u32) {
    let gic = GIC.lock();

    match &*gic {
        GicDriver::V3(_) => {
            // GICv3: Use ICC_SGI1R_EL1 system register
            // Format: Aff3[55:48] | IRM[40] | Aff2[39:32] | INTID[27:24] |
            //         Aff1[23:16] | RS[7:4] | TargetList[15:0]
            //
            // For simple Aff0-only systems (like QEMU virt), we just set
            // the target bit in TargetList for the target CPU.
            let target_list = 1u64 << target_cpu;
            let sgi_value = ((sgi_id as u64) & 0xF) << 24 | target_list;

            // SAFETY: Writing to ICC_SGI1R_EL1 sends an SGI
            unsafe {
                core::arch::asm!(
                    "msr ICC_SGI1R_EL1, {0}",
                    in(reg) sgi_value,
                    options(nomem, nostack)
                );
            }
        }
        GicDriver::V2(_) => {
            panic!("SMP not supported on GICv2 platforms");
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Send SGI to all other CPUs (broadcast)
fn send_sgi_broadcast(sgi_id: u32) {
    let gic = GIC.lock();

    match &*gic {
        GicDriver::V3(_) => {
            // GICv3: IRM=1 (bit 40) means "all other PEs"
            let sgi_value = (1u64 << 40) | (((sgi_id as u64) & 0xF) << 24);

            // SAFETY: Writing to ICC_SGI1R_EL1 sends an SGI
            unsafe {
                core::arch::asm!(
                    "msr ICC_SGI1R_EL1, {0}",
                    in(reg) sgi_value,
                    options(nomem, nostack)
                );
            }
        }
        GicDriver::V2(_) => {
            panic!("SMP not supported on GICv2 platforms");
        }
        GicDriver::Uninitialised => {
            panic!("GIC not initialised");
        }
    }
}

/// Register the IPI handler for scheduler reschedule requests.
///
/// This should be called during kernel initialisation after the GIC is set up.
pub fn register_ipi_handler(handler: IrqHandler) {
    // SGI 0 is used for reschedule IPI
    register_handler(0, handler);
    enable_irq(0);
}
