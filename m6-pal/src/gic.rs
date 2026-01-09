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

/// Static storage for registered interrupt handlers
/// Index is the interrupt ID (INTID)
static IRQ_HANDLERS: Mutex<[Option<IrqHandler>; MAX_HANDLERS]> =
    Mutex::new([None; MAX_HANDLERS]);

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
