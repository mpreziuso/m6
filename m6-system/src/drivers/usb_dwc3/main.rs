//! USB DWC3 Host Controller Driver for RK3588
//!
//! Userspace driver for DesignWare USB3 DRD controllers on the RK3588 SoC.
//! Operates in Host mode using the embedded xHCI controller.
//!
//! # RK3588 USB3 OTG Controllers
//!
//! | Controller | Address | PHY |
//! |------------|---------|-----|
//! | USB3OTG_0 | 0xFC000000 | USBDPPHY0 (0xFED70000) |
//! | USB3OTG_1 | 0xFC400000 | USBDPPHY1 (0xFED80000) |
//! | USB3OTG_2 | 0xFCD00000 | (uses USBDPPHY0 or 1) |
//!
//! # Capabilities received from device-mgr
//!
//! - Slot 10: DeviceFrame for DWC3 MMIO (controller + PHY combined)
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 13: IOSpace for DMA
//! - Slot 14: Notification for IRQ delivery
//! - Slot 15: SMMU control (if available)
//! - Slot 16: DMA pool for IOVA allocation
//! - Slots 21+: DMA buffer frames

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(iterator_try_collect)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

#[path = "../usb_xhci/executor.rs"]
mod executor;
#[path = "../usb_xhci/hal.rs"]
mod hal;
#[path = "../usb_xhci/ipc.rs"]
mod ipc;

#[path = "../../io.rs"]
mod io;

mod cru;

// -- Simple logger for crab-usb debug output

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            io::puts("[");
            io::puts(record.level().as_str());
            io::puts("] ");
            // Format the message - we need to handle fmt::Arguments
            use core::fmt::Write;
            let mut buf = LogBuffer::new();
            let _ = write!(buf, "{}", record.args());
            io::puts(buf.as_str());
            io::newline();
        }
    }

    fn flush(&self) {}
}

struct LogBuffer {
    buf: [u8; 256],
    pos: usize,
}

impl LogBuffer {
    const fn new() -> Self {
        Self {
            buf: [0u8; 256],
            pos: 0,
        }
    }

    fn as_str(&self) -> &str {
        // SAFETY: We only write valid UTF-8 bytes
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.pos]) }
    }
}

impl core::fmt::Write for LogBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let to_copy = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

static LOGGER: SimpleLogger = SimpleLogger;

fn init_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Debug);
}

use core::ptr::NonNull;
use core::time::Duration;

use crab_usb::{
    impl_trait, DeviceInfo, DwcNewParams, DwcParams, DrMode, EventHandler, Kernel, USBHost,
    UdphyParam, Usb2PhyParam, Usb2PhyPortId, UsbPhyInterfaceMode,
};

use m6_syscall::invoke::{
    frame_get_phys, irq_set_handler, map_frame, recv,
    reply_recv, retype, sched_yield,
};

use ipc::{request, response, status};

// -- Capability slot definitions

const CNODE_RADIX: u8 = 10;

#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

const ROOT_VSPACE: u64 = cptr(2);
const DEVICE_FRAME: u64 = cptr(10);
const IRQ_HANDLER: u64 = cptr(11);
const SERVICE_EP: u64 = cptr(12);
const IOSPACE: u64 = cptr(13);
const IRQ_NOTIF: u64 = cptr(14);
const DMA_POOL: u64 = cptr(16);
const UNTYPED_SLOT: u64 = 17;
const ROOT_CNODE: u64 = cptr(0);

// DMA buffer frame slots (used when IOMMU available)
const DMA_BUFFER_START: u64 = 21;
const DMA_BUFFER_COUNT: usize = 32;

// Fallback DMA slots (used when no IOMMU - allocate from untyped)
// Use high slot numbers to avoid conflicts with heap allocator (starts at 128)
// 32 pages = 128KB, enough for xHCI infrastructure plus device contexts
const FALLBACK_DMA_SLOT_START: u64 = 512;
const FALLBACK_DMA_COUNT: usize = 32;

// Additional frame slots (GRF, CRU, PHY, etc.)
// These match the order in DWC3_ADDITIONAL_FRAMES in manifest.rs:
// 0: SYS_GRF, 1: USB_GRF, 2: USBDPPHY0_GRF, 3: USBDPPHY1_GRF,
// 4: USB2PHY0_GRF, 5: USB2PHY1_GRF, 6: USB2PHY2_GRF, 7: CRU,
// 8: USBDPPHY0 (actual PHY registers), 9: USBDPPHY1
const ADDITIONAL_FRAME_START: u64 = 30;

// Extended MMIO frame slots (for DWC3's large MMIO region)
// Slot 48 contains page 1 (0x1000-0x1FFF), slot 49 contains page 2, etc.
// These are needed because DWC3 registers span >4KB (GSNPSID at 0xC120)
const EXTENDED_MMIO_START: u64 = 48;
const EXTENDED_MMIO_MAX: usize = 16;
const FRAME_SYS_GRF: u64 = cptr(ADDITIONAL_FRAME_START);
const FRAME_USB_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 1);
const FRAME_USBDPPHY0_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 2);
const FRAME_USBDPPHY1_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 3);
const FRAME_USB2PHY0_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 4);
const FRAME_USB2PHY1_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 5);
const FRAME_USB2PHY2_GRF: u64 = cptr(ADDITIONAL_FRAME_START + 6);
const FRAME_CRU: u64 = cptr(ADDITIONAL_FRAME_START + 7);
const FRAME_USBDPPHY0: u64 = cptr(ADDITIONAL_FRAME_START + 8);
const FRAME_USBDPPHY1: u64 = cptr(ADDITIONAL_FRAME_START + 9);

#[inline]
const fn dma_buffer_frame(index: usize) -> u64 {
    cptr(DMA_BUFFER_START + index as u64)
}

/// Virtual address layout for DWC3 driver.
///
/// Each controller instance uses a separate virtual address region to avoid
/// conflicts when multiple DWC3 drivers are spawned for different controllers.
/// The region size is 1MB per controller, laid out as:
///   - 0x0000_8X00_0000: DWC3 MMIO (256KB)
///   - 0x0000_8X01_0000: DMA buffers (32KB)
///   - 0x0000_8X05_0000: GRF regions (8 x 4KB)
///   - 0x0000_8X06_0000: PHY regions (2 x 64KB)
/// Where X = controller index (0, 1, or 2).
const VADDR_REGION_SIZE: u64 = 0x0010_0000; // 1MB per controller
const VADDR_BASE: u64 = 0x0000_8000_0000;

/// Per-controller virtual address layout
struct VaddrLayout {
    mmio: u64,
    dma: u64,
    sys_grf: u64,
    usb_grf: u64,
    usbdpphy0_grf: u64,
    usbdpphy1_grf: u64,
    usb2phy0_grf: u64,
    usb2phy1_grf: u64,
    usb2phy2_grf: u64,
    cru: u64,
    usbdpphy0: u64,
    usbdpphy1: u64,
}

impl VaddrLayout {
    /// Create virtual address layout for a controller instance.
    const fn for_controller(idx: usize) -> Self {
        let base = VADDR_BASE + (idx as u64) * VADDR_REGION_SIZE;
        Self {
            mmio: base,
            dma: base + 0x0001_0000,
            sys_grf: base + 0x0005_0000,
            usb_grf: base + 0x0005_1000,
            usbdpphy0_grf: base + 0x0005_2000,
            usbdpphy1_grf: base + 0x0005_3000,
            usb2phy0_grf: base + 0x0005_4000,
            usb2phy1_grf: base + 0x0005_5000,
            usb2phy2_grf: base + 0x0005_6000,
            cru: base + 0x0005_7000,
            usbdpphy0: base + 0x0006_0000,
            usbdpphy1: base + 0x0007_0000,
        }
    }
}
/// Page size for DMA buffers
const PAGE_SIZE: u64 = 4096;
/// IRQ badge
const IRQ_BADGE: u64 = 1;

/// DMA buffer allocation state
struct DmaBuffers {
    vaddrs: [u64; DMA_BUFFER_COUNT],
    iovas: [u64; DMA_BUFFER_COUNT],
    count: usize,
}

impl DmaBuffers {
    const fn new() -> Self {
        Self {
            vaddrs: [0; DMA_BUFFER_COUNT],
            iovas: [0; DMA_BUFFER_COUNT],
            count: 0,
        }
    }

    fn base_vaddr(&self) -> u64 {
        self.vaddrs[0]
    }

    fn base_iova(&self) -> u64 {
        self.iovas[0]
    }

    fn total_size(&self) -> usize {
        self.count * PAGE_SIZE as usize
    }
}

/// Allocate DMA buffers from untyped memory when IOMMU is not available.
///
/// This fallback path allocates frames from the driver's untyped memory and
/// uses their physical addresses directly (no IOMMU translation).
fn allocate_fallback_dma_buffers(layout: &VaddrLayout) -> DmaBuffers {
    use m6_cap::ObjectType;

    let mut dma = DmaBuffers::new();
    let untyped_cptr = cptr(UNTYPED_SLOT);

    for i in 0..FALLBACK_DMA_COUNT {
        let slot = FALLBACK_DMA_SLOT_START + i as u64;
        let frame_cptr = cptr(slot);
        let vaddr = layout.dma + (i as u64) * PAGE_SIZE;

        // Retype untyped into a frame at the slot
        if let Err(e) = retype(
            untyped_cptr,
            ObjectType::Frame as u64,
            12, // 4KB
            ROOT_CNODE,
            slot,
            1,
        ) {
            io::puts("[drv-usb-dwc3] Failed to retype DMA frame ");
            io::put_u64(i as u64);
            io::puts(": ");
            io::put_u64(e as u64);
            io::newline();
            break;
        }

        // Get physical address of the frame
        let phys_addr = match frame_get_phys(frame_cptr) {
            Ok(addr) => addr as u64,
            Err(e) => {
                io::puts("[drv-usb-dwc3] Failed to get phys addr for frame ");
                io::put_u64(i as u64);
                io::puts(": ");
                io::put_u64(e as u64);
                io::newline();
                break;
            }
        };

        // Map frame to VSpace
        if let Err(e) = map_frame(ROOT_VSPACE, frame_cptr, vaddr, 0b011, 0) {
            io::puts("[drv-usb-dwc3] Failed to map fallback DMA frame ");
            io::put_u64(i as u64);
            io::puts(": ");
            io::put_u64(e as u64);
            io::newline();
            break;
        }

        dma.vaddrs[i] = vaddr;
        dma.iovas[i] = phys_addr; // Use physical address as "IOVA" (no translation)
        dma.count = i + 1;

        // Zero the memory
        // SAFETY: We just mapped this memory
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    dma
}

/// GRF and PHY mapping result
struct GrfMappings {
    sys_grf: u64,
    usb_grf: u64,
    usbdpphy0_grf: u64,
    usbdpphy1_grf: u64,
    usb2phy0_grf: u64,
    usb2phy1_grf: u64,
    usb2phy2_grf: u64,
    cru: u64,
    /// USBDP PHY 0 actual registers (PMA/PCS)
    usbdpphy0: u64,
    /// USBDP PHY 1 actual registers (PMA/PCS)
    usbdpphy1: u64,
}

impl GrfMappings {
    const fn empty() -> Self {
        Self {
            sys_grf: 0,
            usb_grf: 0,
            usbdpphy0_grf: 0,
            usbdpphy1_grf: 0,
            usb2phy0_grf: 0,
            usb2phy1_grf: 0,
            usb2phy2_grf: 0,
            cru: 0,
            usbdpphy0: 0,
            usbdpphy1: 0,
        }
    }
}

/// Map additional GRF, CRU, and PHY frames to driver's address space.
///
/// These frames are provided by device-mgr at slots 30-39.
/// On non-RK3588 platforms, these slots may be empty.
fn map_grf_frames(layout: &VaddrLayout) -> GrfMappings {
    let mut mappings = GrfMappings::empty();

    // Frame slot to virtual address mapping (4KB frames)
    let frame_mappings: [(u64, u64, &str, &mut u64); 10] = [
        (FRAME_SYS_GRF, layout.sys_grf, "SYS_GRF", &mut mappings.sys_grf),
        (FRAME_USB_GRF, layout.usb_grf, "USB_GRF", &mut mappings.usb_grf),
        (FRAME_USBDPPHY0_GRF, layout.usbdpphy0_grf, "USBDPPHY0_GRF", &mut mappings.usbdpphy0_grf),
        (FRAME_USBDPPHY1_GRF, layout.usbdpphy1_grf, "USBDPPHY1_GRF", &mut mappings.usbdpphy1_grf),
        (FRAME_USB2PHY0_GRF, layout.usb2phy0_grf, "USB2PHY0_GRF", &mut mappings.usb2phy0_grf),
        (FRAME_USB2PHY1_GRF, layout.usb2phy1_grf, "USB2PHY1_GRF", &mut mappings.usb2phy1_grf),
        (FRAME_USB2PHY2_GRF, layout.usb2phy2_grf, "USB2PHY2_GRF", &mut mappings.usb2phy2_grf),
        (FRAME_CRU, layout.cru, "CRU", &mut mappings.cru),
        (FRAME_USBDPPHY0, layout.usbdpphy0, "USBDPPHY0", &mut mappings.usbdpphy0),
        (FRAME_USBDPPHY1, layout.usbdpphy1, "USBDPPHY1", &mut mappings.usbdpphy1),
    ];

    let mut mapped_count = 0;
    for (frame_cptr, vaddr, name, result) in frame_mappings {
        match map_frame(ROOT_VSPACE, frame_cptr, vaddr, 0b011, 0) {
            Ok(_) => {
                *result = vaddr;
                mapped_count += 1;
            }
            Err(e) => {
                // Not all platforms have GRF frames - this is expected on QEMU
                if e != m6_syscall::error::SyscallError::InvalidCap {
                    io::puts("[drv-usb-dwc3] ERROR: Failed to map ");
                    io::puts(name);
                    io::puts("\n");
                }
            }
        }
    }

    if mapped_count > 0 {
        io::puts("[drv-usb-dwc3] Mapped ");
        io::put_u64(mapped_count as u64);
        io::puts(" GRF/PHY/CRU regions\n");
    }

    mappings
}

/// Large frame slot definitions for multi-page MMIO regions.
/// These slots (64-127) contain additional pages for large additional frames.
const LARGE_FRAME_START: u64 = 64;
const LARGE_FRAME_MAX: usize = 64;

/// Map large frame slots for multi-page additional MMIO regions.
///
/// The PHY needs 64KB (16 pages). Page 0 is in the regular additional frame slot,
/// and pages 1-15 are in large frame slots starting at 64.
///
/// Returns the number of additional pages mapped for the PHY.
fn map_large_phy_frames(layout: &VaddrLayout, grf_mappings: &GrfMappings) -> usize {
    if grf_mappings.usbdpphy0 == 0 {
        // PHY not mapped, skip large frames
        return 0;
    }

    let mut mapped_count = 0;
    let base_vaddr = layout.usbdpphy0;

    // Map pages 1-15 (page 0 is already mapped in map_grf_frames)
    for i in 0..15 {
        let slot = LARGE_FRAME_START + i as u64;
        let frame_cptr = cptr(slot);
        // Pages are consecutive: base + 0x1000, base + 0x2000, etc.
        let vaddr = base_vaddr + ((i + 1) as u64 * PAGE_SIZE);

        match map_frame(ROOT_VSPACE, frame_cptr, vaddr, 0b011, 0) {
            Ok(_) => {
                mapped_count += 1;
            }
            Err(m6_syscall::error::SyscallError::InvalidCap)
            | Err(m6_syscall::error::SyscallError::EmptySlot) => {
                // No more large frames - this is expected
                break;
            }
            Err(e) => {
                io::puts("[drv-usb-dwc3] Failed to map large PHY frame ");
                io::put_u64(i as u64);
                io::puts(": ");
                io::put_u64(e as u64);
                io::newline();
                break;
            }
        }
    }

    mapped_count
}

/// Map extended MMIO frames for large MMIO regions.
///
/// DWC3 requires more than 4KB of MMIO space (GSNPSID is at offset 0xC120).
/// Device-mgr provides additional DeviceFrame capabilities at slots 48+ for
/// pages beyond the first 4KB.
///
/// Returns the number of extended pages successfully mapped.
fn map_extended_mmio_frames(layout: &VaddrLayout) -> usize {
    let mut mapped_count = 0;

    for i in 0..EXTENDED_MMIO_MAX {
        let slot = EXTENDED_MMIO_START + i as u64;
        let frame_cptr = cptr(slot);
        // Page 0 is at layout.mmio, page 1 is at +0x1000, etc.
        let vaddr = layout.mmio + ((i + 1) as u64 * PAGE_SIZE);

        match map_frame(ROOT_VSPACE, frame_cptr, vaddr, 0b011, 0) {
            Ok(_) => {
                mapped_count += 1;
            }
            Err(m6_syscall::error::SyscallError::InvalidCap)
            | Err(m6_syscall::error::SyscallError::EmptySlot) => {
                // No more extended frames - this is expected
                break;
            }
            Err(e) => {
                io::puts("[drv-usb-dwc3] Failed to map extended MMIO page ");
                io::put_u64(i as u64);
                io::puts(": ");
                io::put_u64(e as u64);
                io::newline();
                break;
            }
        }
    }

    mapped_count
}

/// Set up DMA buffers for USB operations.
///
/// Device-mgr pre-allocates DMA frames and maps them to our VSpace.
/// This function detects if those pre-allocated buffers exist and uses them.
/// If not available (no IOMMU or IOSpace failed), falls back to allocating
/// from untyped memory with physical addresses.
fn map_dma_buffers(layout: &VaddrLayout) -> DmaBuffers {
    use m6_syscall::error::SyscallError;

    // Check if pre-allocated DMA frames are available by probing slot 21
    let frame_cap = dma_buffer_frame(0);

    // Try to get the physical address of the pre-allocated frame
    // This will fail with InvalidCap if the slot is empty
    match frame_get_phys(frame_cap) {
        Ok(phys_addr) => {
            // Pre-allocated DMA frames exist
            return use_preallocated_dma_buffers(layout, phys_addr as u64);
        }
        Err(SyscallError::InvalidCap) | Err(SyscallError::EmptySlot) => {
            // No pre-allocated DMA frames, use fallback
            return allocate_fallback_dma_buffers(layout);
        }
        Err(_) => {
            return allocate_fallback_dma_buffers(layout);
        }
    }
}

/// Use pre-allocated DMA buffers that device-mgr already mapped.
fn use_preallocated_dma_buffers(layout: &VaddrLayout, _first_phys: u64) -> DmaBuffers {
    let mut dma = DmaBuffers::new();

    for i in 0..DMA_BUFFER_COUNT {
        let frame_cap = dma_buffer_frame(i);
        let vaddr = layout.dma + (i as u64) * PAGE_SIZE;

        // Get physical address for this frame (used as IOVA in bypass mode)
        let phys_addr = match frame_get_phys(frame_cap) {
            Ok(addr) => addr as u64,
            Err(_) => break, // No more frames
        };

        dma.vaddrs[i] = vaddr;
        dma.iovas[i] = phys_addr; // Use physical address as IOVA
        dma.count = i + 1;

        // Zero the memory (already mapped by device-mgr)
        // SAFETY: Device-mgr mapped this memory at vaddr
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    dma
}

// -- crab-usb Kernel trait implementation

struct M6Kernel;

impl_trait! {
    impl Kernel for M6Kernel {
        fn page_size() -> usize {
            PAGE_SIZE as usize
        }

        fn delay(duration: Duration) {
            // Use kernel sleep syscall for delays
            let nanos = duration.as_nanos() as u64;
            let _ = m6_syscall::invoke::tcb_sleep(nanos);
        }
    }
}

/// DWC3 device state
struct Dwc3Device {
    host: USBHost,
    event_handler: Option<EventHandler>,
    dma: DmaBuffers,
    initialised: bool,
    devices: alloc::vec::Vec<DeviceInfo>,
}

/// IRQ configuration result
#[derive(Clone, Copy)]
struct IrqConfig {
    enabled: bool,
    notif: u64,
}

impl IrqConfig {
    const fn disabled() -> Self {
        Self {
            enabled: false,
            notif: IRQ_NOTIF,
        }
    }
}

/// Set up IRQ handling
fn setup_irq() -> IrqConfig {
    match irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE) {
        Ok(_) => IrqConfig {
            enabled: true,
            notif: IRQ_NOTIF,
        },
        Err(e) => {
            io::puts("[drv-usb-dwc3] ERROR: irq_set_handler failed: ");
            io::put_u64(e as u64);
            io::newline();
            IrqConfig::disabled()
        }
    }
}

/// Entry point for DWC3 driver.
///
/// # Arguments
///
/// * `device_phys_addr` - Physical address of the device (from DTB reg property)
///
/// # Safety
///
/// Must be called only once as the driver entry point with valid capability slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_phys_addr: u64) -> ! {
    // Initialise heap allocator before any heap allocations
    rt::init_allocator();

    // Initialise logger for crab-usb debug output
    init_logger();

    io::puts("\x1b[36m[drv-usb-dwc3] DWC3 USB driver starting\x1b[0m\n");

    // Determine controller index from the physical address
    let controller_idx = match device_phys_addr {
        0xFC00_0000 => 0, // USB3OTG_0
        0xFC40_0000 => 1, // USB3OTG_1
        0xFCD0_0000 => 2, // USB3OTG_2
        _ => {
            let nibble = ((device_phys_addr >> 20) & 0xF) as usize;
            match nibble {
                0x0 => 0,
                0x4 => 1,
                0xD => 2,
                _ => 0,
            }
        }
    };

    let page_offset = device_phys_addr & 0xFFF;
    let layout = VaddrLayout::for_controller(controller_idx);

    // Map the DeviceFrame (DWC3 MMIO)
    if let Err(e) = map_frame(ROOT_VSPACE, DEVICE_FRAME, layout.mmio, 0b011, 0) {
        io::puts("[drv-usb-dwc3] ERROR: Failed to map MMIO: ");
        io::put_u64(e as u64);
        io::newline();
        halt();
    }

    // Map extended MMIO frames
    let extended_pages = map_extended_mmio_frames(&layout);
    if extended_pages < 12 {
        io::puts("[drv-usb-dwc3] WARNING: Insufficient MMIO pages mapped\n");
    }

    let ctrl_addr = layout.mmio + page_offset;

    // Map DMA buffer frames (may be empty if IOMMU not available)
    let dma = map_dma_buffers(&layout);

    // Initialise the DMA HAL
    // SAFETY: Called once during init
    if dma.count > 0 {
        unsafe {
            hal::init_dma_hal(dma.base_vaddr(), dma.base_iova(), dma.total_size());
            hal::register_osal();
        }
    } else {
        unsafe {
            hal::init_dma_hal(0, 0, 0);
            hal::register_osal();
        }
    }

    // Set up IRQ handling
    let _irq_config = setup_irq();

    // Map additional GRF and CRU frames (RK3588-specific)
    // These may fail on non-RK3588 platforms, which is expected
    let grf_mappings = map_grf_frames(&layout);

    // Map additional pages for large PHY MMIO region (needs 64KB for PMA at offset 0x8000)
    let phy_extra_pages = map_large_phy_frames(&layout, &grf_mappings);
    if grf_mappings.usbdpphy0 != 0 && phy_extra_pages < 8 {
        io::puts("[drv-usb-dwc3] WARNING: PHY MMIO only ");
        io::put_u64((phy_extra_pages + 1) as u64);
        io::puts(" pages mapped, PMA at 0x8000 may not be accessible\n");
    }

    // Check if firmware already initialised the hardware
    const GSNPSID_OFFSET: u64 = 0xC120;
    let clocks_already_enabled = {
        // SAFETY: ctrl_addr is mapped
        let gsnpsid = unsafe {
            core::ptr::read_volatile((ctrl_addr + GSNPSID_OFFSET) as *const u32)
        };
        gsnpsid != 0xFFFF_FFFF && gsnpsid != 0 && (gsnpsid >> 16) == 0x5533
    };

    // Create CRU instance for reset control
    let cru = if clocks_already_enabled {
        cru::RK3588Cru::skip_resets()
    } else if grf_mappings.cru != 0 {
        // SAFETY: grf_mappings.cru is a valid mapped virtual address
        unsafe { cru::RK3588Cru::with_base(grf_mappings.cru) }
    } else {
        cru::RK3588Cru::new()
    };

    if !clocks_already_enabled {
        cru.enable_usb3_clocks(controller_idx);
        cru.deassert_usb3_reset(controller_idx);
        // Delay to let clocks stabilise
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }

    // Verify hardware is responding
    // SAFETY: ctrl_addr is mapped
    let gsnpsid = unsafe {
        core::ptr::read_volatile((ctrl_addr + GSNPSID_OFFSET) as *const u32)
    };

    if gsnpsid == 0xFFFF_FFFF || gsnpsid == 0 {
        io::puts("[drv-usb-dwc3] ERROR: Hardware not responding\n");
        halt();
    }

    if (gsnpsid >> 16) != 0x5533 {
        io::puts("[drv-usb-dwc3] WARNING: Unexpected GSNPSID\n");
    }

    // When firmware already initialised the controller, use xHCI directly
    if clocks_already_enabled {
        run_xhci_mode(ctrl_addr, dma);
    }

    // -- Full DWC3 initialization path (when firmware didn't initialize) --

    // PHY MMIO - use mapped address from grf_mappings (mapped at slots 38/39)
    // The PHY needs 64KB for PCS (0x4000) and PMA (0x8000) regions
    let phy_mmio_addr = if grf_mappings.usbdpphy0 != 0 {
        grf_mappings.usbdpphy0
    } else {
        io::puts("[drv-usb-dwc3] WARNING: USBDPPHY0 not mapped, PHY init will fail\n");
        layout.usbdpphy0 // Use expected address even if not mapped (will fault)
    };
    let phy_mmio = NonNull::new(phy_mmio_addr as *mut u8).expect("PHY MMIO is null");

    // GRF MMIO pointers - use mapped addresses if available, otherwise fallback
    // (fallback addresses won't work but allow compilation/running on non-RK3588)
    let u2phy_grf_addr = if grf_mappings.usb2phy0_grf != 0 {
        grf_mappings.usb2phy0_grf
    } else {
        layout.usb2phy0_grf
    };
    let usb_grf_addr = if grf_mappings.usb_grf != 0 {
        grf_mappings.usb_grf
    } else {
        layout.usb_grf
    };
    let usbdpphy_grf_addr = if grf_mappings.usbdpphy0_grf != 0 {
        grf_mappings.usbdpphy0_grf
    } else {
        layout.usbdpphy0_grf
    };
    let vo_grf_addr = if grf_mappings.sys_grf != 0 {
        grf_mappings.sys_grf
    } else {
        layout.sys_grf
    };

    let u2phy_grf = NonNull::new(u2phy_grf_addr as *mut u8).expect("USB2PHY GRF is null");
    let usb_grf = NonNull::new(usb_grf_addr as *mut u8).expect("USB GRF is null");
    let usbdpphy_grf = NonNull::new(usbdpphy_grf_addr as *mut u8).expect("USBDPPHY GRF is null");
    let vo_grf = NonNull::new(vo_grf_addr as *mut u8).expect("VO GRF is null");

    // Reset ID lists for PHY reset control
    // These IDs must be provided even when we want to skip resets, because crab-usb
    // looks up reset names in the HashMap. The actual reset operations are controlled
    // by the CRU implementation (which will be a no-op when skip_resets is true).
    static UDPHY_RESETS: &[(&str, u64)] = &[
        ("init", 0),
        ("cmn", 1),
        ("lane", 2),
        ("pcs_apb", 3),
        ("pma_apb", 4),
    ];
    static USB2PHY_RESETS: &[(&str, u64)] = &[("phy", 5)];

    let udphy_param = UdphyParam {
        id: 0,
        u2phy_grf,
        usb_grf,
        usbdpphy_grf,
        vo_grf,
        dp_lane_mux: &[], // USB-only mode, no DP lanes
        rst_list: UDPHY_RESETS,
    };

    let usb2phy_param = Usb2PhyParam {
        reg: 0x0, // First USB2PHY
        port_kind: Usb2PhyPortId::Otg,
        usb_grf,
        rst_list: USB2PHY_RESETS,
    };

    let dwc_params = DwcParams {
        dr_mode: DrMode::Host,
        hsphy_mode: UsbPhyInterfaceMode::Utmi,
        ..Default::default()
    };

    let ctrl_mmio = NonNull::new(ctrl_addr as *mut u8).expect("Controller MMIO is null");
    let dma_mask: u64 = 0xFFFF_FFFF_FFFF; // 48-bit DMA

    let params = DwcNewParams {
        ctrl: ctrl_mmio,
        phy: phy_mmio,
        phy_param: udphy_param,
        usb2_phy_param: usb2phy_param,
        cru,
        rst_list: &[],
        dma_mask: dma_mask as usize,
        params: dwc_params,
    };

    let host = match USBHost::new_dwc(params) {
        Ok(h) => h,
        Err(e) => {
            io::puts("[drv-usb-dwc3] ERROR: Failed to create DWC3 host: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
            halt();
        }
    };

    let mut device = Dwc3Device {
        host,
        event_handler: None,
        dma,
        initialised: false,
        devices: alloc::vec::Vec::new(),
    };

    // Initialise the controller
    let init_result = executor::block_on(device.host.init());
    if let Err(e) = init_result {
        io::puts("[drv-usb-dwc3] ERROR: Controller init failed: ");
        io::puts(core::any::type_name_of_val(&e));
        io::newline();
        halt();
    }

    // Create event handler and register it with the executor
    let event_handler = device.host.create_event_handler();
    // SAFETY: Single-threaded driver, called once after init
    unsafe {
        executor::set_event_handler(event_handler);
        executor::enable_event_polling();
    }

    match executor::block_on(device.host.probe_devices()) {
        Ok(devices) => {
            if devices.len() > 0 {
                io::puts("[drv-usb-dwc3] Found ");
                io::put_u64(devices.len() as u64);
                io::puts(" USB device(s)\n");
            }
            device.devices = devices;
        }
        Err(e) => {
            io::puts("[drv-usb-dwc3] ERROR: Device probe failed: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
        }
    }

    device.initialised = true;
    io::puts("[drv-usb-dwc3] Ready\n");

    service_loop(&mut device);
}

/// Run in xHCI mode, bypassing DWC3/PHY initialisation.
///
/// Used when firmware (UEFI) has already initialised the USB controller.
/// The embedded xHCI is at offset 0x0 within the DWC3 register space.
fn run_xhci_mode(ctrl_addr: u64, dma: DmaBuffers) -> ! {
    let mmio = NonNull::new(ctrl_addr as *mut u8).expect("MMIO address is null");
    let dma_mask: u64 = 0xFFFF_FFFF_FFFF; // 48-bit DMA

    let mut host = match USBHost::new_xhci(mmio, dma_mask as usize) {
        Ok(h) => h,
        Err(e) => {
            io::puts("[drv-usb-dwc3] ERROR: Failed to create xHCI host: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
            halt();
        }
    };

    // Create and register event handler before any async operations
    let event_handler = host.create_event_handler();
    // SAFETY: Single-threaded driver, called once during initialisation
    unsafe {
        executor::set_event_handler(event_handler);
    }

    let mut device = Dwc3Device {
        host,
        event_handler: None,
        dma,
        initialised: false,
        devices: alloc::vec::Vec::new(),
    };

    // Initialise the xHCI controller
    let init_result = executor::block_on(device.host.init());
    if let Err(e) = init_result {
        io::puts("[drv-usb-dwc3] ERROR: xHCI init failed: ");
        io::puts(core::any::type_name_of_val(&e));
        io::newline();
        halt();
    }

    // Now that the event ring is set up, enable event polling
    // SAFETY: xHCI init completed, event ring is ready
    unsafe {
        executor::enable_event_polling();
    }

    match executor::block_on(device.host.probe_devices()) {
        Ok(devices) => {
            if devices.len() > 0 {
                io::puts("[drv-usb-dwc3] Found ");
                io::put_u64(devices.len() as u64);
                io::puts(" USB device(s)\n");
            }
            device.devices = devices;
        }
        Err(e) => {
            io::puts("[drv-usb-dwc3] ERROR: Device probe failed: ");
            io::puts(core::any::type_name_of_val(&e));
            io::newline();
        }
    }

    device.initialised = true;
    io::puts("[drv-usb-dwc3] Ready\n");

    service_loop(&mut device);
}

/// Halt the driver on fatal error.
fn halt() -> ! {
    loop {
        sched_yield();
    }
}

/// Main service loop
fn service_loop(device: &mut Dwc3Device) -> ! {
    let mut result = recv(SERVICE_EP);

    loop {
        match result {
            Ok(ipc_result) => {
                let response = handle_request(device, ipc_result.label, &ipc_result.msg);
                result = reply_recv(SERVICE_EP, response, 0, 0, 0);
            }
            Err(err) => {
                io::puts("[drv-usb-dwc3] IPC error: ");
                io::put_u64(err as u64);
                io::newline();
                sched_yield();
                result = recv(SERVICE_EP);
            }
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(device: &mut Dwc3Device, label: u64, msg: &[u64; 4]) -> u64 {
    match label & 0xFFFF {
        request::GET_INFO => handle_get_info(device),
        request::GET_STATUS => handle_get_status(device),
        request::GET_PORT_COUNT => handle_get_port_count(device),
        request::GET_PORT_STATUS => handle_get_port_status(device, msg[0] as u8),
        request::LIST_DEVICES => handle_list_devices(device),
        _ => response::ERR_UNSUPPORTED,
    }
}

fn handle_get_info(_device: &Dwc3Device) -> u64 {
    response::OK
}

fn handle_get_status(device: &Dwc3Device) -> u64 {
    let mut flags = 0u64;
    if device.initialised {
        flags |= status::READY;
        flags |= status::USB2_SUPPORTED;
        flags |= status::USB3_SUPPORTED;
        flags |= status::PORTS_POWERED;
    }
    flags
}

fn handle_get_port_count(_device: &Dwc3Device) -> u64 {
    response::OK | (2 << 16) // DWC3 typically has 2 ports (USB2 + USB3)
}

fn handle_get_port_status(_device: &Dwc3Device, port: u8) -> u64 {
    if port == 0 || port > 4 {
        return response::ERR_INVALID_PORT;
    }
    response::OK
}

fn handle_list_devices(device: &Dwc3Device) -> u64 {
    let count = device.devices.len() as u64;
    response::OK | (count << 16)
}
