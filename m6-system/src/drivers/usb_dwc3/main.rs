//! USB DWC3 Host Controller Driver for RK3588
//!
//! Userspace driver for DesignWare USB3 DRD controllers on the RK3588 SoC.
//! Operates in Host mode using the embedded xHCI controller.
//!
//! This driver uses direct xHCI register access - firmware (UEFI) is expected
//! to have already initialised the controller and PHY.
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
//! - Slot 14: Notification for IRQ delivery

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

#[path = "../../io.rs"]
mod io;
#[path = "../usb_xhci/ipc.rs"]
mod ipc;
#[path = "../usb_xhci/xhci.rs"]
mod xhci;

use m6_syscall::invoke::{frame_get_phys, irq_ack, irq_set_handler, map_frame, recv, reply_recv, sched_yield};

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
const IRQ_NOTIF: u64 = cptr(14);

/// First DMA buffer frame slot (slots 21-36)
const DMA_BUFFER_START: u64 = 21;
/// Number of DMA buffer pages provided by device-mgr
/// 16 pages = 64KB for xHCI structures + interrupt endpoint rings
const DMA_BUFFER_COUNT: usize = 16;

/// Get CPtr for DMA buffer frame at index
#[inline]
const fn dma_buffer_frame(index: usize) -> u64 {
    cptr(DMA_BUFFER_START + index as u64)
}

// Extended MMIO frame slots (for DWC3's large MMIO region)
// TODO: Import from shared slot constants crate instead of hardcoding
const EXTENDED_MMIO_START: u64 = 56;
const EXTENDED_MMIO_MAX: usize = 16;

/// Page size
const PAGE_SIZE: u64 = 4096;
/// IRQ badge
const IRQ_BADGE: u64 = 1;

/// DMA buffer allocation state
/// Note: DMA buffers are pre-mapped by device-mgr.
/// TODO: When IOSpace is properly configured, use IOVA 0x1000_0000 instead of physical address.
/// Currently the SMMU appears to be in bypass mode, so we use physical addresses.
struct DmaBuffers {
    /// Base virtual address of DMA buffer region
    base_vaddr: u64,
    /// Base physical address for DMA operations
    /// Used when SMMU is in bypass mode (identity mapping)
    base_paddr: u64,
    /// Number of pages available
    count: usize,
}

impl DmaBuffers {
    /// Get the base virtual address
    fn base_vaddr(&self) -> u64 {
        self.base_vaddr
    }

    /// Get the base physical/DMA address
    fn base_dma_addr(&self) -> u64 {
        self.base_paddr
    }

    /// Get total size
    fn total_size(&self) -> usize {
        self.count * PAGE_SIZE as usize
    }
}

/// Check for DMA buffers pre-mapped by device-mgr.
///
/// Device-mgr maps DMA buffers into the driver's VSpace at per-controller addresses.
/// We use frame_get_phys to get the physical address for DMA operations.
///
/// TODO: When IOSpace/SMMU is properly configured, use IOVA instead of physical address.
fn check_dma_buffers(controller_idx: usize) -> Option<DmaBuffers> {
    // Calculate DMA buffer virtual address (same convention as device-mgr)
    let base_vaddr = 0x0000_8000_0000 + (controller_idx as u64) * 0x0010_0000 + 0x0001_0000;

    // Get physical address of first DMA buffer frame using frame_get_phys syscall
    let first_frame_cap = dma_buffer_frame(0);
    let base_paddr = match frame_get_phys(first_frame_cap) {
        Ok(paddr) => paddr as u64,
        Err(_) => return None,
    };

    // Zero all DMA buffer pages
    for i in 0..DMA_BUFFER_COUNT {
        let page_addr = base_vaddr + (i as u64) * PAGE_SIZE;
        // SAFETY: Memory is mapped by device-mgr
        unsafe {
            core::ptr::write_bytes(page_addr as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    Some(DmaBuffers {
        base_vaddr,
        base_paddr,
        count: DMA_BUFFER_COUNT,
    })
}

/// Virtual address layout for DWC3 driver.
const VADDR_REGION_SIZE: u64 = 0x0010_0000; // 1MB per controller
const VADDR_BASE: u64 = 0x0000_8000_0000;

/// Per-controller virtual address layout
struct VaddrLayout {
    mmio: u64,
}

impl VaddrLayout {
    const fn for_controller(idx: usize) -> Self {
        let base = VADDR_BASE + (idx as u64) * VADDR_REGION_SIZE;
        Self { mmio: base }
    }
}

/// Device state for direct xHCI mode
struct Dwc3Device {
    /// Direct xHCI controller for register access
    xhci_ctrl: xhci::XhciController,
    /// DMA buffers for xHCI operations
    dma: Option<DmaBuffers>,
    /// Cached port status
    port_status_cache: alloc::vec::Vec<xhci::PortStatus>,
    /// Enumerated USB devices
    devices: alloc::vec::Vec<UsbDeviceInfo>,
    /// Whether device enumeration has been performed
    devices_enumerated: bool,
    /// Whether xHCI is initialized for command submission
    xhci_initialized: bool,
}

/// Basic USB device info
#[derive(Clone)]
struct UsbDeviceInfo {
    slot_id: u8,
    port: u8,
    speed: xhci::PortSpeed,
    interfaces: alloc::vec::Vec<UsbInterfaceInfo>,
}

/// Basic USB interface info
#[derive(Clone)]
struct UsbInterfaceInfo {
    interface_number: u8,
    class: u8,
    subclass: u8,
    protocol: u8,
    endpoint_address: u8,
    endpoint_interval: u8,
    endpoint_max_packet: u16,
}

/// Set up IRQ handling
fn setup_irq() {
    let _ = irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE);
}

/// Map extended MMIO frames for large MMIO regions.
fn map_extended_mmio_frames(layout: &VaddrLayout) -> usize {
    let mut mapped_count = 0;

    for i in 0..EXTENDED_MMIO_MAX {
        let slot = EXTENDED_MMIO_START + i as u64;
        let frame_cptr = cptr(slot);
        let vaddr = layout.mmio + ((i + 1) as u64 * PAGE_SIZE);

        match map_frame(ROOT_VSPACE, frame_cptr, vaddr, 0b011, 0) {
            Ok(_) => {
                mapped_count += 1;
            }
            Err(m6_syscall::error::SyscallError::InvalidCap)
            | Err(m6_syscall::error::SyscallError::EmptySlot) => {
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    mapped_count
}

/// Entry point for DWC3 driver.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(device_phys_addr: u64) -> ! {
    // Initialise heap allocator
    rt::init_allocator();

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
    if let Err(_) = map_frame(ROOT_VSPACE, DEVICE_FRAME, layout.mmio, 0b011, 0) {
        halt();
    }

    // Map extended MMIO frames
    let _extended_pages = map_extended_mmio_frames(&layout);

    let ctrl_addr = layout.mmio + page_offset;

    // Set up IRQ handling
    setup_irq();

    // Verify hardware is responding
    const GSNPSID_OFFSET: u64 = 0xC120;
    // SAFETY: ctrl_addr is mapped
    let gsnpsid = unsafe {
        core::ptr::read_volatile((ctrl_addr + GSNPSID_OFFSET) as *const u32)
    };

    if gsnpsid == 0xFFFF_FFFF || gsnpsid == 0 {
        halt();
    }

    // Configure GCTL for host mode operation (matching Linux dwc3_core_setup_global_control).
    // We do NOT perform CORESOFTRESET — UEFI has already initialised the controller
    // and the USB link is established. A core reset would kill the link and require
    // PHY re-negotiation (100+ ms), causing device enumeration to fail.
    // The xHCI HCRST in try_initialize_xhci() is sufficient to reset xHCI state
    // while preserving port connections.
    const GCTL_OFFSET: u64 = 0xC110;
    let gctl = unsafe { core::ptr::read_volatile((ctrl_addr + GCTL_OFFSET) as *const u32) };

    const DSBLCLKGTNG: u32 = 1 << 0;
    const GBLHIBERNATIONEN: u32 = 1 << 1;
    const SCALEDOWN_MASK: u32 = 0x3 << 4;
    const PRTCAP_HOST: u32 = 0x1 << 12;
    const PRTCAP_MASK: u32 = 0x3 << 12;

    let mut new_gctl = gctl;
    new_gctl |= DSBLCLKGTNG;       // Disable clock gating for register access
    new_gctl &= !GBLHIBERNATIONEN; // Clear hibernation enable
    new_gctl &= !SCALEDOWN_MASK;   // Clear timing scale-down
    new_gctl &= !PRTCAP_MASK;      // Clear PRTCAP
    new_gctl |= PRTCAP_HOST;       // Set host mode

    if new_gctl != gctl {
        unsafe {
            core::ptr::write_volatile((ctrl_addr + GCTL_OFFSET) as *mut u32, new_gctl);
        }

        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }

    // Configure USB2 PHY (GUSB2PHYCFG at offset 0xC200)
    // The PHY configuration is critical for xHCI to work properly
    const GUSB2PHYCFG_OFFSET: u64 = 0xC200;
    let gusb2phycfg = unsafe {
        core::ptr::read_volatile((ctrl_addr + GUSB2PHYCFG_OFFSET) as *const u32)
    };
    // Configure GUSB2PHYCFG per RK3588 DTS quirks and Linux dwc3_core_init:
    // - Bit 6: SUSPHY — clear (dis_u2_susphy_quirk: don't auto-suspend PHY)
    // - Bit 8: ENBLSLPM — clear (dis_enblslpm_quirk: disable SLP mode)
    // - Bit 30: U2_FREECLK_EXISTS — clear (dis-u2-freeclk-exists-quirk)
    // - Bits 13:10: USBTRDTIM — set based on PHYIF width
    // - Bit 31: PHYSUSP — read-only, but writing 0 is harmless
    const SUSPHY: u32 = 1 << 6;
    const ENBLSLPM: u32 = 1 << 8;
    const U2_FREECLK_EXISTS: u32 = 1 << 30;
    const PHYSUSP: u32 = 1 << 31;
    const USBTRDTIM_MASK: u32 = 0xF << 10;
    const PHYIF_MASK: u32 = 1 << 3;
    // Turnaround time: 5 for 16-bit UTMI, 9 for 8-bit UTMI
    const USBTRDTIM_16BIT: u32 = 5 << 10;
    const USBTRDTIM_8BIT: u32 = 9 << 10;

    {
        let mut new_phycfg = gusb2phycfg;
        new_phycfg &= !(SUSPHY | ENBLSLPM | U2_FREECLK_EXISTS | PHYSUSP);
        // Set USBTRDTIM based on current PHYIF width
        new_phycfg &= !USBTRDTIM_MASK;
        if (new_phycfg & PHYIF_MASK) != 0 {
            new_phycfg |= USBTRDTIM_16BIT;
        } else {
            new_phycfg |= USBTRDTIM_8BIT;
        }

        if new_phycfg != gusb2phycfg {
            unsafe {
                core::ptr::write_volatile(
                    (ctrl_addr + GUSB2PHYCFG_OFFSET) as *mut u32,
                    new_phycfg,
                );
            }

            // Wait for PHY to stabilise
            for _ in 0..50_000 {
                core::hint::spin_loop();
            }
        }
    }

    // Configure USB3 PHY (GUSB3PIPECTL at offset 0xC2C0)
    const GUSB3PIPECTL_OFFSET: u64 = 0xC2C0;
    let gusb3pipectl = unsafe {
        core::ptr::read_volatile((ctrl_addr + GUSB3PIPECTL_OFFSET) as *const u32)
    };
    // Check if USB3 PIPE is suspended
    // Bit 17: SUSPHY - Suspend USB 3.0 SS PHY
    const USB3_SUSPHY: u32 = 1 << 17;
    if (gusb3pipectl & USB3_SUSPHY) != 0 {
        let new_pipectl = gusb3pipectl & !USB3_SUSPHY;
        unsafe {
            core::ptr::write_volatile(
                (ctrl_addr + GUSB3PIPECTL_OFFSET) as *mut u32,
                new_pipectl,
            );
        }

        // Wait for PHY to stabilize
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }
    }

    // Configure GFLADJ (Frame Length Adjustment) for the reference clock.
    // RK3588 uses a 24 MHz reference clock. The DWC3 defaults assume 30 MHz,
    // so we must set multiple fields to correct the SOF/ITP frame interval.
    // Without this, the periodic scheduler cannot generate correct timing
    // and interrupt endpoints will never fire.
    //
    // For 24 MHz ref clock:
    //   period = 1e9/24e6 = 41 ns
    //   fladj = (125000 * 1e9) / (24e6 * 41) - 125000 = 2032
    //   decr = 480e6 / 24e6 = 20
    const GFLADJ_OFFSET: u64 = 0xC630;
    let gfladj = unsafe { core::ptr::read_volatile((ctrl_addr + GFLADJ_OFFSET) as *const u32) };

    const GFLADJ_30MHZ_SDBND_SEL: u32 = 1 << 7;
    const GFLADJ_30MHZ_MASK: u32 = 0x3F;
    const GFLADJ_30MHZ_VALUE: u32 = 0x20;
    const GFLADJ_REFCLK_FLADJ_MASK: u32 = 0x3FFF << 8;     // bits 21:8
    const GFLADJ_REFCLK_FLADJ_VALUE: u32 = 2032 << 8;       // for 24 MHz
    const GFLADJ_240MHZDECR_MASK: u32 = 0x7F << 24;         // bits 30:24
    const GFLADJ_240MHZDECR_VALUE: u32 = 10 << 24;          // (480MHz/24MHz)/2
    const GFLADJ_240MHZDECR_PLS1: u32 = 1 << 31;            // bit 31

    let new_gfladj = (gfladj
        & !(GFLADJ_30MHZ_MASK
            | GFLADJ_30MHZ_SDBND_SEL
            | GFLADJ_REFCLK_FLADJ_MASK
            | GFLADJ_240MHZDECR_MASK
            | GFLADJ_240MHZDECR_PLS1))
        | GFLADJ_30MHZ_SDBND_SEL
        | GFLADJ_30MHZ_VALUE
        | GFLADJ_REFCLK_FLADJ_VALUE
        | GFLADJ_240MHZDECR_VALUE;
        // 240MHZDECR_PLS1 stays 0 (decr=20 is even)

    if new_gfladj != gfladj {
        unsafe {
            core::ptr::write_volatile((ctrl_addr + GFLADJ_OFFSET) as *mut u32, new_gfladj);
        }
    }

    // Configure GUCTL (Global User Control) with reference clock period.
    // REFCLKPER (bits 31:22) tells the controller the ref clock period in ns.
    // For 24 MHz: period = 1e9/24e6 = 41 ns.
    // Linux's dwc3_ref_clk_period() always writes this.
    const GUCTL_OFFSET: u64 = 0xC12C;
    let guctl = unsafe { core::ptr::read_volatile((ctrl_addr + GUCTL_OFFSET) as *const u32) };

    const GUCTL_REFCLKPER_MASK: u32 = 0x3FF << 22; // bits 31:22
    const GUCTL_REFCLKPER_VALUE: u32 = 41 << 22;   // 41 ns for 24 MHz
    let new_guctl = (guctl & !GUCTL_REFCLKPER_MASK) | GUCTL_REFCLKPER_VALUE;
    if new_guctl != guctl {
        unsafe {
            core::ptr::write_volatile((ctrl_addr + GUCTL_OFFSET) as *mut u32, new_guctl);
        }
    }

    // Configure GUCTL1 — park mode disable for RK3588 (per DTS quirks).
    // Disabling park mode prevents the xHCI scheduler from batching
    // requests in ways that can starve periodic endpoints.
    const GUCTL1_OFFSET: u64 = 0xC11C;
    let guctl1 = unsafe { core::ptr::read_volatile((ctrl_addr + GUCTL1_OFFSET) as *const u32) };
    const PARKMODE_DISABLE_SS: u32 = 1 << 17;
    const PARKMODE_DISABLE_HS: u32 = 1 << 16;
    let new_guctl1 = guctl1 | PARKMODE_DISABLE_SS | PARKMODE_DISABLE_HS;
    if new_guctl1 != guctl1 {
        unsafe {
            core::ptr::write_volatile((ctrl_addr + GUCTL1_OFFSET) as *mut u32, new_guctl1);
        }
    }

    // Mask DWC3 internal events until a proper buffer is set up.
    // After core soft reset, GEVNTSIZ defaults to 0 (events unmasked, no buffer).
    // This can stall the DWC3 event engine. Mask events immediately, then set
    // up a proper buffer later when DMA memory is available.
    unsafe {
        // GEVNTSIZ(0) at 0xC408: set bit 31 (interrupt mask), size=0
        core::ptr::write_volatile((ctrl_addr + 0xC408) as *mut u32, 1u32 << 31);
        // Clear any pending event count
        let cnt = core::ptr::read_volatile((ctrl_addr + 0xC40C) as *const u32);
        if cnt != 0 {
            core::ptr::write_volatile((ctrl_addr + 0xC40C) as *mut u32, cnt);
        }
    }

    // Create xHCI controller for direct register access
    // SAFETY: ctrl_addr is mapped
    let xhci_ctrl = unsafe { xhci::XhciController::new(ctrl_addr) };

    // Scan ports using direct register access
    let port_status_cache = xhci_ctrl.scan_ports();
    let connected_count = port_status_cache.iter().filter(|p| p.connected).count();

    // Check for DMA buffers pre-mapped by device-mgr
    let dma = check_dma_buffers(controller_idx);

    io::puts("[drv-usb-dwc3] ports=");
    io::put_u64(connected_count as u64);
    io::puts(" dma=");
    io::puts(if dma.is_some() { "yes" } else { "no" });
    io::newline();

    let mut device = Dwc3Device {
        xhci_ctrl,
        dma,
        port_status_cache,
        devices: alloc::vec::Vec::new(),
        devices_enumerated: false,
        xhci_initialized: false,
    };

    // If we have DMA buffers and connected devices, try to initialize xHCI
    if device.dma.is_some() && connected_count > 0 {
        match try_initialize_xhci(&mut device) {
            Ok(()) => io::puts("[drv-usb-dwc3] xHCI init OK\n"),
            Err(e) => {
                io::puts("[drv-usb-dwc3] xHCI init FAILED: ");
                io::puts(e);
                io::newline();
            }
        }
    }

    service_loop(&mut device);
}

/// Try to initialise xHCI command/event rings for device enumeration.
///
/// HCRST is required to clear the controller's internal state (cached DCBAA,
/// command ring pointers, etc.). Without it, the controller enters HCE when
/// we try to use new data structures. However, on DWC3, HCRST also clears
/// port connection state. We must wait for the PHY to re-detect connected
/// devices after reset (~100-200ms for USB2).
///
/// Uses physical addresses for DMA since IOMMU is not available.
fn try_initialize_xhci(device: &mut Dwc3Device) -> Result<(), &'static str> {
    let dma = device.dma.as_ref().ok_or("No DMA buffers")?;

    if dma.total_size() < 0x5000 {
        return Err("DMA region too small");
    }

    // Remember how many connected ports we had before HCRST
    let had_connected = device.port_status_cache.iter().any(|p| p.connected);

    // HCRST: required to clear controller internal state so our new
    // DCBAA/command ring/event ring are accepted without HCE.
    let _ = device.xhci_ctrl.reset();

    // Clear any error status bits (RW1C)
    device.xhci_ctrl.clear_error_status();

    // Re-apply DWC3 global registers — HCRST may reset them to defaults.
    let ctrl_addr = device.xhci_ctrl.mmio_base;

    // GUSB2PHYCFG
    {
        let reg = unsafe { core::ptr::read_volatile((ctrl_addr + 0xC200) as *const u32) };
        let mut fixed = reg & !((1u32 << 6) | (1 << 8) | (1 << 30) | (1 << 31) | (0xF << 10));
        if (fixed & (1 << 3)) != 0 {
            fixed |= 5 << 10;
        } else {
            fixed |= 9 << 10;
        }
        if fixed != reg {
            unsafe { core::ptr::write_volatile((ctrl_addr + 0xC200) as *mut u32, fixed); }
        }
    }

    // GFLADJ
    {
        let reg = unsafe { core::ptr::read_volatile((ctrl_addr + 0xC630) as *const u32) };
        let expected = (reg
            & !((0x3Fu32) | (1 << 7) | (0x3FFF << 8) | (0x7F << 24) | (1 << 31)))
            | (1 << 7) | 0x20u32 | (2032u32 << 8) | (10u32 << 24);
        if reg != expected {
            unsafe { core::ptr::write_volatile((ctrl_addr + 0xC630) as *mut u32, expected); }
        }
    }

    // GUCTL
    {
        let reg = unsafe { core::ptr::read_volatile((ctrl_addr + 0xC12C) as *const u32) };
        let expected = (reg & !(0x3FFu32 << 22)) | (41u32 << 22);
        if reg != expected {
            unsafe { core::ptr::write_volatile((ctrl_addr + 0xC12C) as *mut u32, expected); }
        }
    }

    // GUCTL1
    {
        let reg = unsafe { core::ptr::read_volatile((ctrl_addr + 0xC11C) as *const u32) };
        let expected = reg | (1u32 << 16) | (1u32 << 17);
        if reg != expected {
            unsafe { core::ptr::write_volatile((ctrl_addr + 0xC11C) as *mut u32, expected); }
        }
    }

    // Set up DWC3 event buffer
    {
        const EVT_BUF_OFFSET: u64 = 0xB000;
        let evt_vaddr = dma.base_vaddr() + EVT_BUF_OFFSET;
        let evt_iova = dma.base_dma_addr() + EVT_BUF_OFFSET;
        const EVT_BUF_SIZE: u32 = 0x1000;

        unsafe { core::ptr::write_bytes(evt_vaddr as *mut u8, 0, EVT_BUF_SIZE as usize); }
        let _ = m6_syscall::invoke::cache_clean(evt_vaddr, EVT_BUF_SIZE as usize);

        unsafe {
            core::ptr::write_volatile((ctrl_addr + 0xC400) as *mut u32, evt_iova as u32);
            core::ptr::write_volatile((ctrl_addr + 0xC404) as *mut u32, (evt_iova >> 32) as u32);
            core::ptr::write_volatile((ctrl_addr + 0xC408) as *mut u32, EVT_BUF_SIZE);
            let cnt = core::ptr::read_volatile((ctrl_addr + 0xC40C) as *const u32);
            core::ptr::write_volatile((ctrl_addr + 0xC40C) as *mut u32, cnt);
        }
    }

    // After HCRST, DWC3 loses port connection state. Wait for the PHY to
    // re-detect connected devices. USB2 debounce takes ~100ms; we allow
    // up to ~500ms using sched_yield() to avoid burning CPU.
    if had_connected {
        let max_ports = device.xhci_ctrl.max_ports();
        for _ in 0..100 {
            let mut found = false;
            for p in 0..max_ports {
                let ps = device.xhci_ctrl.read_port_status(p);
                if ps.connected {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
            sched_yield();
        }
    }

    // Re-scan ports after reconnection wait
    device.port_status_cache = device.xhci_ctrl.scan_ports();

    let dma_region = xhci::XhciDmaRegion {
        vaddr: dma.base_vaddr(),
        iova: dma.base_dma_addr(),
        size: dma.total_size(),
    };

    // SAFETY: DMA region is valid and mapped
    unsafe {
        device.xhci_ctrl.initialize(&dma_region)?;
    }

    device.xhci_initialized = true;

    // Clear any pending status bits from initialisation
    device.xhci_ctrl.clear_all_status();

    Ok(())
}

/// Halt the driver on fatal error.
fn halt() -> ! {
    loop {
        sched_yield();
    }
}

/// IPC response with label and optional message data.
struct IpcResponse {
    label: u64,
    msg: [u64; 4],
}

impl IpcResponse {
    const fn simple(label: u64) -> Self {
        Self { label, msg: [0; 4] }
    }
}

/// Main service loop
fn service_loop(device: &mut Dwc3Device) -> ! {
    let mut last_response = IpcResponse::simple(0);
    let mut first_message = true;

    loop {
        let result = if first_message {
            first_message = false;
            recv(SERVICE_EP)
        } else {
            reply_recv(
                SERVICE_EP,
                last_response.label,
                last_response.msg[0],
                last_response.msg[1],
                last_response.msg[2],
            )
        };

        match result {
            Ok(ipc_result) => {
                // Check if this is an IRQ notification
                if ipc_result.badge == IRQ_BADGE {
                    process_xhci_interrupts(device);
                    let _ = irq_ack(IRQ_HANDLER);

                    // Don't send reply for IRQ notification
                    first_message = true;
                } else {
                    // Handle IPC request
                    last_response = handle_request(device, ipc_result.label, &ipc_result.msg);
                }
            }
            Err(_) => {
                sched_yield();
                first_message = true;
            }
        }
    }
}

/// Process xHCI transfer events triggered by IRQ.
fn process_xhci_interrupts(device: &mut Dwc3Device) {
    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    // Poll all active interrupt endpoints for data
    for transfer in transfers.iter_mut() {
        if transfer.active && transfer.configured {
            if let Some((data, len)) = device.xhci_ctrl.poll_interrupt_data(
                transfer.slot_id,
                transfer.ep_idx,
            ) {
                // Store data in buffer for later retrieval.
                // Do NOT re-queue here — handle_get_interrupt_data re-queues
                // when the data is actually consumed. Re-queueing in both places
                // creates an extra TRB per cycle, wasting ring entries.
                for i in 0..len.min(8) {
                    transfer.buffer[i] = data[i];
                }
                transfer.buffer_len = len as u8;
                transfer.has_pending_data = true;
            }
        }
    }
}

/// Handle an incoming IPC request
fn handle_request(device: &mut Dwc3Device, label: u64, msg: &[u64; 4]) -> IpcResponse {
    match label & 0xFFFF {
        request::GET_INFO => IpcResponse::simple(response::OK),
        request::GET_STATUS => IpcResponse::simple(
            status::READY | status::USB2_SUPPORTED | status::USB3_SUPPORTED | status::PORTS_POWERED,
        ),
        request::GET_PORT_COUNT => {
            let count = device.xhci_ctrl.max_ports() as u64;
            IpcResponse::simple(response::OK | (count << 16))
        }
        request::GET_PORT_STATUS => IpcResponse::simple(handle_get_port_status(device, msg[0] as u8)),
        request::LIST_DEVICES => IpcResponse::simple(handle_list_devices(device)),
        request::GET_INTERFACES => IpcResponse::simple(handle_get_interfaces(device, msg[0] as u8)),
        request::START_INTERRUPT => {
            let packed = msg[0];
            let device_addr = (packed & 0xFF) as u8;
            let endpoint = ((packed >> 8) & 0xFF) as u8;
            let interval = ((packed >> 16) & 0xFFFF) as u16;
            IpcResponse::simple(handle_start_interrupt(device, device_addr, endpoint, msg[1], interval))
        }
        request::STOP_INTERRUPT => IpcResponse::simple(handle_stop_interrupt(device, msg[0] as u8, msg[1] as u8)),
        request::GET_INTERRUPT_DATA => {
            handle_get_interrupt_data(device, msg[0] as u8, msg[1] as u8)
        }
        request::SET_PROTOCOL => {
            // msg[0] bits 0-7: device_addr, bits 8-15: interface, bits 16-23: protocol (0=boot, 1=report)
            let device_addr = (msg[0] & 0xFF) as u8;
            let interface = ((msg[0] >> 8) & 0xFF) as u8;
            let protocol = ((msg[0] >> 16) & 0xFF) as u8;
            IpcResponse::simple(handle_set_protocol(device, device_addr, interface, protocol))
        }
        request::SET_IDLE => {
            // msg[0] bits 0-7: device_addr, bits 8-15: interface, bits 16-23: duration, bits 24-31: report_id
            let device_addr = (msg[0] & 0xFF) as u8;
            let interface = ((msg[0] >> 8) & 0xFF) as u8;
            let duration = ((msg[0] >> 16) & 0xFF) as u8;
            let report_id = ((msg[0] >> 24) & 0xFF) as u8;
            IpcResponse::simple(handle_set_idle(device, device_addr, interface, duration, report_id))
        }
        _ => IpcResponse::simple(response::ERR_UNSUPPORTED),
    }
}

fn handle_get_port_status(device: &mut Dwc3Device, port: u8) -> u64 {
    if port == 0 {
        return response::ERR_INVALID_PORT;
    }

    let port_idx = port - 1;
    if port_idx >= device.xhci_ctrl.max_ports() {
        return response::ERR_INVALID_PORT;
    }

    // Read fresh port status from registers
    let port_status = device.xhci_ctrl.read_port_status(port_idx);

    // Update cache
    if (port_idx as usize) < device.port_status_cache.len() {
        device.port_status_cache[port_idx as usize] = port_status;
    }

    // Build response
    let mut flags: u64 = 0;
    if port_status.connected {
        flags |= ipc::port_status::CONNECTED;
    }
    if port_status.enabled {
        flags |= ipc::port_status::ENABLED;
    }
    if port_status.powered {
        flags |= ipc::port_status::POWER;
    }
    if port_status.in_reset {
        flags |= ipc::port_status::RESET;
    }
    if port_status.connect_changed {
        flags |= ipc::port_status::CHANGED;
    }

    let speed_flags = match port_status.speed {
        xhci::PortSpeed::Low => ipc::port_status::LOW_SPEED,
        xhci::PortSpeed::Full => ipc::port_status::FULL_SPEED,
        xhci::PortSpeed::High => ipc::port_status::HIGH_SPEED,
        xhci::PortSpeed::Super | xhci::PortSpeed::SuperPlus => ipc::port_status::SUPER_SPEED,
        xhci::PortSpeed::Unknown => 0,
    };
    flags |= speed_flags;

    response::OK | flags
}

fn handle_list_devices(device: &mut Dwc3Device) -> u64 {
    ensure_enumerated(device);
    let count = device.devices.len() as u64;
    response::OK | (count << 16)
}

/// Ensure devices have been enumerated (lazy enumeration)
fn ensure_enumerated(device: &mut Dwc3Device) {
    if device.devices_enumerated {
        return;
    }

    // Reset ALL connected ports to put devices into the Default state.
    // Even if a port is already enabled (from UEFI), the device still has
    // its old UEFI-assigned address. A port reset is required so the device
    // enters the Default state and is ready for fresh address assignment.
    for i in 0..device.port_status_cache.len() {
        let port_status = &device.port_status_cache[i];
        if port_status.connected {
            let port_idx = port_status.port - 1;
            match device.xhci_ctrl.reset_port(port_idx) {
                Ok(new_status) => {
                    device.port_status_cache[i] = new_status;
                }
                Err(_) => {}
            }
        }
    }

    // Collect connected and enabled ports
    let connected_ports: alloc::vec::Vec<_> = device
        .port_status_cache
        .iter()
        .filter(|p| p.connected && p.enabled)
        .cloned()
        .collect();

    // If xHCI is initialised, try to enable slots and enumerate
    if device.xhci_initialized {
        for port_status in &connected_ports {
            match enumerate_device(device, port_status) {
                Ok(dev_info) => {
                    device.devices.push(dev_info);
                }
                Err(e) => {
                    io::puts("[drv-usb-dwc3] enumerate FAIL: ");
                    io::puts(e);
                    io::newline();
                    // Add placeholder for unenumerated device
                    device.devices.push(UsbDeviceInfo {
                        slot_id: 0,
                        port: port_status.port,
                        speed: port_status.speed,
                        interfaces: alloc::vec::Vec::new(),
                    });
                }
            }
        }
    } else {
        // No xHCI init - just create placeholders
        for port_status in &connected_ports {
            device.devices.push(UsbDeviceInfo {
                slot_id: 0,
                port: port_status.port,
                speed: port_status.speed,
                interfaces: alloc::vec::Vec::new(),
            });
        }
    }

    // Clear any pending status bits from enumeration
    device.xhci_ctrl.clear_all_status();

    io::puts("[drv-usb-dwc3] enumerated ");
    io::put_u64(device.devices.len() as u64);
    io::puts(" dev(s)\n");

    device.devices_enumerated = true;
}

/// Enumerate a single device on a port
fn enumerate_device(
    device: &mut Dwc3Device,
    port_status: &xhci::PortStatus,
) -> Result<UsbDeviceInfo, &'static str> {
    // Enable a slot for this device
    let slot_id = device.xhci_ctrl.enable_slot()?;

    // Address the device
    device.xhci_ctrl.address_device(slot_id, port_status.port, port_status.speed)?;

    // Get device descriptor
    let dev_desc = match device.xhci_ctrl.get_device_descriptor(slot_id) {
        Ok(d) => d,
        Err(_) => {
            return Ok(UsbDeviceInfo {
                slot_id,
                port: port_status.port,
                speed: port_status.speed,
                interfaces: alloc::vec::Vec::new(),
            });
        }
    };

    // Get configuration descriptor to find interfaces
    let mut config_buf = [0u8; 256];
    let mut interfaces = alloc::vec::Vec::new();

    if let Ok(len) = device.xhci_ctrl.get_configuration_descriptor(slot_id, 0, &mut config_buf) {
        interfaces = parse_configuration_descriptor(&config_buf[..len]);

        // Send SET_CONFIGURATION to activate the device
        // bConfigurationValue is at offset 5 in the configuration descriptor
        let config_value = if len > 5 { config_buf[5] } else { 1 };
        let mut dummy = [0u8; 0];
        let _ = device.xhci_ctrl.control_transfer(
            slot_id,
            0x00,  // bmRequestType: Host-to-Device, Standard, Device
            0x09,  // bRequest: SET_CONFIGURATION
            config_value as u16,  // wValue: configuration value
            0,     // wIndex
            &mut dummy,
        );
    }

    // Use device class from descriptor if device-level, otherwise from interfaces
    let _ = dev_desc;

    Ok(UsbDeviceInfo {
        slot_id,
        port: port_status.port,
        speed: port_status.speed,
        interfaces,
    })
}

/// Parse configuration descriptor to extract interface information
fn parse_configuration_descriptor(data: &[u8]) -> alloc::vec::Vec<UsbInterfaceInfo> {
    let mut interfaces = alloc::vec::Vec::new();
    // Skip configuration descriptor header (9 bytes)
    if data.len() < 9 {
        return interfaces;
    }
    let mut offset = data[0] as usize; // bLength

    // Parse remaining descriptors
    while offset + 2 <= data.len() {
        let desc_len = data[offset] as usize;
        let desc_type = data[offset + 1];

        if desc_len < 2 || offset + desc_len > data.len() {
            break;
        }

        // Interface descriptor (type = 4)
        if desc_type == xhci::descriptor_type::INTERFACE && desc_len >= 9 {
            let iface = UsbInterfaceInfo {
                interface_number: data[offset + 2],
                class: data[offset + 5],
                subclass: data[offset + 6],
                protocol: data[offset + 7],
                endpoint_address: 0, // Will be filled from endpoint descriptor
                endpoint_interval: 0,
                endpoint_max_packet: 0,
            };
            interfaces.push(iface);
        }

        // Endpoint descriptor (type = 5)
        if desc_type == xhci::descriptor_type::ENDPOINT && desc_len >= 7 {
            // Associate with the most recent interface
            if let Some(iface) = interfaces.last_mut() {
                let ep_addr = data[offset + 2];
                let ep_attrs = data[offset + 3];
                // wMaxPacketSize at offset 4-5 (little-endian)
                let ep_max_packet = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
                let ep_interval = data[offset + 6];

                // For HID, we want the IN interrupt endpoint
                let is_in = (ep_addr & 0x80) != 0;
                let is_interrupt = (ep_attrs & 0x03) == 3;

                if is_in && is_interrupt && iface.endpoint_address == 0 {
                    iface.endpoint_address = ep_addr;
                    iface.endpoint_interval = ep_interval;
                    iface.endpoint_max_packet = ep_max_packet;
                }
            }
        }

        offset += desc_len;
    }

    interfaces
}

fn handle_get_interfaces(device: &mut Dwc3Device, addr: u8) -> u64 {
    ensure_enumerated(device);

    let idx = (addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let dev = &device.devices[idx];
    let iface_count = dev.interfaces.len() as u8;

    if iface_count == 0 {
        // No interfaces enumerated yet - requires GET_DESCRIPTOR (future work)
        return response::OK;
    }

    // Pack first interface into response
    let mut first_iface_packed = 0u32;
    if let Some(iface) = dev.interfaces.first() {
        first_iface_packed = (iface.class as u32)
            | ((iface.subclass as u32) << 8)
            | ((iface.protocol as u32) << 16)
            | ((iface.endpoint_address as u32) << 24);
    }

    response::OK | ((iface_count as u64) << 16) | ((first_iface_packed as u64) << 32)
}

// -- Interrupt transfer management

struct InterruptTransfer {
    device_addr: u8,
    endpoint: u8,
    slot_id: u8,
    interface: u8,
    ep_idx: usize,
    notif_cptr: u64,
    interval_ms: u16,
    buffer: [u8; 8],
    buffer_len: u8,
    has_pending_data: bool,
    active: bool,
    configured: bool,
}

impl InterruptTransfer {
    const fn empty() -> Self {
        Self {
            device_addr: 0,
            endpoint: 0,
            slot_id: 0,
            interface: 0,
            ep_idx: 0,
            notif_cptr: 0,
            interval_ms: 0,
            buffer: [0; 8],
            buffer_len: 0,
            has_pending_data: false,
            active: false,
            configured: false,
        }
    }
}

const MAX_INTERRUPT_TRANSFERS: usize = 8;

static mut INTERRUPT_TRANSFERS: [InterruptTransfer; MAX_INTERRUPT_TRANSFERS] =
    [const { InterruptTransfer::empty() }; MAX_INTERRUPT_TRANSFERS];

fn handle_start_interrupt(
    device: &mut Dwc3Device,
    device_addr: u8,
    endpoint: u8,
    notif_cptr: u64,
    interval_ms: u16,
) -> u64 {
    // Check endpoint is IN direction
    if (endpoint & 0x80) == 0 {
        return response::ERR_INVALID;
    }

    // Find the slot_id for this device
    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_NO_DEVICE;
    }

    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 {
        return response::ERR_INVALID;
    }

    // Find the endpoint interval, max packet size, and interface number
    let mut ep_interval = 10u8; // Default to 10ms
    let mut ep_max_packet = 8u16; // Default to 8 for HID boot protocol
    let mut ep_interface = 0u8;
    for iface in &device.devices[idx].interfaces {
        if iface.endpoint_address == endpoint {
            ep_interval = iface.endpoint_interval;
            ep_interface = iface.interface_number;
            if iface.endpoint_max_packet > 0 {
                ep_max_packet = iface.endpoint_max_packet;
            }
            break;
        }
    }

    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };
    let slot = transfers.iter_mut().find(|t| !t.active);

    match slot {
        Some(transfer) => {
            transfer.device_addr = device_addr;
            transfer.endpoint = endpoint;
            transfer.slot_id = slot_id;
            transfer.interface = ep_interface;
            transfer.notif_cptr = notif_cptr;
            transfer.interval_ms = if interval_ms == 0 { 10 } else { interval_ms };
            transfer.buffer = [0; 8];
            transfer.buffer_len = 0;
            transfer.has_pending_data = false;
            transfer.active = true;
            transfer.configured = false;

            // Configure the interrupt endpoint in xHCI
            match device.xhci_ctrl.configure_interrupt_endpoint(
                slot_id,
                endpoint,
                ep_max_packet,
                ep_interval,
            ) {
                Ok(ep_idx) => {
                    transfer.ep_idx = ep_idx;
                    transfer.configured = true;
                    response::OK
                }
                Err(_) => {
                    transfer.active = false;
                    response::ERR_INVALID
                }
            }
        }
        None => response::ERR_NO_RESOURCES,
    }
}

fn handle_stop_interrupt(_device: &mut Dwc3Device, device_addr: u8, endpoint: u8) -> u64 {
    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    for transfer in transfers.iter_mut() {
        if transfer.active && transfer.device_addr == device_addr && transfer.endpoint == endpoint {
            transfer.active = false;
            return response::OK;
        }
    }

    response::ERR_INVALID
}

fn handle_get_interrupt_data(device: &mut Dwc3Device, device_addr: u8, endpoint: u8) -> IpcResponse {
    // SAFETY: Single-threaded driver
    let transfers = unsafe { &mut *(&raw mut INTERRUPT_TRANSFERS) };

    for transfer in transfers.iter_mut() {
        if transfer.active && transfer.device_addr == device_addr && transfer.endpoint == endpoint {
            // First check if we already have pending data in our buffer
            if transfer.has_pending_data {
                let packed_all = u64::from_le_bytes(transfer.buffer);
                let count = transfer.buffer_len;
                transfer.has_pending_data = false;
                transfer.buffer_len = 0;

                // Re-queue the transfer for the next data
                if transfer.configured {
                    let _ = device.xhci_ctrl.queue_interrupt_transfer(
                        transfer.slot_id,
                        transfer.ep_idx,
                    );
                }

                return IpcResponse {
                    label: response::OK | ((count as u64) << 16),
                    msg: [packed_all, 0, 0, 0],
                };
            }

            // No pending data in buffer, poll xHCI for new data
            if transfer.configured {
                if let Some((data, len)) = device.xhci_ctrl.poll_interrupt_data(
                    transfer.slot_id,
                    transfer.ep_idx,
                ) {
                    let packed_all = u64::from_le_bytes(data);

                    // Re-queue the transfer for the next data
                    let _ = device.xhci_ctrl.queue_interrupt_transfer(
                        transfer.slot_id,
                        transfer.ep_idx,
                    );

                    return IpcResponse {
                        label: response::OK | ((len as u64) << 16),
                        msg: [packed_all, 0, 0, 0],
                    };
                }
            }

            // No data available — interrupt endpoint data arrives via
            // process_transfer_events and is returned on the next poll.
            return IpcResponse::simple(response::OK);
        }
    }

    IpcResponse::simple(response::ERR_INVALID)
}

/// Handle SET_PROTOCOL request (HID class request 0x0B)
/// protocol: 0 = boot protocol, 1 = report protocol
fn handle_set_protocol(device: &mut Dwc3Device, device_addr: u8, interface: u8, protocol: u8) -> u64 {
    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_INVALID;
    }
    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 {
        return response::ERR_INVALID;
    }

    // SET_PROTOCOL: bmRequestType=0x21, bRequest=0x0B
    let mut dummy = [0u8; 0];
    let _ = device.xhci_ctrl.control_transfer(
        slot_id, 0x21, 0x0B,
        protocol as u16, interface as u16,
        &mut dummy,
    );
    // Return OK regardless — some devices don't support SET_PROTOCOL
    response::OK
}

/// Handle SET_IDLE request (HID class request 0x0A)
/// duration: report rate (in 4ms units, 0 = infinite/only report on change)
/// report_id: 0 for all reports, or specific report ID
fn handle_set_idle(device: &mut Dwc3Device, device_addr: u8, interface: u8, duration: u8, report_id: u8) -> u64 {
    let idx = (device_addr as usize).saturating_sub(1);
    if idx >= device.devices.len() {
        return response::ERR_INVALID;
    }
    let slot_id = device.devices[idx].slot_id;
    if slot_id == 0 {
        return response::ERR_INVALID;
    }

    // SET_IDLE: bmRequestType=0x21, bRequest=0x0A
    let mut dummy = [0u8; 0];
    let w_value = ((duration as u16) << 8) | (report_id as u16);
    let _ = device.xhci_ctrl.control_transfer(
        slot_id, 0x21, 0x0A,
        w_value, interface as u16,
        &mut dummy,
    );
    // Return OK regardless — some devices don't support SET_IDLE
    response::OK
}
