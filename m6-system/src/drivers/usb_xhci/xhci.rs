//! Direct xHCI Register Access Module
//!
//! Provides direct access to xHCI registers without going through crab-usb.
//! This is used when firmware (UEFI) has already initialised the controller,
//! allowing us to read hardware state directly rather than running a
//! potentially blocking initialisation sequence.
//!
//! Based on the xHCI specification (eXtensible Host Controller Interface).

#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr::{read_volatile, write_volatile};
use m6_syscall::invoke::{cache_clean, cache_flush, cache_invalidate};

// -- xHCI Register Structures

/// xHCI Capability Registers (read-only, at MMIO base)
#[repr(C)]
pub struct XhciCapRegs {
    /// 0x00: Capability register length (offset to operational registers)
    pub caplength: u8,
    /// 0x01: Reserved
    pub _rsvd: u8,
    /// 0x02: Interface version (BCD, e.g., 0x0100 = 1.0)
    pub hciversion: u16,
    /// 0x04: Structural parameters 1 (max slots [31:24], max intrs [18:8], max ports [7:0])
    pub hcsparams1: u32,
    /// 0x08: Structural parameters 2
    pub hcsparams2: u32,
    /// 0x0C: Structural parameters 3
    pub hcsparams3: u32,
    /// 0x10: Capability parameters 1
    pub hccparams1: u32,
    /// 0x14: Doorbell offset (from cap base)
    pub dboff: u32,
    /// 0x18: Runtime registers offset (from cap base)
    pub rtsoff: u32,
    /// 0x1C: Capability parameters 2
    pub hccparams2: u32,
}

impl XhciCapRegs {
    /// Get maximum number of device slots (bits 7:0 per xHCI spec Table 2-8)
    #[inline]
    pub fn max_slots(&self) -> u8 {
        (self.hcsparams1 & 0xFF) as u8
    }

    /// Get maximum number of interrupters (bits 18:8)
    #[inline]
    pub fn max_intrs(&self) -> u16 {
        ((self.hcsparams1 >> 8) & 0x7FF) as u16
    }

    /// Get maximum number of ports (bits 31:24 per xHCI spec Table 2-8)
    #[inline]
    pub fn max_ports(&self) -> u8 {
        ((self.hcsparams1 >> 24) & 0xFF) as u8
    }

    /// Check if 64-bit addressing is supported
    #[inline]
    pub fn ac64(&self) -> bool {
        (self.hccparams1 & 0x01) != 0
    }

    /// Get context size (0 = 32 bytes, 1 = 64 bytes)
    #[inline]
    pub fn context_size(&self) -> usize {
        if (self.hccparams1 & 0x04) != 0 { 64 } else { 32 }
    }

    /// Get page size (power of 2)
    #[inline]
    pub fn page_size_bits(&self) -> u8 {
        // Bits 15:12 encode page size as 2^(12+n)
        let ps = ((self.hcsparams2 >> 12) & 0xF) as u8;
        12 + ps
    }

    /// Get max scratchpad buffers required by the controller.
    ///
    /// HCSPARAMS2 bits 31:27 = Max Scratchpad Bufs Hi,
    /// HCSPARAMS2 bits 25:21 = Max Scratchpad Bufs Lo.
    #[inline]
    pub fn max_scratchpad_bufs(&self) -> u32 {
        let hi = (self.hcsparams2 >> 27) & 0x1F;
        let lo = (self.hcsparams2 >> 21) & 0x1F;
        (hi << 5) | lo
    }
}

/// xHCI Operational Registers (at MMIO base + caplength)
#[repr(C)]
pub struct XhciOpRegs {
    /// 0x00: USB Command
    pub usbcmd: u32,
    /// 0x04: USB Status
    pub usbsts: u32,
    /// 0x08: Page Size
    pub pagesize: u32,
    /// 0x0C-0x10: Reserved
    pub _rsvd1: [u32; 2],
    /// 0x14: Device Notification Control
    pub dnctrl: u32,
    /// 0x18: Command Ring Control (64-bit)
    pub crcr_lo: u32,
    pub crcr_hi: u32,
    /// 0x20-0x28: Reserved
    pub _rsvd2: [u32; 4],
    /// 0x30: Device Context Base Address Array Pointer (64-bit)
    pub dcbaap_lo: u32,
    pub dcbaap_hi: u32,
    /// 0x38: Configure
    pub config: u32,
}

/// USB Command register bits
pub mod usbcmd {
    /// Run/Stop - 0=stop, 1=run
    pub const RUN_STOP: u32 = 1 << 0;
    /// Host Controller Reset
    pub const HCRST: u32 = 1 << 1;
    /// Interrupter Enable
    pub const INTE: u32 = 1 << 2;
    /// Host System Error Enable
    pub const HSEE: u32 = 1 << 3;
    /// Light Host Controller Reset
    pub const LHCRST: u32 = 1 << 7;
    /// Controller Save State
    pub const CSS: u32 = 1 << 8;
    /// Controller Restore State
    pub const CRS: u32 = 1 << 9;
    /// Enable Wrap Event
    pub const EWE: u32 = 1 << 10;
    /// Enable U3 MFINDEX Stop
    pub const EU3S: u32 = 1 << 11;
}

/// USB Status register bits
pub mod usbsts {
    /// Host Controller Halted
    pub const HCH: u32 = 1 << 0;
    /// Host System Error
    pub const HSE: u32 = 1 << 2;
    /// Event Interrupt
    pub const EINT: u32 = 1 << 3;
    /// Port Change Detect
    pub const PCD: u32 = 1 << 4;
    /// Save State Status
    pub const SSS: u32 = 1 << 8;
    /// Restore State Status
    pub const RSS: u32 = 1 << 9;
    /// Save/Restore Error
    pub const SRE: u32 = 1 << 10;
    /// Controller Not Ready
    pub const CNR: u32 = 1 << 11;
    /// Host Controller Error
    pub const HCE: u32 = 1 << 12;
}

/// Port Status and Control Register
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XhciPortRegs {
    /// Port Status and Control
    pub portsc: u32,
    /// Port Power Management Status and Control
    pub portpmsc: u32,
    /// Port Link Info
    pub portli: u32,
    /// Port Hardware LPM Control
    pub porthlpmc: u32,
}

/// Port Status and Control Register bits
pub mod portsc {
    /// Current Connect Status
    pub const CCS: u32 = 1 << 0;
    /// Port Enabled/Disabled
    pub const PED: u32 = 1 << 1;
    /// Over-current Active
    pub const OCA: u32 = 1 << 3;
    /// Port Reset
    pub const PR: u32 = 1 << 4;
    /// Port Link State (bits 8:5)
    pub const PLS_MASK: u32 = 0xF << 5;
    pub const PLS_SHIFT: u32 = 5;
    /// Port Power
    pub const PP: u32 = 1 << 9;
    /// Port Speed (bits 13:10)
    pub const SPEED_MASK: u32 = 0xF << 10;
    pub const SPEED_SHIFT: u32 = 10;
    /// Port Indicator Control (bits 15:14)
    pub const PIC_MASK: u32 = 0x3 << 14;
    /// Port Link State Write Strobe
    pub const LWS: u32 = 1 << 16;
    /// Connect Status Change
    pub const CSC: u32 = 1 << 17;
    /// Port Enabled/Disabled Change
    pub const PEC: u32 = 1 << 18;
    /// Warm Port Reset Change
    pub const WRC: u32 = 1 << 19;
    /// Over-current Change
    pub const OCC: u32 = 1 << 20;
    /// Port Reset Change
    pub const PRC: u32 = 1 << 21;
    /// Port Link State Change
    pub const PLC: u32 = 1 << 22;
    /// Port Config Error Change
    pub const CEC: u32 = 1 << 23;
    /// Cold Attach Status
    pub const CAS: u32 = 1 << 24;
    /// Wake on Connect Enable
    pub const WCE: u32 = 1 << 25;
    /// Wake on Disconnect Enable
    pub const WDE: u32 = 1 << 26;
    /// Wake on Over-current Enable
    pub const WOE: u32 = 1 << 27;
    /// Device Removable
    pub const DR: u32 = 1 << 30;
    /// Warm Port Reset
    pub const WPR: u32 = 1 << 31;

    /// Preserve mask - bits that should be preserved when writing
    pub const PRESERVE_MASK: u32 = PP | PIC_MASK | LWS | WCE | WDE | WOE;
    /// Change bits - write 1 to clear
    pub const CHANGE_MASK: u32 = CSC | PEC | WRC | OCC | PRC | PLC | CEC;
}

/// USB port speed values (from portsc SPEED field)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PortSpeed {
    /// Not connected or unknown
    Unknown = 0,
    /// Full Speed (12 Mbps)
    Full = 1,
    /// Low Speed (1.5 Mbps)
    Low = 2,
    /// High Speed (480 Mbps)
    High = 3,
    /// SuperSpeed (5 Gbps)
    Super = 4,
    /// SuperSpeed+ (10 Gbps)
    SuperPlus = 5,
}

impl From<u8> for PortSpeed {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Full,
            2 => Self::Low,
            3 => Self::High,
            4 => Self::Super,
            5 => Self::SuperPlus,
            _ => Self::Unknown,
        }
    }
}

impl PortSpeed {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Full => "full",
            Self::Low => "low",
            Self::High => "high",
            Self::Super => "super",
            Self::SuperPlus => "super+",
        }
    }
}

/// Port link state values
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkState {
    U0 = 0,      // On (USB3) / Enabled (USB2)
    U1 = 1,      // Standby (USB3 only)
    U2 = 2,      // Sleep (USB3 only)
    U3 = 3,      // Suspend
    Disabled = 4,
    RxDetect = 5,
    Inactive = 6,
    Polling = 7,
    Recovery = 8,
    HotReset = 9,
    ComplianceMode = 10,
    TestMode = 11,
    Resume = 15,
}

impl From<u8> for LinkState {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::U0,
            1 => Self::U1,
            2 => Self::U2,
            3 => Self::U3,
            4 => Self::Disabled,
            5 => Self::RxDetect,
            6 => Self::Inactive,
            7 => Self::Polling,
            8 => Self::Recovery,
            9 => Self::HotReset,
            10 => Self::ComplianceMode,
            11 => Self::TestMode,
            15 => Self::Resume,
            _ => Self::Disabled,
        }
    }
}

/// Port status information
#[derive(Clone, Copy, Debug)]
pub struct PortStatus {
    /// Port number (1-based)
    pub port: u8,
    /// Device connected
    pub connected: bool,
    /// Port enabled
    pub enabled: bool,
    /// Port powered
    pub powered: bool,
    /// Device speed
    pub speed: PortSpeed,
    /// Link state
    pub link_state: LinkState,
    /// Port in reset
    pub in_reset: bool,
    /// Connect status changed
    pub connect_changed: bool,
    /// Raw portsc value
    pub raw_portsc: u32,
}

impl PortStatus {
    /// Create an invalid/empty port status
    pub fn invalid() -> Self {
        Self {
            port: 0,
            connected: false,
            enabled: false,
            powered: false,
            speed: PortSpeed::Unknown,
            link_state: LinkState::Disabled,
            in_reset: false,
            connect_changed: false,
            raw_portsc: 0,
        }
    }

    /// Parse from raw portsc value
    pub fn from_portsc(port: u8, portsc: u32) -> Self {
        let speed_val = ((portsc & portsc::SPEED_MASK) >> portsc::SPEED_SHIFT) as u8;
        let pls_val = ((portsc & portsc::PLS_MASK) >> portsc::PLS_SHIFT) as u8;

        Self {
            port,
            connected: (portsc & portsc::CCS) != 0,
            enabled: (portsc & portsc::PED) != 0,
            powered: (portsc & portsc::PP) != 0,
            speed: PortSpeed::from(speed_val),
            link_state: LinkState::from(pls_val),
            in_reset: (portsc & portsc::PR) != 0,
            connect_changed: (portsc & portsc::CSC) != 0,
            raw_portsc: portsc,
        }
    }
}

// -- xHCI Controller State

/// Command ring size (number of TRBs)
const COMMAND_RING_SIZE: usize = 64;
/// Event ring size (number of TRBs)
const EVENT_RING_SIZE: usize = 64;
/// Transfer ring size (number of TRBs) - last entry is Link TRB
const TRANSFER_RING_SIZE: usize = 64;
/// Maximum supported device slots
const MAX_DEVICE_SLOTS: usize = 32;

/// DMA memory region for xHCI structures
pub struct XhciDmaRegion {
    /// Virtual address (CPU accessible)
    pub vaddr: u64,
    /// IOVA/Physical address (device accessible)
    pub iova: u64,
    /// Size in bytes
    pub size: usize,
}

impl XhciDmaRegion {
    /// Get a sub-region at offset
    pub fn offset(&self, offset: usize) -> Option<Self> {
        if offset >= self.size {
            return None;
        }
        Some(Self {
            vaddr: self.vaddr + offset as u64,
            iova: self.iova + offset as u64,
            size: self.size - offset,
        })
    }
}

/// State for an interrupt endpoint
#[derive(Clone, Copy, Default)]
struct InterruptEndpointState {
    /// Transfer Ring virtual address
    ring_vaddr: u64,
    /// Transfer Ring IOVA
    ring_iova: u64,
    /// Current enqueue index
    enqueue_idx: usize,
    /// Producer cycle state
    cycle: bool,
    /// Endpoint is configured and active
    active: bool,
    /// Endpoint address (with direction bit)
    endpoint_addr: u8,
    /// Endpoint ID (DCI - Device Context Index)
    endpoint_id: u8,
    /// Maximum packet size
    max_packet_size: u16,
    /// Polling interval
    interval: u8,
    /// Pending data buffer (for received interrupt data)
    pending_data: [u8; 8],
    /// Pending data length
    pending_len: u8,
    /// Has pending data ready to read
    has_pending: bool,
}

/// Maximum interrupt endpoints per device
const MAX_INTERRUPT_EPS: usize = 4;

/// Per-slot state for device enumeration
struct SlotState {
    /// Output Device Context virtual address
    output_ctx_vaddr: u64,
    /// Output Device Context IOVA
    output_ctx_iova: u64,
    /// Input Context virtual address
    input_ctx_vaddr: u64,
    /// Input Context IOVA
    input_ctx_iova: u64,
    /// EP0 Transfer Ring virtual address
    ep0_ring_vaddr: u64,
    /// EP0 Transfer Ring IOVA
    ep0_ring_iova: u64,
    /// EP0 Transfer Ring enqueue index
    ep0_enqueue_idx: usize,
    /// EP0 Transfer Ring cycle bit
    ep0_cycle: bool,
    /// Device has been addressed
    addressed: bool,
    /// Root hub port number (1-based)
    port: u8,
    /// Device speed
    speed: PortSpeed,
    /// Interrupt endpoints
    interrupt_eps: [InterruptEndpointState; MAX_INTERRUPT_EPS],
    /// Number of configured interrupt endpoints
    interrupt_ep_count: usize,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            output_ctx_vaddr: 0,
            output_ctx_iova: 0,
            input_ctx_vaddr: 0,
            input_ctx_iova: 0,
            ep0_ring_vaddr: 0,
            ep0_ring_iova: 0,
            ep0_enqueue_idx: 0,
            ep0_cycle: true,
            addressed: false,
            port: 0,
            speed: PortSpeed::Unknown,
            interrupt_eps: [InterruptEndpointState::default(); MAX_INTERRUPT_EPS],
            interrupt_ep_count: 0,
        }
    }
}

/// xHCI controller state for direct register access
pub struct XhciController {
    /// MMIO base address
    pub mmio_base: u64,
    /// Capability register length (offset to operational registers)
    cap_length: u8,
    /// Doorbell offset from cap base
    db_offset: u32,
    /// Runtime registers offset from cap base
    rts_offset: u32,
    /// Maximum number of ports
    max_ports: u8,
    /// Maximum number of device slots
    max_slots: u8,
    /// Context size (32 or 64 bytes)
    context_size: usize,
    /// Controller is running
    running: bool,
    /// Command ring state
    command_ring: Option<CommandRing>,
    /// Event ring state
    event_ring: Option<EventRing>,
    /// Device Context Base Address Array
    dcbaa: Option<Dcbaa>,
    /// DMA region base virtual address
    dma_vaddr: u64,
    /// DMA region base IOVA
    dma_iova: u64,
    /// DMA region size
    dma_size: usize,
    /// Scratch buffer virtual address (for control transfer data)
    scratch_vaddr: u64,
    /// Scratch buffer IOVA
    scratch_iova: u64,
    /// Per-slot state
    slots: [SlotState; MAX_DEVICE_SLOTS],
    /// Enabled slots bitmap
    slot_enabled: [bool; MAX_DEVICE_SLOTS],
    /// Diagnostic: last CRCR value written (for debugging)
    last_crcr_write: u64,
    /// Diagnostic: last CRCR readback value (for debugging)
    last_crcr_readback: u64,
    /// Diagnostic: last error USBSTS value
    last_error_usbsts: u32,
    /// Diagnostic: last error USBCMD value
    last_error_usbcmd: u32,
    /// Diagnostic: last command completion code
    last_completion_code: u8,
    /// Stashed events consumed during synchronous polling (control_transfer/submit_command)
    /// that belong to a different slot/endpoint. Drained by process_transfer_events().
    stashed_events: [Option<Trb>; 8],
    /// Number of stashed events
    stashed_count: usize,
    /// Raw HCSPARAMS2 value (for scratchpad buf count etc.)
    hcsparams2: u32,
}

/// Command ring state
struct CommandRing {
    /// Ring buffer virtual address
    vaddr: u64,
    /// Ring buffer IOVA
    iova: u64,
    /// Current enqueue index
    enqueue_idx: usize,
    /// Producer cycle state
    cycle: bool,
}

/// Event ring state
struct EventRing {
    /// Ring buffer virtual address
    vaddr: u64,
    /// Ring buffer IOVA
    iova: u64,
    /// Event Ring Segment Table virtual address
    erst_vaddr: u64,
    /// Event Ring Segment Table IOVA
    erst_iova: u64,
    /// Current dequeue index
    dequeue_idx: usize,
    /// Consumer cycle state
    cycle: bool,
}

/// Device Context Base Address Array
struct Dcbaa {
    /// Array virtual address
    vaddr: u64,
    /// Array IOVA
    iova: u64,
}

impl XhciController {
    /// Create a new xHCI controller instance from MMIO base address.
    ///
    /// # Safety
    ///
    /// The mmio_base must be a valid mapped virtual address for the xHCI MMIO region.
    pub unsafe fn new(mmio_base: u64) -> Self {
        // SAFETY: Caller guarantees mmio_base is valid
        let cap_regs = unsafe { Self::read_cap_regs_static(mmio_base) };

        const EMPTY_INT_EP: InterruptEndpointState = InterruptEndpointState {
            ring_vaddr: 0,
            ring_iova: 0,
            enqueue_idx: 0,
            cycle: true,
            active: false,
            endpoint_addr: 0,
            endpoint_id: 0,
            max_packet_size: 0,
            interval: 0,
            pending_data: [0; 8],
            pending_len: 0,
            has_pending: false,
        };
        const EMPTY_SLOT: SlotState = SlotState {
            output_ctx_vaddr: 0,
            output_ctx_iova: 0,
            input_ctx_vaddr: 0,
            input_ctx_iova: 0,
            ep0_ring_vaddr: 0,
            ep0_ring_iova: 0,
            ep0_enqueue_idx: 0,
            ep0_cycle: true,
            addressed: false,
            port: 0,
            speed: PortSpeed::Unknown,
            interrupt_eps: [EMPTY_INT_EP; MAX_INTERRUPT_EPS],
            interrupt_ep_count: 0,
        };

        Self {
            mmio_base,
            cap_length: cap_regs.caplength,
            db_offset: cap_regs.dboff,
            rts_offset: cap_regs.rtsoff,
            max_ports: cap_regs.max_ports(),
            max_slots: cap_regs.max_slots().min(MAX_DEVICE_SLOTS as u8),
            context_size: cap_regs.context_size(),
            running: false,
            command_ring: None,
            event_ring: None,
            dcbaa: None,
            dma_vaddr: 0,
            dma_iova: 0,
            dma_size: 0,
            scratch_vaddr: 0,
            scratch_iova: 0,
            slots: [EMPTY_SLOT; MAX_DEVICE_SLOTS],
            slot_enabled: [false; MAX_DEVICE_SLOTS],
            last_crcr_write: 0,
            last_crcr_readback: 0,
            last_error_usbsts: 0,
            last_error_usbcmd: 0,
            last_completion_code: 0,
            stashed_events: [None; 8],
            stashed_count: 0,
            hcsparams2: cap_regs.hcsparams2,
        }
    }

    /// Get last error diagnostics (USBSTS, USBCMD when error occurred)
    pub fn get_last_error(&self) -> (u32, u32) {
        (self.last_error_usbsts, self.last_error_usbcmd)
    }

    /// Get last command completion code
    pub fn get_last_completion_code(&self) -> u8 {
        self.last_completion_code
    }

    /// Get doorbell register base address
    #[inline]
    fn doorbell_base(&self) -> u64 {
        self.mmio_base + self.db_offset as u64
    }

    /// Get runtime register base address
    #[inline]
    fn runtime_base(&self) -> u64 {
        self.mmio_base + self.rts_offset as u64
    }

    /// Ring a doorbell
    fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let db_addr = self.doorbell_base() + (slot_id as u64 * 4);
        // SAFETY: Doorbell address is within MMIO region
        unsafe {
            write_volatile(db_addr as *mut u32, target as u32);
            // DSB to ensure doorbell write is ordered
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
            // Force-drain the ARM write buffer by reading back from the device.
            // On ARM, dsb ensures ordering but the write may still be posted
            // in the interconnect. A readback forces it through to the device.
            let _ = read_volatile(self.op_base() as *const u32);
        }
    }

    /// Ring the host controller doorbell (for command ring)
    pub fn ring_command_doorbell(&self) {
        self.ring_doorbell(0, 0);
    }

    /// Ring an endpoint doorbell
    pub fn ring_endpoint_doorbell(&self, slot_id: u8, endpoint_id: u8) {
        self.ring_doorbell(slot_id, endpoint_id);
    }

    /// Initialize the xHCI data structures for enumeration.
    ///
    /// This sets up:
    /// - Device Context Base Address Array (DCBAA)
    /// - Command Ring
    /// - Event Ring
    ///
    /// # Arguments
    ///
    /// * `dma` - DMA memory region (must be at least 16KB, 64-byte aligned)
    ///
    /// # Safety
    ///
    /// The DMA region must be valid and accessible by both CPU and device.
    pub unsafe fn initialize(&mut self, dma: &XhciDmaRegion) -> Result<(), &'static str> {
        // Memory layout in DMA region:
        // 0x0000 - 0x0FFF: DCBAA (4KB, 64-byte aligned)
        // 0x1000 - 0x1FFF: Command Ring (4KB = 256 TRBs)
        // 0x2000 - 0x2FFF: Event Ring (4KB = 256 TRBs)
        // 0x3000 - 0x30FF: Event Ring Segment Table (256 bytes)
        // 0x4000+: Device contexts and transfer rings

        if dma.size < 0x8000 {
            return Err("DMA region too small (need at least 32KB)");
        }

        // Store DMA region info for device context allocation
        self.dma_vaddr = dma.vaddr;
        self.dma_iova = dma.iova;
        self.dma_size = dma.size;

        // Scratch buffer at 0x7000 (4KB for control transfer data stage)
        self.scratch_vaddr = dma.vaddr + 0x7000;
        self.scratch_iova = dma.iova + 0x7000;

        let cap_regs = self.read_cap_regs();

        // Walk xHCI Extended Capabilities to claim USB Legacy Support ownership.
        // USBLEGSUP survives HCRST; if the firmware set BIOS_SEM the
        // controller may inhibit the periodic scheduler.
        let xecp_offset = ((cap_regs.hccparams1 >> 16) & 0xFFFF) as u64;
        if xecp_offset > 0 {
            let mut ecp_ptr = self.mmio_base + xecp_offset * 4;
            for _ in 0..8u32 {
                // SAFETY: MMIO is mapped
                let ecp_dw0 = unsafe { read_volatile(ecp_ptr as *const u32) };
                let cap_id = ecp_dw0 & 0xFF;
                let next = ((ecp_dw0 >> 8) & 0xFF) as u64;

                // USB Legacy Support (id=1): claim ownership from UEFI firmware.
                if cap_id == 1 {
                    let usblegsup = ecp_dw0;
                    let bios_sem = (usblegsup >> 16) & 1;
                    let os_sem = (usblegsup >> 24) & 1;

                    if bios_sem != 0 || os_sem == 0 {
                        // Claim OS ownership: set bit 24, preserve other bits
                        let claim = usblegsup | (1 << 24);
                        unsafe { write_volatile(ecp_ptr as *mut u32, claim); }

                        // Wait for BIOS to release (bit 16 to clear)
                        let mut released = false;
                        for _ in 0..1_000_000u32 {
                            let v = unsafe { read_volatile(ecp_ptr as *const u32) };
                            if (v >> 16) & 1 == 0 {
                                released = true;
                                break;
                            }
                            core::hint::spin_loop();
                        }

                        if !released {
                            // Force-clear BIOS ownership (no SMI handler on ARM)
                            let forced = (unsafe { read_volatile(ecp_ptr as *const u32) })
                                & !(1u32 << 16) | (1u32 << 24);
                            unsafe { write_volatile(ecp_ptr as *mut u32, forced); }
                        }
                    }
                }

                if next == 0 { break; }
                ecp_ptr += next * 4;
            }
        }

        // Wait for controller to be ready
        if !self.is_ready() {
            return Err("Controller not ready");
        }

        // Stop controller if running
        if self.is_running() {
            self.stop();
            // Wait for halt with longer timeout
            let mut halted = false;
            for _ in 0..100000 {
                if self.is_halted() {
                    halted = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !halted {
                return Err("Controller failed to halt");
            }
        }

        // Verify we're halted before proceeding
        if !self.is_halted() {
            return Err("Controller not halted");
        }

        // Setup DCBAA
        self.setup_dcbaa(dma.vaddr, dma.iova)?;

        // Setup Command Ring
        self.setup_command_ring(dma.vaddr + 0x1000, dma.iova + 0x1000)?;

        // Setup Event Ring
        self.setup_event_ring(
            dma.vaddr + 0x2000,
            dma.iova + 0x2000,
            dma.vaddr + 0x3000,
            dma.iova + 0x3000,
        )?;

        // Configure max slots
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped
        unsafe {
            write_volatile(
                (op_base + 0x38) as *mut u32, // CONFIG register
                self.max_slots as u32,
            );
        }

        // Setup scratchpad buffers if required by the controller
        self.setup_scratchpad_buffers(dma)?;

        // Flush CPU caches to ensure DMA structures are visible to hardware.
        // ARM is not cache-coherent for device DMA by default.
        let _ = cache_flush(dma.vaddr, dma.size);

        // Start the controller
        self.start()?;

        Ok(())
    }

    /// Setup the Device Context Base Address Array
    fn setup_dcbaa(&mut self, vaddr: u64, iova: u64) -> Result<(), &'static str> {
        // Zero the DCBAA (256 entries * 8 bytes = 2KB)
        // SAFETY: vaddr is valid DMA memory
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, 256 * 8);
        }

        // Write DCBAAP to operational registers
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped
        unsafe {
            // Read before write for diagnostic
            let pre_lo = read_volatile((op_base + 0x30) as *const u32);
            let pre_hi = read_volatile((op_base + 0x34) as *const u32);
            let _pre_val = (pre_hi as u64) << 32 | pre_lo as u64;

            // DWC3 write-64-hi-lo quirk: write Hi dword first, then Lo.
            // Lo write triggers the hardware to latch the full 64-bit value.
            write_volatile((op_base + 0x34) as *mut u32, (iova >> 32) as u32);
            write_volatile((op_base + 0x30) as *mut u32, iova as u32);

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Read back to verify
            let readback_lo = read_volatile((op_base + 0x30) as *const u32);
            let readback_hi = read_volatile((op_base + 0x34) as *const u32);
            let readback = (readback_hi as u64) << 32 | readback_lo as u64;
            if readback != iova {
                // Store values for potential debugging
                self.last_crcr_write = iova; // Reuse field for DCBAAP diag
                self.last_crcr_readback = readback;
                return Err("DCBAAP write failed verification");
            }
        }

        self.dcbaa = Some(Dcbaa { vaddr, iova });
        Ok(())
    }

    /// Setup scratchpad buffers if the controller requires them.
    ///
    /// The xHCI spec requires the driver to allocate scratchpad pages when
    /// HCSPARAMS2 Max Scratchpad Bufs > 0. Without these, the periodic
    /// scheduler (interrupt/isochronous endpoints) may not function.
    ///
    /// The scratchpad buffer array lives in the DMA region at offset 0xA000.
    /// Scratchpad pages themselves are allocated from the heap to avoid
    /// being constrained by the DMA region size (RK3588 requires 32 pages).
    fn setup_scratchpad_buffers(&mut self, dma: &XhciDmaRegion) -> Result<(), &'static str> {
        let cap_regs = self.read_cap_regs();
        let num_bufs = cap_regs.max_scratchpad_bufs() as usize;

        if num_bufs == 0 {
            return Ok(());
        }

        // Scratchpad Buffer Array at DMA offset 0xA000 (fits in one 4KB page)
        const SP_ARRAY_OFFSET: usize = 0xA000;
        if SP_ARRAY_OFFSET + 0x1000 > dma.size {
            return Err("DMA region too small for scratchpad array");
        }

        let array_vaddr = dma.vaddr + SP_ARRAY_OFFSET as u64;
        let array_iova = dma.iova + SP_ARRAY_OFFSET as u64;

        // Zero the scratchpad buffer array
        // SAFETY: DMA region is mapped and within bounds
        unsafe {
            core::ptr::write_bytes(array_vaddr as *mut u8, 0, 0x1000);
        }

        // Allocate scratchpad pages from the heap and register their physical
        // addresses in the array. Using heap avoids DMA region size constraints.
        let layout = core::alloc::Layout::from_size_align(0x1000, 0x1000)
            .map_err(|_| "invalid scratchpad page layout")?;

        for i in 0..num_bufs {
            // SAFETY: Layout is valid (4KB size, 4KB aligned)
            let page_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if page_ptr.is_null() {
                return Err("failed to allocate scratchpad page");
            }
            let page_vaddr = page_ptr as u64;

            // Flush zeroed page to physical memory so the controller sees it
            let _ = cache_clean(page_vaddr, 0x1000);

            // Get the physical address for this heap page
            let page_phys = crate::rt::get_heap_phys_addr(page_vaddr)
                .ok_or("scratchpad page has no physical address")?;

            // Write page physical address to the Scratchpad Buffer Array
            // SAFETY: array_vaddr is mapped DMA memory
            unsafe {
                write_volatile((array_vaddr + (i as u64) * 8) as *mut u64, page_phys);
            }
        }

        // Flush the scratchpad buffer array to physical memory
        let _ = cache_clean(array_vaddr, 0x1000);

        // Point DCBAAP[0] to the Scratchpad Buffer Array
        let dcbaa = self.dcbaa.as_ref().ok_or("DCBAA not set up")?;
        // SAFETY: DCBAA is mapped DMA memory
        unsafe {
            write_volatile(dcbaa.vaddr as *mut u64, array_iova);
        }
        let _ = cache_clean(dcbaa.vaddr, 8);

        Ok(())
    }

    /// Setup the Command Ring
    fn setup_command_ring(&mut self, vaddr: u64, iova: u64) -> Result<(), &'static str> {
        // Zero the command ring
        let ring_size_bytes = COMMAND_RING_SIZE * 16; // 16 bytes per TRB
        // SAFETY: vaddr is valid DMA memory
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, ring_size_bytes);
        }

        // Write CRCR to operational registers
        // Bit 0 = Ring Cycle State (set to 1)
        let crcr = iova | 1;
        let op_base = self.op_base();

        // SAFETY: MMIO is mapped
        unsafe {
            // First, read current CRCR state
            let pre_lo = read_volatile((op_base + 0x18) as *const u32);
            let _pre_hi = read_volatile((op_base + 0x1C) as *const u32);

            // Check if CRR (Command Ring Running) bit is set - if so, we need to stop it first
            if (pre_lo & (1 << 3)) != 0 {
                // Set CS (Command Stop) bit to stop the command ring
                write_volatile((op_base + 0x18) as *mut u32, pre_lo | (1 << 1));

                // Wait for CRR to clear
                for _ in 0..10000 {
                    let crr = read_volatile((op_base + 0x18) as *const u32) & (1 << 3);
                    if crr == 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }
            }

            // DWC3 write-64-hi-lo quirk: write Hi dword first, then Lo.
            // Lo write triggers the hardware to latch the full 64-bit value.
            write_volatile((op_base + 0x1C) as *mut u32, (crcr >> 32) as u32);
            write_volatile((op_base + 0x18) as *mut u32, crcr as u32);

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Note: xHCI spec says CRCR bits [63:6] (the pointer) return 0 on read.
            // This is by design - "Reading CRCR provides '0' for the pointer portion."
            // We cannot verify the write by reading back. Instead, verify operational
            // registers are accessible by checking PAGESIZE which should be non-zero.
            let pagesize = read_volatile((op_base + 0x08) as *const u32);
            if pagesize == 0 || pagesize == 0xFFFFFFFF {
                self.last_crcr_write = crcr;
                self.last_crcr_readback = 0;
                return Err("CRCR write failed - operational registers may be inaccessible");
            }

            // Store the CRCR value we wrote (since we can't read it back)
            self.last_crcr_write = crcr;
            self.last_crcr_readback = 0; // Expected - CRCR returns 0 on read
        }

        self.command_ring = Some(CommandRing {
            vaddr,
            iova,
            enqueue_idx: 0,
            cycle: true,
        });
        Ok(())
    }

    /// Get last CRCR diagnostic values (for debugging write failures)
    pub fn get_crcr_diag(&self) -> (u64, u64) {
        (self.last_crcr_write, self.last_crcr_readback)
    }

    /// Setup the Event Ring
    fn setup_event_ring(
        &mut self,
        ring_vaddr: u64,
        ring_iova: u64,
        erst_vaddr: u64,
        erst_iova: u64,
    ) -> Result<(), &'static str> {
        // Zero the event ring
        let ring_size_bytes = EVENT_RING_SIZE * 16;
        // SAFETY: vaddr is valid DMA memory
        unsafe {
            core::ptr::write_bytes(ring_vaddr as *mut u8, 0, ring_size_bytes);
        }

        // Setup Event Ring Segment Table Entry
        // Entry format: Ring Segment Base Address (8 bytes) + Ring Segment Size (4 bytes) + Reserved (4 bytes)
        // SAFETY: erst_vaddr is valid DMA memory
        unsafe {
            let erst_entry = erst_vaddr as *mut u64;
            write_volatile(erst_entry, ring_iova);
            write_volatile(erst_entry.add(1), EVENT_RING_SIZE as u64);
        }

        // Write to interrupter 0 registers (at runtime base + 0x20 + interrupter*32)
        let intr0_base = self.runtime_base() + 0x20;
        // SAFETY: MMIO is mapped
        unsafe {
            // IMOD - Interrupt Moderation (offset 0x04)
            // Set to 0 for immediate interrupt delivery (no moderation)
            // Low 16 bits = IMODI (interval), High 16 bits = IMODC (counter)
            write_volatile((intr0_base + 0x04) as *mut u32, 0);

            // ERSTSZ - Event Ring Segment Table Size
            write_volatile((intr0_base + 0x08) as *mut u32, 1);

            // ERDP - Event Ring Dequeue Pointer
            // Write Hi first, then Lo per xHCI spec recommendation.
            // Lo write triggers processing; EHB (bit 3) in Lo is RW1C.
            write_volatile((intr0_base + 0x1C) as *mut u32, (ring_iova >> 32) as u32);
            write_volatile((intr0_base + 0x18) as *mut u32, ring_iova as u32);

            // ERSTBA - Event Ring Segment Table Base Address
            // Write Hi first, then Lo (Lo triggers Event Ring initialisation)
            write_volatile((intr0_base + 0x14) as *mut u32, (erst_iova >> 32) as u32);
            write_volatile((intr0_base + 0x10) as *mut u32, erst_iova as u32);

            // IMAN - Interrupter Management (enable interrupter)
            // Bit 0 = IP (Interrupt Pending) - write 1 to clear
            // Bit 1 = IE (Interrupt Enable) - set to enable interrupts
            // Write 0x3 to clear any pending interrupt and enable
            write_volatile((intr0_base + 0x00) as *mut u32, 0x3);
        }

        self.event_ring = Some(EventRing {
            vaddr: ring_vaddr,
            iova: ring_iova,
            erst_vaddr,
            erst_iova,
            dequeue_idx: 0,
            cycle: true,
        });
        Ok(())
    }

    /// Submit a command TRB and wait for completion.
    ///
    /// Returns the completion TRB on success.
    pub fn submit_command(&mut self, trb: &Trb) -> Result<CommandCompletionTrb, &'static str> {
        let ring = self.command_ring.as_mut().ok_or("Command ring not initialized")?;

        // Write TRB to command ring
        let trb_addr = ring.vaddr + (ring.enqueue_idx * 16) as u64;

        // SAFETY: trb_addr is within DMA region
        unsafe {
            let dest = trb_addr as *mut Trb;
            // Copy TRB with correct cycle bit
            let mut cmd_trb = *trb;
            cmd_trb.set_cycle(ring.cycle);
            write_volatile(dest, cmd_trb);
        }

        // Flush cache to ensure hardware sees the TRB.
        // ARM is not cache-coherent for device DMA.
        let _ = cache_clean(trb_addr, 16);

        // Advance enqueue pointer
        ring.enqueue_idx += 1;
        if ring.enqueue_idx >= COMMAND_RING_SIZE - 1 {
            // Wrap around - add link TRB
            ring.enqueue_idx = 0;
            ring.cycle = !ring.cycle;
        }

        // Ring the doorbell
        self.ring_command_doorbell();

        // Poll for completion (with timeout)
        // Stash non-command events so they aren't lost.
        for iteration in 0..1000 {
            if let Some(event) = self.poll_event() {
                if event.trb_type() == trb_type::COMMAND_COMPLETION {
                    // SAFETY: We've verified the TRB type
                    let completion = unsafe {
                        core::ptr::read_unaligned(&event as *const Trb as *const CommandCompletionTrb)
                    };
                    return Ok(completion);
                }
                // Stash non-command events for later processing
                if self.stashed_count < self.stashed_events.len() {
                    self.stashed_events[self.stashed_count] = Some(event);
                    self.stashed_count += 1;
                }
            }

            // Check for controller errors periodically
            if iteration == 500 {
                let (usbcmd, usbsts, _, _) = self.get_diagnostics();
                if (usbsts & 0x1000) != 0 {
                    // HCE - Host Controller Error
                    self.last_error_usbsts = usbsts;
                    self.last_error_usbcmd = usbcmd;
                    return Err("HCE: Host Controller Error");
                }
                if (usbsts & 0x4) != 0 {
                    // HSE - Host System Error (DMA issue)
                    self.last_error_usbsts = usbsts;
                    self.last_error_usbcmd = usbcmd;
                    return Err("HSE: Host System Error (DMA)");
                }
                if (usbsts & 0x1) != 0 {
                    // HCH - controller halted
                    self.last_error_usbsts = usbsts;
                    self.last_error_usbcmd = usbcmd;
                    return Err("HCH: Controller halted");
                }
            }

            // Delay between polls - longer delays reduce CPU spinning
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        Err("Command timeout")
    }

    /// Poll for an event from the event ring.
    ///
    /// Returns the event TRB if one is available.
    pub fn poll_event(&mut self) -> Option<Trb> {
        // Get runtime base first to avoid borrow conflicts
        let intr0_base = self.runtime_base() + 0x20;

        let ring = self.event_ring.as_mut()?;

        let trb_addr = ring.vaddr + (ring.dequeue_idx * 16) as u64;

        // Invalidate cache to ensure we read fresh data from hardware.
        // ARM is not cache-coherent for device DMA.
        let _ = cache_invalidate(trb_addr, 16);

        // SAFETY: trb_addr is within DMA region
        let trb = unsafe { read_volatile(trb_addr as *const Trb) };

        // Check if this TRB is valid (cycle bit matches)
        if trb.cycle() != ring.cycle {
            return None;
        }

        // Advance dequeue pointer
        ring.dequeue_idx += 1;
        if ring.dequeue_idx >= EVENT_RING_SIZE {
            ring.dequeue_idx = 0;
            ring.cycle = !ring.cycle;
        }

        // Update ERDP (write Hi first, then Lo per xHCI spec)
        let new_dequeue = ring.iova + (ring.dequeue_idx * 16) as u64;
        // Set EHB (Event Handler Busy) bit to clear (RW1C)
        let erdp = new_dequeue | (1 << 3);
        // SAFETY: MMIO is mapped
        unsafe {
            write_volatile((intr0_base + 0x1C) as *mut u32, (erdp >> 32) as u32);
            write_volatile((intr0_base + 0x18) as *mut u32, erdp as u32);

            // Clear IMAN IP (Interrupt Pending) by writing 1 to it
            let iman = read_volatile((intr0_base + 0x00) as *const u32);
            write_volatile((intr0_base + 0x00) as *mut u32, iman | 1);

            // Clear USBSTS.EINT (bit 3) to allow new interrupt assertions
            let op_base = self.mmio_base + self.cap_length as u64;
            let usbsts = read_volatile((op_base + 0x04) as *const u32);
            if (usbsts & (1 << 3)) != 0 {
                write_volatile((op_base + 0x04) as *mut u32, 1 << 3);
            }
        }

        Some(trb)
    }

    /// Enable a slot for a new device.
    ///
    /// Returns the allocated slot ID (1-based).
    pub fn enable_slot(&mut self) -> Result<u8, &'static str> {
        let trb = Trb {
            param: 0,
            status: 0,
            control: (trb_type::ENABLE_SLOT as u32) << 10,
        };

        let completion = self.submit_command(&trb)?;

        if !completion.is_success() {
            return Err("Enable Slot command failed");
        }

        let slot_id = completion.slot_id();
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID returned");
        }

        self.slot_enabled[slot_id as usize - 1] = true;
        Ok(slot_id)
    }

    /// Address a device after enabling its slot.
    ///
    /// This sets up the device context and issues the Address Device command.
    /// After this, the device will have a USB address and control transfers
    /// can be performed on endpoint 0.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID returned by enable_slot (1-based)
    /// * `port` - Root hub port number (1-based)
    /// * `speed` - Device speed
    pub fn address_device(
        &mut self,
        slot_id: u8,
        port: u8,
        speed: PortSpeed,
    ) -> Result<(), &'static str> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID");
        }
        if !self.slot_enabled[slot_id as usize - 1] {
            return Err("Slot not enabled");
        }
        if self.dma_vaddr == 0 {
            return Err("DMA not initialised");
        }

        // Memory layout for this slot (slot_id is 1-based):
        // We only support slot 1 for now due to limited DMA space
        // 0x4000: Output Device Context (4KB)
        // 0x5000: Input Context (4KB)
        // 0x6000: EP0 Transfer Ring (4KB)
        if slot_id != 1 {
            return Err("Only slot 1 supported (limited DMA space)");
        }

        let slot_idx = slot_id as usize - 1;
        let output_ctx_vaddr = self.dma_vaddr + 0x4000;
        let output_ctx_iova = self.dma_iova + 0x4000;
        let input_ctx_vaddr = self.dma_vaddr + 0x5000;
        let input_ctx_iova = self.dma_iova + 0x5000;
        let ep0_ring_vaddr = self.dma_vaddr + 0x6000;
        let ep0_ring_iova = self.dma_iova + 0x6000;

        // Zero the Output Device Context
        // SAFETY: Output context address is within DMA region
        unsafe {
            core::ptr::write_bytes(output_ctx_vaddr as *mut u8, 0, 0x1000);
        }

        // Zero the Input Context
        // SAFETY: Input context address is within DMA region
        unsafe {
            core::ptr::write_bytes(input_ctx_vaddr as *mut u8, 0, 0x1000);
        }

        // Zero the EP0 Transfer Ring and place Link TRB at the last entry
        // SAFETY: EP0 ring address is within DMA region
        unsafe {
            core::ptr::write_bytes(ep0_ring_vaddr as *mut u8, 0, 0x1000);
            // Link TRB at index COMMAND_RING_SIZE-1 points back to ring start
            let link_trb_addr = ep0_ring_vaddr + ((COMMAND_RING_SIZE - 1) * 16) as u64;
            let link_trb = Trb {
                param: ep0_ring_iova,
                status: 0,
                control: (trb_type::LINK as u32) << 10
                    | (1 << 1) // Toggle Cycle (TC)
                    | 1,       // Cycle bit = 1 (matches initial DCS)
            };
            write_volatile(link_trb_addr as *mut Trb, link_trb);
        }

        // Set up Input Control Context
        // Add flags: bit 0 = Slot Context, bit 1 = EP0 Context
        let input_ctrl = InputControlContext::for_address_device();
        // SAFETY: Input context address is valid
        unsafe {
            write_volatile(input_ctx_vaddr as *mut InputControlContext, input_ctrl);
        }

        // Set up Slot Context (at input_ctx + context_size for 64-byte, or +32 for 32-byte)
        // For 64-byte contexts: Input Control Context is at 0, Slot Context at 64
        let slot_ctx_offset = self.context_size;
        let slot_ctx_addr = input_ctx_vaddr + slot_ctx_offset as u64;

        // Determine max packet size based on speed
        let max_packet_size: u16 = match speed {
            PortSpeed::Low => 8,
            PortSpeed::Full => 8,   // Start with 8, update after GET_DESCRIPTOR
            PortSpeed::High => 64,
            PortSpeed::Super | PortSpeed::SuperPlus => 512,
            PortSpeed::Unknown => 8,
        };

        // Build Slot Context
        // info1: Route String (0) | Speed | MTT (0) | Hub (0) | Context Entries (1 for EP0 only)
        let speed_val = match speed {
            PortSpeed::Full => 1,
            PortSpeed::Low => 2,
            PortSpeed::High => 3,
            PortSpeed::Super => 4,
            PortSpeed::SuperPlus => 5,
            PortSpeed::Unknown => 1,
        };
        let slot_ctx = SlotContext {
            info1: (1 << 27) | (speed_val << 20), // Context Entries=1, Speed
            info2: (port as u32) << 16,           // Root Hub Port Number
            info3: 0,
            state: 0,
            _reserved: [0; 4],
        };
        // SAFETY: Slot context address is valid
        unsafe {
            write_volatile(slot_ctx_addr as *mut SlotContext, slot_ctx);
        }

        // Set up EP0 Context (at input_ctx + 2*context_size)
        let ep0_ctx_offset = 2 * self.context_size;
        let ep0_ctx_addr = input_ctx_vaddr + ep0_ctx_offset as u64;

        // Build EP0 Context per xHCI spec Table 6-7:
        // info1 (Dword 0): EP State, Mult, MaxPStreams, LSA, Interval - all 0 for Address Device
        // info2 (Dword 1): CErr[2:1]=3, EP Type[5:3]=4 (Control Bidir), Max Packet Size[31:16]
        // TR Dequeue Pointer with DCS=1 (Dequeue Cycle State)
        let ep0_ctx = EndpointContext {
            info1: 0, // EP State will be set by HC
            info2: (3 << 1) | (4 << 3) | ((max_packet_size as u32) << 16), // CErr=3, EP Type=4, MaxPacketSize
            tr_dequeue_lo: (ep0_ring_iova | 1) as u32, // DCS=1
            tr_dequeue_hi: (ep0_ring_iova >> 32) as u32,
            info3: 8, // Average TRB length = 8 bytes for control
            _reserved: [0; 3],
        };
        // SAFETY: EP0 context address is valid
        unsafe {
            write_volatile(ep0_ctx_addr as *mut EndpointContext, ep0_ctx);
        }

        // Update DCBAA to point to Output Device Context
        // SAFETY: DCBAA address is valid
        unsafe {
            self.set_device_context(slot_id, output_ctx_iova);
        }

        // Flush caches before submitting command
        let _ = cache_flush(output_ctx_vaddr, 0x1000);
        let _ = cache_flush(input_ctx_vaddr, 0x1000);
        let _ = cache_flush(ep0_ring_vaddr, 0x1000);

        // Also flush the DCBAA entry we just wrote
        if let Some(ref dcbaa) = self.dcbaa {
            let dcbaa_entry_addr = dcbaa.vaddr + (slot_id as u64 * 8);
            let _ = cache_flush(dcbaa_entry_addr, 8);
        }

        // Submit Address Device command
        let addr_dev_trb = AddressDeviceTrb::new(input_ctx_iova, slot_id, false);
        // SAFETY: Converting TRB types
        let trb = unsafe {
            core::ptr::read_unaligned(&addr_dev_trb as *const AddressDeviceTrb as *const Trb)
        };

        let completion = self.submit_command(&trb)?;

        if !completion.is_success() {
            let code = completion.completion_code();
            self.last_completion_code = code;
            return match code {
                completion_code::SLOT_NOT_ENABLED => Err("Slot not enabled"),
                completion_code::TRB_ERROR => Err("TRB error"),
                completion_code::USB_TRANSACTION_ERROR => Err("USB transaction error"),
                completion_code::STALL_ERROR => Err("Stall error"),
                17 => Err("Context state error"),
                19 => Err("Invalid slot state"),
                _ => Err("Address Device command failed"),
            };
        }

        // Store slot state
        self.slots[slot_idx] = SlotState {
            output_ctx_vaddr,
            output_ctx_iova,
            input_ctx_vaddr,
            input_ctx_iova,
            ep0_ring_vaddr,
            ep0_ring_iova,
            ep0_enqueue_idx: 0,
            ep0_cycle: true,
            addressed: true,
            port,
            speed,
            interrupt_eps: [InterruptEndpointState::default(); MAX_INTERRUPT_EPS],
            interrupt_ep_count: 0,
        };

        Ok(())
    }

    /// Perform a control transfer on endpoint 0.
    ///
    /// This is used for GET_DESCRIPTOR and other control requests.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID (1-based)
    /// * `request_type` - bmRequestType
    /// * `request` - bRequest
    /// * `value` - wValue
    /// * `index` - wIndex
    /// * `data` - Buffer for data stage (IN transfers) or data to send (OUT transfers)
    ///
    /// Returns the number of bytes transferred on success.
    pub fn control_transfer(
        &mut self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
    ) -> Result<usize, &'static str> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID");
        }

        let slot_idx = slot_id as usize - 1;
        if !self.slots[slot_idx].addressed {
            return Err("Device not addressed");
        }

        let is_in = (request_type & 0x80) != 0;
        let length = data.len().min(4096) as u16; // Max 4KB for scratch buffer

        // Get slot state
        let slot = &mut self.slots[slot_idx];
        let ep0_ring_vaddr = slot.ep0_ring_vaddr;
        let _ep0_ring_iova = slot.ep0_ring_iova;
        let mut enqueue_idx = slot.ep0_enqueue_idx;
        let mut cycle = slot.ep0_cycle;

        // Use scratch buffer for data stage
        let data_buffer_iova = self.scratch_iova;
        let data_buffer_vaddr = self.scratch_vaddr;

        // For OUT transfers, copy data to scratch buffer
        if !is_in && !data.is_empty() {
            // SAFETY: Scratch buffer is valid
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    data_buffer_vaddr as *mut u8,
                    length as usize,
                );
            }
            let _ = cache_clean(data_buffer_vaddr, length as usize);
        }

        // Queue Setup Stage TRB
        let setup_trb_addr = ep0_ring_vaddr + (enqueue_idx * 16) as u64;
        let setup_trb = Trb {
            // param: bmRequestType | bRequest | wValue | wIndex
            param: (request_type as u64)
                | ((request as u64) << 8)
                | ((value as u64) << 16)
                | ((index as u64) << 32)
                | ((length as u64) << 48),
            status: 8, // TRB Transfer Length = 8 for setup
            control: (trb_type::SETUP_STAGE as u32) << 10
                | (if is_in { 3 } else if length > 0 { 2 } else { 0 }) << 16 // TRT
                | (1 << 6) // IDT (Immediate Data)
                | if cycle { 1 } else { 0 },
        };
        // SAFETY: TRB address is valid
        unsafe {
            write_volatile(setup_trb_addr as *mut Trb, setup_trb);
        }
        enqueue_idx += 1;

        // Queue Data Stage TRB (if length > 0)
        if length > 0 {
            let data_trb_addr = ep0_ring_vaddr + (enqueue_idx * 16) as u64;
            let data_trb = Trb {
                param: data_buffer_iova,
                status: length as u32,
                control: (trb_type::DATA_STAGE as u32) << 10
                    | (if is_in { 1 } else { 0 }) << 16 // DIR
                    | if cycle { 1 } else { 0 },
            };
            // SAFETY: TRB address is valid
            unsafe {
                write_volatile(data_trb_addr as *mut Trb, data_trb);
            }
            enqueue_idx += 1;
        }

        // Queue Status Stage TRB
        let status_trb_addr = ep0_ring_vaddr + (enqueue_idx * 16) as u64;
        let status_trb = Trb {
            param: 0,
            status: 0,
            control: (trb_type::STATUS_STAGE as u32) << 10
                | (if is_in { 0 } else { 1 }) << 16 // DIR opposite of data stage
                | (1 << 5) // IOC (Interrupt on Completion)
                | if cycle { 1 } else { 0 },
        };
        // SAFETY: TRB address is valid
        unsafe {
            write_volatile(status_trb_addr as *mut Trb, status_trb);
        }
        enqueue_idx += 1;

        // Wrap around via Link TRB (placed at COMMAND_RING_SIZE - 1)
        if enqueue_idx >= COMMAND_RING_SIZE - 1 {
            // Update Link TRB cycle bit to match current producer cycle
            // SAFETY: Link TRB address is within DMA region
            unsafe {
                let link_trb_addr = ep0_ring_vaddr + ((COMMAND_RING_SIZE - 1) * 16) as u64;
                let link_trb = Trb {
                    param: self.slots[slot_idx].ep0_ring_iova,
                    status: 0,
                    control: (trb_type::LINK as u32) << 10
                        | (1 << 1) // Toggle Cycle (TC)
                        | if cycle { 1 } else { 0 },
                };
                write_volatile(link_trb_addr as *mut Trb, link_trb);
            }
            enqueue_idx = 0;
            cycle = !cycle;
        }

        // Update slot state
        self.slots[slot_idx].ep0_enqueue_idx = enqueue_idx;
        self.slots[slot_idx].ep0_cycle = cycle;

        // Flush caches for the TRBs we just wrote
        let _ = cache_clean(ep0_ring_vaddr, 0x1000);

        // Drain DWC3 internal event buffer before ringing doorbell.
        // An overflowed DWC3 event buffer can stall xHCI command processing.
        // SAFETY: MMIO is mapped
        unsafe {
            let gevntcount = read_volatile((self.mmio_base + 0xC40C) as *const u32);
            if gevntcount != 0 {
                write_volatile((self.mmio_base + 0xC40C) as *mut u32, gevntcount);
            }
        }

        // Ring the doorbell for EP0 (endpoint_id = 1 for control endpoint)
        self.ring_endpoint_doorbell(slot_id, 1);

        // Poll for Transfer Event completion
        // Stash events that don't match this control transfer (e.g. interrupt EP data).
        for iteration in 0..2000 {
            if let Some(event) = self.poll_event() {
                if event.trb_type() == trb_type::TRANSFER_EVENT {
                    // Check if this event belongs to our control transfer (EP0, DCI=1)
                    let event_slot = ((event.control >> 24) & 0xFF) as u8;
                    let event_ep = ((event.control >> 16) & 0x1F) as u8;

                    if event_slot == slot_id && event_ep == 1 {
                        // This is our control transfer completion
                        // SAFETY: We've verified the TRB type
                        let transfer_event = unsafe {
                            core::ptr::read_unaligned(&event as *const Trb as *const TransferEventTrb)
                        };

                        let code = transfer_event.completion_code();
                        if code != completion_code::SUCCESS && code != completion_code::SHORT_PACKET {
                            if code == completion_code::STALL_ERROR {
                                let _ = self.reset_endpoint(slot_id, 1);
                                return Err("Stall error (recovered)");
                            }
                            return Err("Transfer failed");
                        }

                        let bytes_transferred = if is_in {
                            let _ = cache_invalidate(data_buffer_vaddr, length as usize);
                            let actual_len = (length as usize) - (transfer_event.residual_length() as usize);
                            let copy_len = actual_len.min(data.len());
                            // SAFETY: Scratch buffer and data are valid
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data_buffer_vaddr as *const u8,
                                    data.as_mut_ptr(),
                                    copy_len,
                                );
                            }
                            copy_len
                        } else {
                            length as usize
                        };

                        return Ok(bytes_transferred);
                    }

                    // Different slot or endpoint — stash for later processing
                    if self.stashed_count < self.stashed_events.len() {
                        self.stashed_events[self.stashed_count] = Some(event);
                        self.stashed_count += 1;
                    }
                } else {
                    // Non-transfer event during control transfer poll — stash it
                    if self.stashed_count < self.stashed_events.len() {
                        self.stashed_events[self.stashed_count] = Some(event);
                        self.stashed_count += 1;
                    }
                }
            }

            // Check for controller errors
            if iteration == 1000 {
                let (usbcmd, usbsts, _, _) = self.get_diagnostics();
                if (usbsts & 0x1004) != 0 {
                    self.last_error_usbsts = usbsts;
                    self.last_error_usbcmd = usbcmd;
                    return Err("Controller error during transfer");
                }
            }

            for _ in 0..500 {
                core::hint::spin_loop();
            }
        }

        Err("Transfer timeout")
    }

    /// Reset a halted endpoint to recover from STALL.
    ///
    /// This issues a Reset Endpoint command to clear the halt condition,
    /// then sets the TR Dequeue Pointer back to the beginning of the ring.
    pub fn reset_endpoint(&mut self, slot_id: u8, ep_dci: u8) -> Result<(), &'static str> {
        // Issue Reset Endpoint command
        // This transitions the endpoint from Halted to Stopped state
        let trb = Trb {
            param: 0,
            status: 0,
            control: (trb_type::RESET_ENDPOINT as u32) << 10
                | ((slot_id as u32) << 24)
                | ((ep_dci as u32) << 16),
        };

        let completion = self.submit_command(&trb)?;
        if !completion.is_success() {
            return Err("Reset Endpoint command failed");
        }

        // For EP0, zero old TRBs, re-place Link TRB, reset dequeue pointer
        if ep_dci == 1 {
            let slot_idx = slot_id as usize - 1;
            let ep0_ring_vaddr = self.slots[slot_idx].ep0_ring_vaddr;
            let ep0_ring_iova = self.slots[slot_idx].ep0_ring_iova;

            // Zero old TRBs and re-place Link TRB to avoid stale data
            // SAFETY: EP0 ring is within DMA region
            unsafe {
                core::ptr::write_bytes(ep0_ring_vaddr as *mut u8, 0, 0x1000);
                let link_trb_addr = ep0_ring_vaddr + ((COMMAND_RING_SIZE - 1) * 16) as u64;
                let link_trb = Trb {
                    param: ep0_ring_iova,
                    status: 0,
                    control: (trb_type::LINK as u32) << 10
                        | (1 << 1) // Toggle Cycle (TC)
                        | 1,       // Cycle bit = 1 (matches initial DCS)
                };
                write_volatile(link_trb_addr as *mut Trb, link_trb);
            }
            let _ = cache_clean(ep0_ring_vaddr, 0x1000);

            // Reset software tracking
            self.slots[slot_idx].ep0_enqueue_idx = 0;
            self.slots[slot_idx].ep0_cycle = true;

            // Issue Set TR Dequeue Pointer command
            // param = new dequeue pointer with DCS bit in bit 0
            let set_deq_trb = Trb {
                param: ep0_ring_iova | 1, // DCS = 1 (cycle bit)
                status: 0,
                control: (trb_type::SET_TR_DEQUEUE as u32) << 10
                    | ((slot_id as u32) << 24)
                    | ((ep_dci as u32) << 16),
            };

            let deq_completion = self.submit_command(&set_deq_trb)?;
            if !deq_completion.is_success() {
                return Err("Set TR Dequeue Pointer failed");
            }
        }

        Ok(())
    }

    /// Get device descriptor from a device.
    ///
    /// Returns the device descriptor on success.
    pub fn get_device_descriptor(
        &mut self,
        slot_id: u8,
    ) -> Result<DeviceDescriptor, &'static str> {
        let mut buf = [0u8; 18];
        let len = self.control_transfer(
            slot_id,
            0x80, // Device to Host, Standard, Device
            0x06, // GET_DESCRIPTOR
            (descriptor_type::DEVICE as u16) << 8,
            0,
            &mut buf,
        )?;

        if len < 8 {
            return Err("Device descriptor too short");
        }

        // SAFETY: Buffer is properly aligned and sized
        let desc = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const DeviceDescriptor) };
        Ok(desc)
    }

    /// Get configuration descriptor from a device.
    ///
    /// Returns the raw configuration descriptor data (includes interface and endpoint descriptors).
    pub fn get_configuration_descriptor(
        &mut self,
        slot_id: u8,
        config_index: u8,
        buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        // First get just the header to find total length
        let mut header = [0u8; 9];
        let len = self.control_transfer(
            slot_id,
            0x80,
            0x06,
            (descriptor_type::CONFIGURATION as u16) << 8 | config_index as u16,
            0,
            &mut header,
        )?;

        if len < 4 {
            return Err("Configuration descriptor header too short");
        }

        // Parse total length from header
        let total_length = u16::from_le_bytes([header[2], header[3]]) as usize;
        let read_length = total_length.min(buf.len());

        // Now get the full descriptor
        self.control_transfer(
            slot_id,
            0x80,
            0x06,
            (descriptor_type::CONFIGURATION as u16) << 8 | config_index as u16,
            0,
            &mut buf[..read_length],
        )
    }

    /// Check if controller is initialized (command ring set up)
    pub fn is_initialized(&self) -> bool {
        self.command_ring.is_some() && self.event_ring.is_some() && self.dcbaa.is_some()
    }

    /// Configure an interrupt IN endpoint for a device.
    ///
    /// This issues a Configure Endpoint command to add the interrupt endpoint
    /// to the device's context, and sets up a transfer ring for it.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID (1-based)
    /// * `endpoint_addr` - Endpoint address (with direction bit, e.g. 0x81 for EP1 IN)
    /// * `max_packet_size` - Maximum packet size (typically 8 for HID)
    /// * `interval` - Polling interval (bInterval from endpoint descriptor)
    ///
    /// Returns endpoint index on success (for use with queue/poll methods).
    pub fn configure_interrupt_endpoint(
        &mut self,
        slot_id: u8,
        endpoint_addr: u8,
        max_packet_size: u16,
        interval: u8,
    ) -> Result<usize, &'static str> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID");
        }
        if !self.slot_enabled[slot_id as usize - 1] {
            return Err("Slot not enabled");
        }

        // Only support IN endpoints for now
        if (endpoint_addr & 0x80) == 0 {
            return Err("Only IN endpoints supported");
        }

        let slot_idx = slot_id as usize - 1;

        // Extract values from slot before calling submit_command
        let (addressed, ep_count, input_ctx_vaddr, input_ctx_iova, output_ctx_vaddr, speed) = {
            let slot = &self.slots[slot_idx];
            (
                slot.addressed,
                slot.interrupt_ep_count,
                slot.input_ctx_vaddr,
                slot.input_ctx_iova,
                slot.output_ctx_vaddr,
                slot.speed,
            )
        };

        if !addressed {
            return Err("Device not addressed");
        }

        // Check if we have room for another interrupt endpoint
        if ep_count >= MAX_INTERRUPT_EPS {
            return Err("Too many interrupt endpoints");
        }

        // Calculate Device Context Index (DCI) for this endpoint
        // DCI = (Endpoint Number * 2) + Direction (0=OUT, 1=IN)
        let ep_num = endpoint_addr & 0x0F;
        let ep_dci = (ep_num * 2) + 1; // +1 for IN direction

        // Allocate transfer ring for this endpoint
        // Use DMA region offset 0x8000 + slot_idx * 0x4000 + ep_idx * 0x1000
        let ep_idx = ep_count;
        let ring_offset = 0x8000 + (slot_idx * 0x4000) + (ep_idx * 0x1000);

        if ring_offset + 0x1000 > self.dma_size {
            return Err("DMA region too small for interrupt endpoint");
        }

        let ring_vaddr = self.dma_vaddr + ring_offset as u64;
        let ring_iova = self.dma_iova + ring_offset as u64;

        // SAFETY: DMA region is mapped and ring_offset is within bounds
        unsafe {
            core::ptr::write_bytes(ring_vaddr as *mut u8, 0, 0x1000);
        }

        // Invalidate CPU cache for the output device context before reading it.
        // The controller wrote this via DMA during Address Device, and ARM is
        // not cache-coherent — stale cache lines would produce zeros.
        let _ = cache_invalidate(output_ctx_vaddr, self.context_size * 33);

        // SAFETY: Input context region is mapped
        unsafe {
            // Clear input context
            core::ptr::write_bytes(input_ctx_vaddr as *mut u8, 0, self.context_size * 33);

            // Input Control Context at offset 0
            // Add flags: bit 0 = Slot Context, bit (ep_dci) = Endpoint Context
            let add_flags = 1u32 | (1u32 << ep_dci);
            write_volatile(input_ctx_vaddr as *mut u32, 0); // drop_flags
            write_volatile((input_ctx_vaddr + 4) as *mut u32, add_flags);

            // Copy current Slot Context from Output Device Context to Input Context
            // Slot Context is at offset context_size in Input Context (after ICC)
            let input_slot_ctx = input_ctx_vaddr + self.context_size as u64;
            core::ptr::copy_nonoverlapping(
                output_ctx_vaddr as *const u8,
                input_slot_ctx as *mut u8,
                self.context_size,
            );

            // Update Context Entries field in Slot Context
            // Context Entries must cover all enabled endpoints
            // Bits [31:27] in dword 0 = number of last valid endpoint context index
            let slot_ctx_dword0 = read_volatile(input_slot_ctx as *const u32);
            let current_entries = (slot_ctx_dword0 >> 27) & 0x1F;
            let new_entries = current_entries.max(ep_dci as u32);
            let new_dword0 = (slot_ctx_dword0 & !(0x1F << 27)) | (new_entries << 27);
            write_volatile(input_slot_ctx as *mut u32, new_dword0);

            // Set up Endpoint Context at offset context_size * (ep_dci + 1)
            let ep_ctx_offset = self.context_size as u64 * (ep_dci as u64 + 1);
            let ep_ctx_addr = input_ctx_vaddr + ep_ctx_offset;

            let ep_ctx = EndpointContext::for_interrupt_in(
                max_packet_size,
                ring_iova,
                interval,
                speed,
            );
            write_volatile(ep_ctx_addr as *mut EndpointContext, ep_ctx);
        }

        // Flush caches before command
        let _ = cache_clean(input_ctx_vaddr, self.context_size * 33);
        let _ = cache_clean(ring_vaddr, 0x1000);

        // Submit Configure Endpoint command
        let trb = Trb {
            param: input_ctx_iova,
            status: 0,
            control: (trb_type::CONFIGURE_ENDPOINT as u32) << 10 | ((slot_id as u32) << 24),
        };

        let completion = self.submit_command(&trb)?;

        if !completion.is_success() {
            return Err("Configure Endpoint command failed");
        }

        // Store endpoint state - borrow slot again after submit_command completes
        // enqueue_idx=0 — ring is empty; we queue the first TRB below
        let slot = &mut self.slots[slot_idx];
        slot.interrupt_eps[ep_idx] = InterruptEndpointState {
            ring_vaddr,
            ring_iova,
            enqueue_idx: 0,
            cycle: true,
            active: true,
            endpoint_addr,
            endpoint_id: ep_dci,
            max_packet_size,
            interval,
            pending_data: [0; 8],
            pending_len: 0,
            has_pending: false,
        };
        slot.interrupt_ep_count += 1;

        // Standard Linux xHCI flow: queue the first TRB AFTER Configure
        // Endpoint succeeds, then ring the doorbell. The pre-queue approach
        // (TRB on ring before Configure Endpoint) may confuse DWC3's
        // periodic scheduler initialisation.
        self.queue_interrupt_transfer(slot_id, ep_idx)?;

        Ok(ep_idx)
    }

    /// Queue an interrupt IN transfer for an endpoint.
    ///
    /// This queues a Normal TRB on the endpoint's transfer ring and rings
    /// the doorbell to start the transfer.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID (1-based)
    /// * `ep_idx` - Endpoint index (returned from configure_interrupt_endpoint)
    pub fn queue_interrupt_transfer(
        &mut self,
        slot_id: u8,
        ep_idx: usize,
    ) -> Result<(), &'static str> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID");
        }

        let slot_idx = slot_id as usize - 1;

        let slot = &mut self.slots[slot_idx];

        if ep_idx >= slot.interrupt_ep_count {
            return Err("Invalid endpoint index");
        }

        let ep = &mut slot.interrupt_eps[ep_idx];
        if !ep.active {
            return Err("Endpoint not active");
        }

        // Allocate a small buffer for the transfer within the transfer ring page
        // Use bytes 0xF00-0xFFF as data buffer (256 bytes, more than enough for HID)
        let data_buffer_vaddr = ep.ring_vaddr + 0xF00;
        let data_buffer_iova = ep.ring_iova + 0xF00;

        // Create Normal TRB for interrupt IN transfer
        // SAFETY: Ring buffer is mapped
        unsafe {
            let trb_addr = ep.ring_vaddr + (ep.enqueue_idx * 16) as u64;

            // Normal TRB: points to data buffer, IOC=1 to get completion event
            let control_val = (trb_type::NORMAL as u32) << 10
                | (1 << 5)  // IOC - Interrupt on Completion
                | (1 << 2)  // ISP - Interrupt on Short Packet (for variable-length HID reports)
                | if ep.cycle { 1 } else { 0 };
            let trb = Trb {
                param: data_buffer_iova,
                // Transfer length = max packet size
                status: ep.max_packet_size as u32,
                // TRB Type = Normal (1), IOC = 1, Cycle bit
                control: control_val,
            };
            write_volatile(trb_addr as *mut Trb, trb);
            let _ = cache_clean(trb_addr, 16);
        }

        // Advance enqueue pointer
        ep.enqueue_idx += 1;
        if ep.enqueue_idx >= TRANSFER_RING_SIZE - 1 {
            // Wrap around - need Link TRB at end
            // SAFETY: Ring buffer is mapped
            unsafe {
                let link_addr = ep.ring_vaddr + ((TRANSFER_RING_SIZE - 1) * 16) as u64;
                let link_trb = Trb {
                    param: ep.ring_iova,
                    status: 0,
                    // TRB Type = Link (6), Toggle Cycle
                    control: (trb_type::LINK as u32) << 10
                        | (1 << 1)  // Toggle Cycle
                        | if ep.cycle { 1 } else { 0 },
                };
                write_volatile(link_addr as *mut Trb, link_trb);
            }
            ep.enqueue_idx = 0;
            ep.cycle = !ep.cycle;
        }

        // Extract values before dropping borrow on self.slots
        let ring_vaddr = ep.ring_vaddr;
        let max_packet_size = ep.max_packet_size;
        let ep_dci = ep.endpoint_id;

        // Flush cache and ensure it's visible to DMA before ringing doorbell
        let _ = cache_clean(ring_vaddr, 0x1000);
        let _ = cache_clean(data_buffer_vaddr, max_packet_size as usize);

        // DSB to ensure cache clean completes before doorbell write
        // SAFETY: DSB barrier instruction
        unsafe {
            core::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }

        // Ring the doorbell (borrow on self.slots is dropped)
        self.ring_endpoint_doorbell(slot_id, ep_dci);

        Ok(())
    }

    /// Force-restart an interrupt endpoint via Stop EP + Set TR Dequeue.
    ///
    /// This bounces the endpoint through the Stopped state, resets its
    /// transfer ring, and re-queues a fresh TRB. Use as a recovery
    /// mechanism when the periodic scheduler fails to fetch TRBs.
    pub fn restart_interrupt_endpoint(
        &mut self,
        slot_id: u8,
        ep_idx: usize,
    ) -> Result<(), &'static str> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return Err("Invalid slot ID");
        }
        let slot_idx = slot_id as usize - 1;
        if ep_idx >= self.slots[slot_idx].interrupt_ep_count {
            return Err("Invalid endpoint index");
        }

        // Copy values before mutable operations
        let ep_dci = self.slots[slot_idx].interrupt_eps[ep_idx].endpoint_id;
        let ring_iova = self.slots[slot_idx].interrupt_eps[ep_idx].ring_iova;
        let ring_vaddr = self.slots[slot_idx].interrupt_eps[ep_idx].ring_vaddr;

        // 1. Stop Endpoint command
        let stop_trb = Trb {
            param: 0,
            status: 0,
            control: (trb_type::STOP_ENDPOINT as u32) << 10
                | ((slot_id as u32) << 24)
                | ((ep_dci as u32) << 16),
        };
        match self.submit_command(&stop_trb) {
            Ok(_) => {}
            Err(_) => {
                // Continue anyway — endpoint might already be stopped
            }
        }

        // 2. Zero the transfer ring and flush to physical memory
        // SAFETY: ring_vaddr is mapped DMA memory
        unsafe {
            core::ptr::write_bytes(ring_vaddr as *mut u8, 0, 0x1000);
        }
        let _ = cache_clean(ring_vaddr, 0x1000);

        // 3. Set TR Dequeue Pointer command — resets ring to base with DCS=1
        let set_deq_trb = Trb {
            param: ring_iova | 1, // DCS = 1
            status: 0,
            control: (trb_type::SET_TR_DEQUEUE as u32) << 10
                | ((slot_id as u32) << 24)
                | ((ep_dci as u32) << 16),
        };
        match self.submit_command(&set_deq_trb) {
            Ok(_) => {}
            Err(_) => {
                return Err("Set TR Dequeue Pointer failed");
            }
        }

        // 4. Reset software ring state
        {
            let ep = &mut self.slots[slot_idx].interrupt_eps[ep_idx];
            ep.enqueue_idx = 0;
            ep.cycle = true;
            ep.has_pending = false;
        }

        // 5. Queue a fresh TRB and ring the doorbell — this transitions
        //    the endpoint from Stopped back to Running.
        self.queue_interrupt_transfer(slot_id, ep_idx)?;

        Ok(())
    }

    /// Poll for interrupt transfer completion and retrieve data.
    ///
    /// This checks the event ring for Transfer Event TRBs related to
    /// interrupt endpoints and returns any received data.
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID (1-based)
    /// * `ep_idx` - Endpoint index
    ///
    /// Returns Some((data, length)) if data is available, None otherwise.
    pub fn poll_interrupt_data(
        &mut self,
        slot_id: u8,
        ep_idx: usize,
    ) -> Option<([u8; 8], usize)> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return None;
        }

        let slot_idx = slot_id as usize - 1;

        // First check if we have pending data already
        {
            let slot = &self.slots[slot_idx];
            if ep_idx >= slot.interrupt_ep_count {
                return None;
            }
            let ep = &slot.interrupt_eps[ep_idx];
            if ep.has_pending {
                let data = ep.pending_data;
                let len = ep.pending_len as usize;
                // Clear pending flag
                let slot = &mut self.slots[slot_idx];
                slot.interrupt_eps[ep_idx].has_pending = false;
                return Some((data, len));
            }
        }

        // Process event ring for transfer events
        self.process_transfer_events();

        // Check again after processing
        let slot = &self.slots[slot_idx];
        if ep_idx >= slot.interrupt_ep_count {
            return None;
        }
        let ep = &slot.interrupt_eps[ep_idx];
        if ep.has_pending {
            let data = ep.pending_data;
            let len = ep.pending_len as usize;
            // Clear pending flag
            let slot = &mut self.slots[slot_idx];
            slot.interrupt_eps[ep_idx].has_pending = false;
            Some((data, len))
        } else {
            None
        }
    }

    /// Dispatch a single transfer event to the appropriate interrupt endpoint.
    ///
    /// Handles Transfer Event TRBs by matching slot_id/ep_id and storing
    /// received data in the endpoint's pending buffer.
    fn dispatch_transfer_event(&mut self, event: &Trb) {
        let slot_id = ((event.control >> 24) & 0xFF) as u8;
        let ep_id = ((event.control >> 16) & 0x1F) as u8;
        let cc = ((event.status >> 24) & 0xFF) as u8;

        // Skip control endpoint events (DCI <= 1)
        if ep_id <= 1 {
            return;
        }

        if slot_id == 0 || (slot_id as usize) > MAX_DEVICE_SLOTS {
            return;
        }

        // cc=26 (Stopped) and cc=27 (Stopped - Length Invalid) are normal
        // responses to a Stop Endpoint command, not errors. The pending TRB
        // was cancelled. cc=23 would be a real Missed Service Error.
        if cc == 26 || cc == 27 {
            return;
        }

        // Handle real MSE (cc=23): re-ring doorbell to retry.
        if cc == 23 {
            self.ring_doorbell(slot_id, ep_id);
            return;
        }

        let slot_idx = slot_id as usize - 1;
        let slot = &mut self.slots[slot_idx];

        for ep in slot.interrupt_eps.iter_mut() {
            if ep.active && ep.endpoint_id == ep_id {
                // 1 = Success, 13 = Short Packet (OK for interrupt)
                if cc == 1 || cc == 13 {
                    let residual = event.status & 0xFFFFFF;
                    let transferred = (ep.max_packet_size as u32).saturating_sub(residual);
                    let data_buffer_vaddr = ep.ring_vaddr + 0xF00;

                    // SAFETY: Data buffer is mapped
                    unsafe {
                        let _ = cache_invalidate(data_buffer_vaddr, 16);
                        let len = (transferred as usize).min(8);
                        for i in 0..len {
                            ep.pending_data[i] =
                                read_volatile((data_buffer_vaddr + i as u64) as *const u8);
                        }
                        ep.pending_len = len as u8;
                        ep.has_pending = true;
                    }
                }
                break;
            }
        }
    }

    /// Process transfer events from the event ring.
    ///
    /// First drains any events stashed during synchronous polling
    /// (control_transfer / submit_command), then reads fresh events
    /// from the hardware event ring.
    pub fn process_transfer_events(&mut self) {
        // Clear EHB (Event Handler Busy) and IMAN.IP before reading events.
        // DWC3 may inhibit the periodic scheduler while EHB is set.
        // Also re-assert IMAN.IE to ensure the interrupter stays enabled.
        {
            let intr0_base = self.mmio_base + self.rts_offset as u64 + 0x20;
            if let Some(ref er) = self.event_ring {
                let erdp = er.iova + (er.dequeue_idx * 16) as u64;
                // SAFETY: MMIO is mapped
                unsafe {
                    // Write ERDP Hi first, then Lo with EHB=1 (RW1C) to clear
                    write_volatile(
                        (intr0_base + 0x1C) as *mut u32,
                        (erdp >> 32) as u32,
                    );
                    write_volatile(
                        (intr0_base + 0x18) as *mut u32,
                        (erdp as u32 & !0xF) | 0x8,
                    );
                    // Clear IMAN.IP (bit 0, RW1C) and ensure IE (bit 1) stays set
                    write_volatile(intr0_base as *mut u32, 0x3);

                    // Drain DWC3 event buffer to prevent overflow.
                    // Write back GEVNTCOUNT to acknowledge consumed events.
                    let gevntcount = read_volatile(
                        (self.mmio_base + 0xC40C) as *const u32
                    );
                    if gevntcount != 0 {
                        write_volatile(
                            (self.mmio_base + 0xC40C) as *mut u32,
                            gevntcount,
                        );
                    }
                }
            }
        }

        // Drain stashed events first — these were consumed from the HW ring
        // during control_transfer() / submit_command() but belong to
        // interrupt endpoints.
        if self.stashed_count > 0 {
            let mut stash = [None; 8];
            let count = self.stashed_count;
            stash[..count].copy_from_slice(&self.stashed_events[..count]);
            self.stashed_count = 0;
            for i in 0..8 {
                self.stashed_events[i] = None;
            }

            for event in stash.iter().flatten() {
                if event.trb_type() == trb_type::TRANSFER_EVENT {
                    self.dispatch_transfer_event(event);
                }
            }
        }

        // Collect events from the hardware ring into a local buffer,
        // advancing SW dequeue pointer as we go. ERDP is updated once
        // after all events are consumed (per xHCI spec recommendation).
        let mut collected = [Trb::new(); 16];
        let mut collected_count = 0usize;
        let mut events_consumed = false;

        {
            let mmio_base = self.mmio_base;
            let rts_offset = self.rts_offset;

            let event_ring = match &mut self.event_ring {
                Some(er) => er,
                None => return,
            };

            for _event_num in 0..16 {
                let event_addr = event_ring.vaddr + (event_ring.dequeue_idx * 16) as u64;

                // SAFETY: Event ring is mapped
                let event = unsafe {
                    let _ = cache_invalidate(event_addr, 16);
                    read_volatile(event_addr as *const Trb)
                };

                let cycle_bit = (event.control & 1) != 0;
                if cycle_bit != event_ring.cycle {
                    break;
                }

                events_consumed = true;

                // Collect transfer events for dispatch after we release the borrow
                let trb_type = event.trb_type();
                if trb_type == trb_type::TRANSFER_EVENT {
                    if collected_count < 16 {
                        collected[collected_count] = event;
                        collected_count += 1;
                    }
                }

                // Advance dequeue pointer
                event_ring.dequeue_idx += 1;
                if event_ring.dequeue_idx >= EVENT_RING_SIZE {
                    event_ring.dequeue_idx = 0;
                    event_ring.cycle = !event_ring.cycle;
                }
            }

            // Update hardware ERDP once after consuming all events.
            // Write Hi first, then Lo per DWC3 requirement. EHB (bit 3) RW1C.
            if events_consumed {
                let intr0_base = mmio_base + rts_offset as u64 + 0x20;
                let erdp = event_ring.iova + (event_ring.dequeue_idx * 16) as u64;
                // SAFETY: MMIO is mapped
                unsafe {
                    write_volatile((intr0_base + 0x1C) as *mut u32, (erdp >> 32) as u32);
                    write_volatile((intr0_base + 0x18) as *mut u32, (erdp | 0x8) as u32);
                }
            }
        } // event_ring borrow released here

        // Dispatch collected transfer events
        for i in 0..collected_count {
            self.dispatch_transfer_event(&collected[i]);
        }

        // Clear USBSTS.EINT (bit 3) by writing 1 to it.
        // Some DWC3 implementations suppress new interrupt assertions if EINT is not cleared.
        let op_base = self.mmio_base + self.cap_length as u64;
        // SAFETY: MMIO is mapped
        unsafe {
            let usbsts = read_volatile((op_base + 0x04) as *const u32);
            if (usbsts & (1 << 3)) != 0 {
                write_volatile((op_base + 0x04) as *mut u32, 1 << 3);
            }
        }

    }

    /// Find endpoint index by endpoint address.
    pub fn find_interrupt_endpoint(&self, slot_id: u8, endpoint_addr: u8) -> Option<usize> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return None;
        }

        let slot_idx = slot_id as usize - 1;
        let slot = &self.slots[slot_idx];

        for (idx, ep) in slot.interrupt_eps.iter().enumerate() {
            if ep.active && ep.endpoint_addr == endpoint_addr {
                return Some(idx);
            }
        }
        None
    }

    /// Get diagnostic information about current controller state.
    /// Returns (usbcmd, usbsts, crcr, dcbaap).
    pub fn get_diagnostics(&self) -> (u32, u32, u64, u64) {
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped
        unsafe {
            let usbcmd = read_volatile((op_base + 0x00) as *const u32);
            let usbsts = read_volatile((op_base + 0x04) as *const u32);
            let crcr_lo = read_volatile((op_base + 0x18) as *const u32);
            let crcr_hi = read_volatile((op_base + 0x1C) as *const u32);
            let dcbaap_lo = read_volatile((op_base + 0x30) as *const u32);
            let dcbaap_hi = read_volatile((op_base + 0x34) as *const u32);

            let crcr = (crcr_hi as u64) << 32 | crcr_lo as u64;
            let dcbaap = (dcbaap_hi as u64) << 32 | dcbaap_lo as u64;

            (usbcmd, usbsts, crcr, dcbaap)
        }
    }

    /// Get event ring dequeue pointer for diagnostics.
    pub fn get_erdp(&self) -> u64 {
        let intr0_base = self.runtime_base() + 0x20;
        // SAFETY: MMIO is mapped
        unsafe {
            let lo = read_volatile((intr0_base + 0x18) as *const u32);
            let hi = read_volatile((intr0_base + 0x1C) as *const u32);
            (hi as u64) << 32 | lo as u64
        }
    }

    /// Dump event ring state for debugging.
    /// Returns (dequeue_idx, cycle, first_4_trbs).
    pub fn debug_event_ring(&self) -> Option<(usize, bool, [(u64, u32, u32); 4])> {
        let event_ring = self.event_ring.as_ref()?;

        let mut trbs = [(0u64, 0u32, 0u32); 4];

        for i in 0..4 {
            let addr = event_ring.vaddr + (i * 16) as u64;
            // SAFETY: Event ring is mapped
            unsafe {
                let _ = cache_invalidate(addr, 16);
                let trb = read_volatile(addr as *const Trb);
                trbs[i] = (trb.param, trb.status, trb.control);
            }
        }

        Some((event_ring.dequeue_idx, event_ring.cycle, trbs))
    }

    /// Debug dump of interrupter registers.
    /// Returns (iman, imod, erstsz, erstba, erdp).
    pub fn debug_interrupter(&self) -> (u32, u32, u32, u64, u64) {
        let intr0_base = self.runtime_base() + 0x20;
        // SAFETY: MMIO is mapped
        unsafe {
            let iman = read_volatile((intr0_base + 0x00) as *const u32);
            let imod = read_volatile((intr0_base + 0x04) as *const u32);
            let erstsz = read_volatile((intr0_base + 0x08) as *const u32);
            let erstba_lo = read_volatile((intr0_base + 0x10) as *const u32);
            let erstba_hi = read_volatile((intr0_base + 0x14) as *const u32);
            let erdp_lo = read_volatile((intr0_base + 0x18) as *const u32);
            let erdp_hi = read_volatile((intr0_base + 0x1C) as *const u32);
            let erstba = ((erstba_hi as u64) << 32) | erstba_lo as u64;
            let erdp = ((erdp_hi as u64) << 32) | erdp_lo as u64;
            (iman, imod, erstsz, erstba, erdp)
        }
    }

    /// Debug dump of interrupt endpoint state.
    pub fn debug_interrupt_ep(&self, slot_id: u8, ep_idx: usize) -> Option<(u8, u8, bool, usize, bool)> {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return None;
        }

        let slot_idx = slot_id as usize - 1;
        let slot = &self.slots[slot_idx];

        if ep_idx >= slot.interrupt_ep_count {
            return None;
        }

        let ep = &slot.interrupt_eps[ep_idx];
        Some((ep.endpoint_addr, ep.endpoint_id, ep.active, ep.enqueue_idx, ep.has_pending))
    }

    /// Get DCBAA virtual address
    pub fn dcbaa_vaddr(&self) -> Option<u64> {
        self.dcbaa.as_ref().map(|d| d.vaddr)
    }

    /// Set device context pointer in DCBAA
    ///
    /// # Safety
    ///
    /// The context_iova must point to a valid device context structure.
    pub unsafe fn set_device_context(&self, slot_id: u8, context_iova: u64) {
        if slot_id == 0 || slot_id as usize > MAX_DEVICE_SLOTS {
            return;
        }
        if let Some(ref dcbaa) = self.dcbaa {
            let entry_addr = dcbaa.vaddr + (slot_id as u64 * 8);
            // SAFETY: Entry address is within DCBAA
            unsafe {
                write_volatile(entry_addr as *mut u64, context_iova);
            }
        }
    }

    /// Read capability registers (static helper for constructor)
    unsafe fn read_cap_regs_static(mmio_base: u64) -> XhciCapRegs {
        // SAFETY: Caller guarantees mmio_base is valid
        let ptr = mmio_base as *const XhciCapRegs;
        unsafe {
            XhciCapRegs {
                caplength: read_volatile(&(*ptr).caplength),
                _rsvd: 0,
                hciversion: read_volatile(&(*ptr).hciversion),
                hcsparams1: read_volatile(&(*ptr).hcsparams1),
                hcsparams2: read_volatile(&(*ptr).hcsparams2),
                hcsparams3: read_volatile(&(*ptr).hcsparams3),
                hccparams1: read_volatile(&(*ptr).hccparams1),
                dboff: read_volatile(&(*ptr).dboff),
                rtsoff: read_volatile(&(*ptr).rtsoff),
                hccparams2: read_volatile(&(*ptr).hccparams2),
            }
        }
    }

    /// Get the operational registers base address
    #[inline]
    fn op_base(&self) -> u64 {
        self.mmio_base + self.cap_length as u64
    }

    /// Get the port registers base address (op_base + 0x400)
    #[inline]
    fn port_base(&self) -> u64 {
        self.op_base() + 0x400
    }

    /// Get the address of a specific port's registers (0-indexed)
    #[inline]
    fn port_regs_addr(&self, port: u8) -> u64 {
        self.port_base() + (port as u64 * 0x10)
    }

    /// Read capability registers
    pub fn read_cap_regs(&self) -> XhciCapRegs {
        // SAFETY: mmio_base was validated at construction
        unsafe { Self::read_cap_regs_static(self.mmio_base) }
    }

    /// Read operational registers
    pub fn read_op_regs(&self) -> XhciOpRegs {
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped and op_base is calculated from valid cap_length
        unsafe {
            let ptr = op_base as *const XhciOpRegs;
            XhciOpRegs {
                usbcmd: read_volatile(&(*ptr).usbcmd),
                usbsts: read_volatile(&(*ptr).usbsts),
                pagesize: read_volatile(&(*ptr).pagesize),
                _rsvd1: [0; 2],
                dnctrl: read_volatile(&(*ptr).dnctrl),
                crcr_lo: read_volatile(&(*ptr).crcr_lo),
                crcr_hi: read_volatile(&(*ptr).crcr_hi),
                _rsvd2: [0; 4],
                dcbaap_lo: read_volatile(&(*ptr).dcbaap_lo),
                dcbaap_hi: read_volatile(&(*ptr).dcbaap_hi),
                config: read_volatile(&(*ptr).config),
            }
        }
    }

    /// Write USBCMD register
    pub fn write_usbcmd(&self, val: u32) {
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped
        unsafe {
            write_volatile((op_base + 0x00) as *mut u32, val);
        }
    }

    /// Write USBSTS register (for clearing status bits)
    pub fn write_usbsts(&self, val: u32) {
        let op_base = self.op_base();
        // SAFETY: MMIO is mapped
        unsafe {
            write_volatile((op_base + 0x04) as *mut u32, val);
        }
    }

    /// Read port status for a specific port (0-indexed)
    pub fn read_port_status(&self, port: u8) -> PortStatus {
        if port >= self.max_ports {
            return PortStatus::invalid();
        }

        let port_addr = self.port_regs_addr(port);
        // SAFETY: Port address is within MMIO region
        let portsc = unsafe { read_volatile(port_addr as *const u32) };

        PortStatus::from_portsc(port + 1, portsc)
    }

    /// Read raw PORTSC register value for diagnostics (0-indexed port)
    pub fn read_raw_portsc(&self, port: u8) -> u32 {
        if port >= self.max_ports {
            return 0xFFFF_FFFF;
        }
        let port_addr = self.port_regs_addr(port);
        // SAFETY: Port address is within MMIO region
        unsafe { read_volatile(port_addr as *const u32) }
    }

    /// Write port status (for clearing change bits or initiating actions)
    ///
    /// # Safety
    ///
    /// Caller must ensure the value is appropriate for the port state.
    pub unsafe fn write_portsc(&self, port: u8, val: u32) {
        if port >= self.max_ports {
            return;
        }

        let port_addr = self.port_regs_addr(port);
        // SAFETY: Port address is within MMIO region
        unsafe {
            write_volatile(port_addr as *mut u32, val);
        }
    }

    /// Clear port status change bits
    pub fn clear_port_changes(&self, port: u8) {
        if port >= self.max_ports {
            return;
        }

        let port_addr = self.port_regs_addr(port);
        // SAFETY: Port address is within MMIO region
        unsafe {
            let current = read_volatile(port_addr as *const u32);
            // Preserve important bits, write 1 to clear change bits
            let new_val = (current & portsc::PRESERVE_MASK) | portsc::CHANGE_MASK;
            write_volatile(port_addr as *mut u32, new_val);
        }
    }

    /// Reset a port to enable a connected device.
    ///
    /// This performs a USB port reset which is required before a device can be
    /// addressed. After reset completes, the port will be enabled (PED=1).
    ///
    /// Returns the new port status, or an error if reset fails.
    pub fn reset_port(&self, port: u8) -> Result<PortStatus, &'static str> {
        if port >= self.max_ports {
            return Err("Invalid port number");
        }

        let port_addr = self.port_regs_addr(port);

        // SAFETY: Port address is within MMIO region
        unsafe {
            let current = read_volatile(port_addr as *const u32);

            // Log initial state
            self.log_portsc("reset: initial", port, current);

            // Check if port is connected
            if (current & portsc::CCS) == 0 {
                return Err("No device connected");
            }

            // For USB2 ports: initiate port reset
            // For USB3 ports: may need warm reset, but try normal reset first
            // Preserve PP (power), set PR (reset), clear change bits (RW1C)
            let reset_val = (current & portsc::PRESERVE_MASK) | portsc::PR | portsc::CHANGE_MASK;
            self.log_portsc("reset: writing", port, reset_val);
            write_volatile(port_addr as *mut u32, reset_val);

            // Memory barrier to ensure write is visible
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Verify the write took effect
            let after_write = read_volatile(port_addr as *const u32);
            self.log_portsc("reset: after write", port, after_write);

            // Check if PR bit was actually set
            if (after_write & portsc::PR) == 0 {
                // PR didn't stick - port may not support this or is in wrong state
                return Err("PR bit not set after write");
            }

            // Wait for reset to complete (PR clears when done, PRC sets)
            // USB spec allows up to 50ms for reset, use longer timeout
            for i in 0..500_000 {
                let status = read_volatile(port_addr as *const u32);
                if (status & portsc::PR) == 0 {
                    // Reset complete
                    self.log_portsc("reset: complete", port, status);

                    // Clear change bits
                    let clear_val = (status & portsc::PRESERVE_MASK) | portsc::CHANGE_MASK;
                    write_volatile(port_addr as *mut u32, clear_val);

                    return Ok(PortStatus::from_portsc(port + 1, status));
                }
                if i == 100_000 {
                    self.log_portsc("reset: still waiting", port, status);
                }
                core::hint::spin_loop();
            }

            // Timeout - log final state
            let final_status = read_volatile(port_addr as *const u32);
            self.log_portsc("reset: timeout", port, final_status);
        }

        Err("Port reset timeout")
    }

    /// Log PORTSC value for debugging
    fn log_portsc(&self, context: &str, port: u8, portsc: u32) {
        // Format: "[xhci] port N context: PORTSC=0xXXXX (CCS=X PED=X PR=X PP=X PLS=X SPD=X)"
        // We can't use io:: here directly, so this is a no-op in the shared module
        // The caller (dwc3/xhci driver) will need to provide logging
        let _ = (context, port, portsc);
    }

    /// Scan all ports and return their status
    pub fn scan_ports(&self) -> alloc::vec::Vec<PortStatus> {
        let mut ports = alloc::vec::Vec::with_capacity(self.max_ports as usize);
        for i in 0..self.max_ports {
            ports.push(self.read_port_status(i));
        }
        ports
    }

    /// Get maximum number of ports
    #[inline]
    pub fn max_ports(&self) -> u8 {
        self.max_ports
    }

    /// Get maximum number of device slots
    #[inline]
    pub fn max_slots(&self) -> u8 {
        self.max_slots
    }

    /// Get context size (32 or 64 bytes)
    #[inline]
    pub fn context_size(&self) -> usize {
        self.context_size
    }

    /// Check if controller is running
    pub fn is_running(&self) -> bool {
        let op_regs = self.read_op_regs();
        (op_regs.usbcmd & usbcmd::RUN_STOP) != 0 && (op_regs.usbsts & usbsts::HCH) == 0
    }

    /// Check if controller is halted
    pub fn is_halted(&self) -> bool {
        let op_regs = self.read_op_regs();
        (op_regs.usbsts & usbsts::HCH) != 0
    }

    /// Check if controller is ready (not in CNR state)
    pub fn is_ready(&self) -> bool {
        let op_regs = self.read_op_regs();
        (op_regs.usbsts & usbsts::CNR) == 0
    }

    /// Start the controller (set Run/Stop bit)
    pub fn start(&mut self) -> Result<(), &'static str> {
        if !self.is_ready() {
            return Err("Controller not ready");
        }

        let op_regs = self.read_op_regs();
        self.write_usbcmd(op_regs.usbcmd | usbcmd::RUN_STOP | usbcmd::INTE);
        self.running = true;
        Ok(())
    }

    /// Stop the controller (clear Run/Stop bit)
    pub fn stop(&mut self) {
        let op_regs = self.read_op_regs();
        self.write_usbcmd(op_regs.usbcmd & !usbcmd::RUN_STOP);
        self.running = false;
    }

    /// Perform a host controller reset (HCRST)
    ///
    /// This resets the controller to initial state, clearing any locks or
    /// stale state from firmware. The controller must be halted first.
    pub fn reset(&mut self) -> Result<(), &'static str> {
        // First stop the controller if running
        if self.is_running() {
            self.stop();
        }

        // Wait for controller to halt
        for _ in 0..100_000 {
            if self.is_halted() {
                break;
            }
            core::hint::spin_loop();
        }

        if !self.is_halted() {
            return Err("Controller failed to halt before reset");
        }

        // Set HCRST bit
        let op_regs = self.read_op_regs();
        self.write_usbcmd(op_regs.usbcmd | usbcmd::HCRST);

        // Wait for reset to complete (HCRST bit clears when done)
        // Also wait for CNR (Controller Not Ready) to clear
        for _ in 0..1_000_000 {
            let op = self.read_op_regs();
            if (op.usbcmd & usbcmd::HCRST) == 0 && (op.usbsts & usbsts::CNR) == 0 {
                // Reset complete
                self.running = false;
                self.command_ring = None;
                self.event_ring = None;
                self.dcbaa = None;
                for i in 0..MAX_DEVICE_SLOTS {
                    self.slot_enabled[i] = false;
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err("Controller reset timeout")
    }

    /// Clear error status bits in USBSTS (RW1C - write 1 to clear)
    ///
    /// This clears HCE (Host Controller Error) and HSE (Host System Error) bits.
    pub fn clear_error_status(&self) {
        // Write 1 to clear HCE and HSE bits
        const HCE: u32 = 1 << 12;
        const HSE: u32 = 1 << 2;
        self.write_usbsts(HCE | HSE);
    }

    /// Get xHCI version string
    pub fn version_string(&self) -> &'static str {
        let cap_regs = self.read_cap_regs();
        match cap_regs.hciversion {
            0x0095 => "0.95",
            0x0096 => "0.96",
            0x0100 => "1.0",
            0x0110 => "1.1",
            0x0120 => "1.2",
            _ => "unknown",
        }
    }

    /// Check for pending port changes
    pub fn has_port_changes(&self) -> bool {
        let op_regs = self.read_op_regs();
        (op_regs.usbsts & usbsts::PCD) != 0
    }

    /// Clear port change detect status
    pub fn clear_port_change_detect(&self) {
        self.write_usbsts(usbsts::PCD);
    }

    /// Clear event interrupt status (EINT bit in USBSTS)
    pub fn clear_event_interrupt(&self) {
        self.write_usbsts(usbsts::EINT);
    }

    /// Clear all pending status bits (EINT, PCD, etc.)
    pub fn clear_all_status(&self) {
        // Clear all RW1C status bits that might be pending
        self.write_usbsts(usbsts::EINT | usbsts::PCD);

        // Clear EHB (Event Handler Busy) in ERDP and IMAN.IP in interrupter 0.
        // DWC3 may inhibit event generation while EHB is set.
        if let Some(ref er) = self.event_ring {
            let intr0_base = self.runtime_base() + 0x20;
            let erdp = er.iova + (er.dequeue_idx * 16) as u64;
            // SAFETY: MMIO is mapped
            unsafe {
                // Write Hi first, then Lo with EHB=1 (RW1C) to clear
                write_volatile(
                    (intr0_base + 0x1C) as *mut u32,
                    (erdp >> 32) as u32,
                );
                write_volatile(
                    (intr0_base + 0x18) as *mut u32,
                    (erdp as u32 & !0xF) | 0x8,
                );
                // Clear IP, ensure IE stays set
                write_volatile(intr0_base as *mut u32, 0x3);
            }
        }
    }

    /// Get count of connected devices
    pub fn connected_device_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.max_ports {
            let status = self.read_port_status(i);
            if status.connected {
                count += 1;
            }
        }
        count
    }
}

// -- Helper functions for standalone use

/// Read port status directly from MMIO (without controller state)
///
/// # Safety
///
/// mmio_base must be a valid mapped xHCI MMIO address.
pub unsafe fn read_port_status_direct(mmio_base: u64, port: u8) -> PortStatus {
    // Read cap_length first
    let cap_length = unsafe { read_volatile(mmio_base as *const u8) };
    let hcsparams1 = unsafe { read_volatile((mmio_base + 4) as *const u32) };
    let max_ports = (hcsparams1 & 0xFF) as u8;

    if port >= max_ports {
        return PortStatus::invalid();
    }

    // Port registers at op_base + 0x400 + (port * 0x10)
    let op_base = mmio_base + cap_length as u64;
    let port_addr = op_base + 0x400 + (port as u64 * 0x10);

    // SAFETY: Caller guarantees mmio_base is valid
    let portsc = unsafe { read_volatile(port_addr as *const u32) };

    PortStatus::from_portsc(port + 1, portsc)
}

/// Get connected device count directly from MMIO
///
/// # Safety
///
/// mmio_base must be a valid mapped xHCI MMIO address.
pub unsafe fn get_connected_count_direct(mmio_base: u64) -> (u8, usize) {
    // Read cap_length and max_ports
    let cap_length = unsafe { read_volatile(mmio_base as *const u8) };
    let hcsparams1 = unsafe { read_volatile((mmio_base + 4) as *const u32) };
    let max_ports = (hcsparams1 & 0xFF) as u8;

    let op_base = mmio_base + cap_length as u64;
    let port_base = op_base + 0x400;

    let mut connected = 0usize;
    for i in 0..max_ports {
        let port_addr = port_base + (i as u64 * 0x10);
        // SAFETY: Caller guarantees mmio_base is valid
        let portsc = unsafe { read_volatile(port_addr as *const u32) };
        if (portsc & portsc::CCS) != 0 {
            connected += 1;
        }
    }

    (max_ports, connected)
}

// -- TRB (Transfer Request Block) Structures

/// Generic TRB structure (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    /// Create an empty TRB
    pub const fn new() -> Self {
        Self { param: 0, status: 0, control: 0 }
    }

    /// Get TRB type from control field
    #[inline]
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Get cycle bit
    #[inline]
    pub fn cycle(&self) -> bool {
        (self.control & 1) != 0
    }

    /// Set cycle bit
    #[inline]
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }
}

/// TRB types
pub mod trb_type {
    // Transfer TRB types
    pub const NORMAL: u8 = 1;
    pub const SETUP_STAGE: u8 = 2;
    pub const DATA_STAGE: u8 = 3;
    pub const STATUS_STAGE: u8 = 4;
    pub const ISOCH: u8 = 5;
    pub const LINK: u8 = 6;
    pub const EVENT_DATA: u8 = 7;
    pub const NO_OP: u8 = 8;

    // Command TRB types
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const EVALUATE_CONTEXT: u8 = 13;
    pub const RESET_ENDPOINT: u8 = 14;
    pub const STOP_ENDPOINT: u8 = 15;
    pub const SET_TR_DEQUEUE: u8 = 16;
    pub const RESET_DEVICE: u8 = 17;
    pub const NO_OP_COMMAND: u8 = 23;

    // Event TRB types
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const PORT_STATUS_CHANGE: u8 = 34;
    pub const BANDWIDTH_REQUEST: u8 = 35;
    pub const DOORBELL: u8 = 36;
    pub const HOST_CONTROLLER: u8 = 37;
    pub const DEVICE_NOTIFICATION: u8 = 38;
    pub const MFINDEX_WRAP: u8 = 39;
}

/// Completion codes for event TRBs
pub mod completion_code {
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER_ERROR: u8 = 2;
    pub const BABBLE_DETECTED: u8 = 3;
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    pub const TRB_ERROR: u8 = 5;
    pub const STALL_ERROR: u8 = 6;
    pub const SHORT_PACKET: u8 = 13;
    pub const SLOT_NOT_ENABLED: u8 = 11;
    pub const NO_SLOTS_AVAILABLE: u8 = 9;
}

/// Setup stage TRB for control transfers
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct SetupStageTrb {
    /// bmRequestType | bRequest | wValue
    pub request_type_and_request: u16,
    pub w_value: u16,
    /// wIndex | wLength
    pub w_index: u16,
    pub w_length: u16,
    /// TRB Transfer Length (always 8 for setup)
    pub trb_transfer_length: u32,
    /// Control: TRT | TRB Type | Cycle
    pub control: u32,
}

impl SetupStageTrb {
    /// Create a GET_DESCRIPTOR setup TRB
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self {
            request_type_and_request: 0x80 | (0x06 << 8), // GET_DESCRIPTOR, Device to Host
            w_value: (desc_type as u16) << 8 | desc_index as u16,
            w_index: 0,
            w_length: length,
            trb_transfer_length: 8,
            control: (trb_type::SETUP_STAGE as u32) << 10 | (3 << 16), // TRT=3 (IN data stage)
        }
    }

    /// Create a SET_ADDRESS setup TRB (used in Address Device)
    pub fn set_address(address: u8) -> Self {
        Self {
            request_type_and_request: 0x00 | (0x05 << 8), // SET_ADDRESS, Host to Device
            w_value: address as u16,
            w_index: 0,
            w_length: 0,
            trb_transfer_length: 8,
            control: (trb_type::SETUP_STAGE as u32) << 10, // No data stage
        }
    }
}

/// Data stage TRB for control transfers
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct DataStageTrb {
    /// Data buffer pointer (64-bit physical/IOVA address)
    pub data_buffer: u64,
    /// TRB Transfer Length | TD Size | Interrupter
    pub status: u32,
    /// Control: DIR | TRB Type | Cycle
    pub control: u32,
}

impl DataStageTrb {
    /// Create an IN data stage TRB
    pub fn data_in(buffer_addr: u64, length: u16) -> Self {
        Self {
            data_buffer: buffer_addr,
            status: length as u32,
            control: (trb_type::DATA_STAGE as u32) << 10 | (1 << 16), // DIR=1 (IN)
        }
    }

    /// Create an OUT data stage TRB
    pub fn data_out(buffer_addr: u64, length: u16) -> Self {
        Self {
            data_buffer: buffer_addr,
            status: length as u32,
            control: (trb_type::DATA_STAGE as u32) << 10, // DIR=0 (OUT)
        }
    }
}

/// Status stage TRB for control transfers
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct StatusStageTrb {
    pub _reserved: u64,
    pub status: u32,
    /// Control: DIR | IOC | TRB Type | Cycle
    pub control: u32,
}

impl StatusStageTrb {
    /// Create an IN status stage TRB (for OUT data transfers)
    pub fn status_in() -> Self {
        Self {
            _reserved: 0,
            status: 0,
            control: (trb_type::STATUS_STAGE as u32) << 10 | (1 << 16) | (1 << 5), // DIR=1, IOC=1
        }
    }

    /// Create an OUT status stage TRB (for IN data transfers)
    pub fn status_out() -> Self {
        Self {
            _reserved: 0,
            status: 0,
            control: (trb_type::STATUS_STAGE as u32) << 10 | (1 << 5), // DIR=0, IOC=1
        }
    }
}

/// Enable Slot Command TRB
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct EnableSlotTrb {
    pub _reserved: [u32; 3],
    pub control: u32,
}

impl EnableSlotTrb {
    pub fn new() -> Self {
        Self {
            _reserved: [0; 3],
            control: (trb_type::ENABLE_SLOT as u32) << 10,
        }
    }
}

impl Default for EnableSlotTrb {
    fn default() -> Self {
        Self::new()
    }
}

/// Address Device Command TRB
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct AddressDeviceTrb {
    /// Input Context pointer (64-bit)
    pub input_context: u64,
    pub _reserved: u32,
    /// Control: BSR | Slot ID | TRB Type | Cycle
    pub control: u32,
}

impl AddressDeviceTrb {
    pub fn new(input_context_addr: u64, slot_id: u8, block_set_address: bool) -> Self {
        let mut control = (trb_type::ADDRESS_DEVICE as u32) << 10 | ((slot_id as u32) << 24);
        if block_set_address {
            control |= 1 << 9; // BSR bit
        }
        Self {
            input_context: input_context_addr,
            _reserved: 0,
            control,
        }
    }
}

/// Command Completion Event TRB
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CommandCompletionTrb {
    /// Command TRB pointer (64-bit)
    pub command_trb_ptr: u64,
    /// Completion Code | Command Completion Parameter
    pub status: u32,
    /// Slot ID | VF ID | TRB Type | Cycle
    pub control: u32,
}

impl CommandCompletionTrb {
    /// Get completion code
    #[inline]
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Get slot ID
    #[inline]
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// Check if successful
    #[inline]
    pub fn is_success(&self) -> bool {
        self.completion_code() == completion_code::SUCCESS
    }
}

/// Transfer Event TRB
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct TransferEventTrb {
    /// TRB pointer (64-bit)
    pub trb_ptr: u64,
    /// Completion Code | Transfer Length
    pub status: u32,
    /// Slot ID | Endpoint ID | TRB Type | Cycle
    pub control: u32,
}

impl TransferEventTrb {
    /// Get completion code
    #[inline]
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Get transfer length (bytes not transferred)
    #[inline]
    pub fn residual_length(&self) -> u32 {
        self.status & 0xFFFFFF
    }

    /// Get slot ID
    #[inline]
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// Get endpoint ID
    #[inline]
    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
    }
}

// -- Device Context Structures

/// Slot Context (32 or 64 bytes depending on controller)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SlotContext {
    /// Route String | Speed | MTT | Hub | Context Entries
    pub info1: u32,
    /// Max Exit Latency | Root Hub Port Number | Number of Ports
    pub info2: u32,
    /// TT Hub Slot ID | TT Port Number | TTT | Interrupter Target
    pub info3: u32,
    /// USB Device Address | Slot State
    pub state: u32,
    pub _reserved: [u32; 4],
}

impl SlotContext {
    /// Get device address
    #[inline]
    pub fn device_address(&self) -> u8 {
        (self.state & 0xFF) as u8
    }

    /// Get slot state
    #[inline]
    pub fn slot_state(&self) -> u8 {
        ((self.state >> 27) & 0x1F) as u8
    }

    /// Get device speed
    #[inline]
    pub fn speed(&self) -> u8 {
        ((self.info1 >> 20) & 0xF) as u8
    }
}

/// Endpoint Context (32 or 64 bytes depending on controller)
///
/// Per xHCI spec Table 6-7:
/// - Dword 0 (info1): EP State[2:0], Mult[9:8], MaxPStreams[14:10], LSA[15], Interval[23:16]
/// - Dword 1 (info2): CErr[2:1], EP Type[5:3], HID[7], Max Burst Size[15:8], Max Packet Size[31:16]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EndpointContext {
    /// Dword 0: EP State | Mult | MaxPStreams | LSA | Interval
    pub info1: u32,
    /// Dword 1: CErr | EP Type | HID | Max Burst Size | Max Packet Size
    pub info2: u32,
    /// TR Dequeue Pointer (64-bit)
    pub tr_dequeue_lo: u32,
    pub tr_dequeue_hi: u32,
    /// Average TRB Length | Max ESIT Payload Lo
    pub info3: u32,
    pub _reserved: [u32; 3],
}

impl EndpointContext {
    /// Get endpoint type (from info2 bits 5:3)
    #[inline]
    pub fn ep_type(&self) -> u8 {
        ((self.info2 >> 3) & 0x7) as u8
    }

    /// Get max packet size (from info2 bits 31:16)
    #[inline]
    pub fn max_packet_size(&self) -> u16 {
        ((self.info2 >> 16) & 0xFFFF) as u16
    }

    /// Create for control endpoint 0
    ///
    /// Per xHCI spec:
    /// - CErr = 3 (retry up to 3 times)
    /// - EP Type = 4 (Control Bidirectional)
    pub fn for_control_ep0(max_packet_size: u16, tr_dequeue: u64) -> Self {
        Self {
            info1: 0, // EP State will be set by HC
            // info2: CErr[2:1]=3, EP Type[5:3]=4, Max Packet Size[31:16]
            info2: (3 << 1) | (4 << 3) | ((max_packet_size as u32) << 16),
            tr_dequeue_lo: (tr_dequeue | 1) as u32, // DCS=1
            tr_dequeue_hi: (tr_dequeue >> 32) as u32,
            info3: 8, // Average TRB length
            _reserved: [0; 3],
        }
    }

    /// Create for Interrupt IN endpoint
    ///
    /// Per xHCI spec:
    /// - CErr = 3 (retry up to 3 times)
    /// - EP Type = 7 (Interrupt IN)
    /// - Interval encoded for USB speed
    pub fn for_interrupt_in(
        max_packet_size: u16,
        tr_dequeue: u64,
        interval: u8,
        speed: PortSpeed,
    ) -> Self {
        // Encode interval per xHCI spec section 6.2.3.6
        // For HS/SS: Interval = bInterval-1 (already in 125us units)
        // For FS/LS: Need to convert ms to 125us units
        let encoded_interval = match speed {
            PortSpeed::High | PortSpeed::Super | PortSpeed::SuperPlus => {
                // interval is already encoded (power of 2 exponent)
                interval.saturating_sub(1).min(15)
            }
            _ => {
                // FS/LS: interval is in ms (frames), convert to 125us (microframe) units.
                // Use fls() (= 32 - leading_zeros) to match Linux xhci_parse_frame_interval().
                // For bInterval=1 on FS: 1*8=8, fls(8)=4, period = 2^(4-1)*125us = 1ms. Correct.
                let interval_125us = (interval as u32).saturating_mul(8);
                if interval_125us == 0 {
                    0
                } else {
                    (32 - interval_125us.leading_zeros()).min(15) as u8
                }
            }
        };

        // For periodic endpoints (interrupt/isochronous), Max ESIT Payload must be set
        // This tells the controller how much data can be transferred per service interval
        // For non-bursting interrupt endpoints: Max ESIT Payload = Max Packet Size
        let max_esit_payload = max_packet_size as u32;

        Self {
            // info1: Interval[23:16], Max ESIT Payload Hi[31:24] (0 for small payloads)
            info1: (encoded_interval as u32) << 16,
            // info2: CErr[2:1]=3, EP Type[5:3]=7 (Interrupt IN), Max Packet Size[31:16]
            info2: (3 << 1) | (7 << 3) | ((max_packet_size as u32) << 16),
            tr_dequeue_lo: (tr_dequeue | 1) as u32, // DCS=1
            tr_dequeue_hi: (tr_dequeue >> 32) as u32,
            // info3: Average TRB Length[15:0], Max ESIT Payload Lo[31:16]
            info3: (max_esit_payload << 16) | (max_packet_size as u32),
            _reserved: [0; 3],
        }
    }
}

/// Input Control Context for Address Device command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputControlContext {
    /// Drop Context Flags
    pub drop_flags: u32,
    /// Add Context Flags
    pub add_flags: u32,
    pub _reserved: [u32; 5],
    /// Configuration Value | Interface Number | Alternate Setting
    pub config: u32,
}

impl InputControlContext {
    /// Create for Address Device command (add slot context and EP0)
    pub fn for_address_device() -> Self {
        Self {
            drop_flags: 0,
            add_flags: 0b11, // Add Slot Context (A0) and EP0 Context (A1)
            _reserved: [0; 5],
            config: 0,
        }
    }
}

// -- USB Descriptor Structures

/// USB Device Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub bcd_usb: u16,
    pub b_device_class: u8,
    pub b_device_subclass: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

/// USB Configuration Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct ConfigurationDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub w_total_length: u16,
    pub b_num_interfaces: u8,
    pub b_configuration_value: u8,
    pub i_configuration: u8,
    pub bm_attributes: u8,
    pub b_max_power: u8,
}

/// USB Interface Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct InterfaceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_interface_number: u8,
    pub b_alternate_setting: u8,
    pub b_num_endpoints: u8,
    pub b_interface_class: u8,
    pub b_interface_subclass: u8,
    pub b_interface_protocol: u8,
    pub i_interface: u8,
}

/// USB Endpoint Descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct EndpointDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_endpoint_address: u8,
    pub bm_attributes: u8,
    pub w_max_packet_size: u16,
    pub b_interval: u8,
}

impl EndpointDescriptor {
    /// Check if IN endpoint
    #[inline]
    pub fn is_in(&self) -> bool {
        (self.b_endpoint_address & 0x80) != 0
    }

    /// Get endpoint number (0-15)
    #[inline]
    pub fn endpoint_number(&self) -> u8 {
        self.b_endpoint_address & 0x0F
    }

    /// Get transfer type (0=Control, 1=Isochronous, 2=Bulk, 3=Interrupt)
    #[inline]
    pub fn transfer_type(&self) -> u8 {
        self.bm_attributes & 0x03
    }
}

/// USB descriptor types
pub mod descriptor_type {
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
    pub const HID: u8 = 0x21;
    pub const HID_REPORT: u8 = 0x22;
}

/// USB class codes
pub mod usb_class {
    pub const HID: u8 = 0x03;
}

/// HID subclass codes
pub mod hid_subclass {
    pub const BOOT: u8 = 0x01;
}

/// HID protocol codes
pub mod hid_protocol {
    pub const KEYBOARD: u8 = 0x01;
    pub const MOUSE: u8 = 0x02;
}
