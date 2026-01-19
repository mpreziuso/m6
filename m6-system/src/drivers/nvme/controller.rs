//! NVMe Controller Abstraction
//!
//! Provides high-level access to an NVMe controller, handling initialisation,
//! register access, and doorbell operations.

#![allow(dead_code)]

use super::command::{DOORBELL_BASE, REG_ACQ, REG_AQA, REG_ASQ, REG_CAP, REG_CC, REG_CSTS, REG_VS};

/// Maximum timeout for controller ready (in milliseconds)
const TIMEOUT_MS: u32 = 5000;

/// Poll iterations per millisecond (approximate)
const POLL_ITERATIONS_PER_MS: usize = 1000;

/// NVMe Controller
pub struct NvmeController {
    /// Base address of MMIO region
    base: usize,
    /// Doorbell stride in bytes (4 << CAP.DSTRD)
    doorbell_stride: usize,
    /// Maximum queue entries supported (CAP.MQES + 1)
    max_queue_entries: u16,
    /// Memory page size shift (12 + CAP.MPSMIN)
    mps_shift: u8,
    /// Controller version
    version: u32,
}

impl NvmeController {
    /// Create a new NVMe controller instance.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` points to a valid, mapped NVMe BAR0 region.
    #[must_use]
    pub unsafe fn new(base: usize) -> Self {
        Self {
            base,
            doorbell_stride: 8, // Default, will be updated from CAP
            max_queue_entries: 0,
            mps_shift: 12,
            version: 0,
        }
    }

    /// Read a 32-bit register.
    #[inline]
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: Base is valid MMIO, caller ensures offset is valid
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a 32-bit register.
    #[inline]
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: Base is valid MMIO, caller ensures offset is valid
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Read a 64-bit register.
    #[inline]
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: Base is valid MMIO, caller ensures offset is valid
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) }
    }

    /// Write a 64-bit register.
    #[inline]
    fn write64(&self, offset: usize, value: u64) {
        // SAFETY: Base is valid MMIO, caller ensures offset is valid
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }

    /// Read Controller Capabilities (CAP).
    #[inline]
    #[must_use]
    pub fn capabilities(&self) -> u64 {
        self.read64(REG_CAP)
    }

    /// Read Controller Status (CSTS).
    #[inline]
    #[must_use]
    pub fn status(&self) -> u32 {
        self.read32(REG_CSTS)
    }

    /// Check if controller is ready (CSTS.RDY = 1).
    #[inline]
    #[must_use]
    pub fn is_ready(&self) -> bool {
        (self.status() & 0x1) != 0
    }

    /// Check if controller has fatal status (CSTS.CFS = 1).
    #[inline]
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        (self.status() & 0x2) != 0
    }

    /// Read Controller Version (VS).
    #[inline]
    #[must_use]
    pub fn read_version(&self) -> u32 {
        self.read32(REG_VS)
    }

    /// Get cached version.
    #[inline]
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Get maximum queue entries supported.
    #[inline]
    #[must_use]
    pub const fn max_queue_entries(&self) -> u16 {
        self.max_queue_entries
    }

    /// Get memory page size (in bytes).
    #[inline]
    #[must_use]
    pub const fn page_size(&self) -> usize {
        1 << self.mps_shift
    }

    /// Get doorbell stride (in bytes).
    #[inline]
    #[must_use]
    pub const fn doorbell_stride(&self) -> usize {
        self.doorbell_stride
    }

    /// Disable the controller.
    ///
    /// Clears CC.EN and waits for CSTS.RDY to become 0.
    pub fn disable(&self) -> Result<(), &'static str> {
        // Clear CC.EN
        let cc = self.read32(REG_CC);
        self.write32(REG_CC, cc & !0x1);

        // Wait for CSTS.RDY = 0
        self.wait_not_ready()?;

        Ok(())
    }

    /// Enable the controller.
    ///
    /// Sets CC.EN and waits for CSTS.RDY to become 1.
    pub fn enable(&self) -> Result<(), &'static str> {
        // Set CC.EN
        let cc = self.read32(REG_CC);
        self.write32(REG_CC, cc | 0x1);

        // Wait for CSTS.RDY = 1
        self.wait_ready()?;

        Ok(())
    }

    /// Wait for controller to become ready.
    fn wait_ready(&self) -> Result<(), &'static str> {
        for _ in 0..(TIMEOUT_MS as usize * POLL_ITERATIONS_PER_MS) {
            if self.is_ready() {
                return Ok(());
            }
            if self.is_fatal() {
                return Err("Controller fatal error");
            }
            core::hint::spin_loop();
        }
        Err("Timeout waiting for controller ready")
    }

    /// Wait for controller to become not ready.
    fn wait_not_ready(&self) -> Result<(), &'static str> {
        for _ in 0..(TIMEOUT_MS as usize * POLL_ITERATIONS_PER_MS) {
            if !self.is_ready() {
                return Ok(());
            }
            if self.is_fatal() {
                return Err("Controller fatal error during disable");
            }
            core::hint::spin_loop();
        }
        Err("Timeout waiting for controller disable")
    }

    /// Initialise the controller with admin queues.
    ///
    /// This performs the full NVMe initialisation sequence:
    /// 1. Disable controller (CC.EN = 0)
    /// 2. Wait for CSTS.RDY = 0
    /// 3. Configure admin queues (AQA, ASQ, ACQ)
    /// 4. Set CC (MPS, IOSQES, IOCQES, EN=1)
    /// 5. Wait for CSTS.RDY = 1
    ///
    /// # Arguments
    ///
    /// - `admin_sq_iova`: IOVA of admin submission queue
    /// - `admin_cq_iova`: IOVA of admin completion queue
    /// - `depth`: Number of entries in each admin queue
    pub fn init(
        &mut self,
        admin_sq_iova: u64,
        admin_cq_iova: u64,
        depth: u16,
    ) -> Result<(), &'static str> {
        // Read capabilities
        let cap = self.capabilities();

        // Extract doorbell stride: 4 << CAP.DSTRD
        let dstrd = ((cap >> 32) & 0xF) as usize;
        self.doorbell_stride = 4 << dstrd;

        // Extract max queue entries: CAP.MQES + 1
        self.max_queue_entries = ((cap & 0xFFFF) as u16) + 1;

        // Extract minimum memory page size: 12 + CAP.MPSMIN
        let mpsmin = ((cap >> 48) & 0xF) as u8;
        self.mps_shift = 12 + mpsmin;

        // Read version
        self.version = self.read_version();

        // Validate depth
        if depth > self.max_queue_entries {
            return Err("Queue depth exceeds controller maximum");
        }

        // Step 1: Disable controller
        self.disable()?;

        // Step 3: Set Admin Queue Attributes (AQA)
        // ASQS and ACQS are 0-based (actual size = value + 1)
        let aqa = (((depth - 1) as u32) << 16) | ((depth - 1) as u32);
        self.write32(REG_AQA, aqa);

        // Step 4: Set Admin Submission Queue Base Address (ASQ)
        self.write64(REG_ASQ, admin_sq_iova);

        // Step 5: Set Admin Completion Queue Base Address (ACQ)
        self.write64(REG_ACQ, admin_cq_iova);

        // Step 6: Set Controller Configuration (CC)
        // - EN = 1 (enable)
        // - CSS = 0 (NVM command set)
        // - MPS = 0 (4KB pages, matching CAP.MPSMIN typically)
        // - IOSQES = 6 (64 bytes, 2^6)
        // - IOCQES = 4 (16 bytes, 2^4)
        // CC: EN=1, CSS=0 (NVM), MPS=0 (4KB), IOSQES=6 (64B), IOCQES=4 (16B)
        let cc = 0x1 | (6 << 16) | (4 << 20);
        self.write32(REG_CC, cc);

        // Step 7: Wait for CSTS.RDY = 1
        self.wait_ready()?;

        Ok(())
    }

    /// Ring the submission queue doorbell.
    ///
    /// # Arguments
    ///
    /// - `qid`: Queue ID (0 for admin queue)
    /// - `tail`: New tail index
    #[inline]
    pub fn ring_sq_doorbell(&self, qid: u16, tail: u16) {
        let offset = DOORBELL_BASE + (qid as usize * 2) * self.doorbell_stride;
        self.write32(offset, tail as u32);
    }

    /// Ring the completion queue doorbell.
    ///
    /// # Arguments
    ///
    /// - `qid`: Queue ID (0 for admin queue)
    /// - `head`: New head index
    #[inline]
    pub fn ring_cq_doorbell(&self, qid: u16, head: u16) {
        let offset = DOORBELL_BASE + (qid as usize * 2 + 1) * self.doorbell_stride;
        self.write32(offset, head as u32);
    }

    /// Get the base address.
    #[inline]
    #[must_use]
    pub const fn base(&self) -> usize {
        self.base
    }
}

/// NVMe Identify Controller data structure (4096 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdentifyController {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// Serial Number (ASCII, 20 bytes)
    pub sn: [u8; 20],
    /// Model Number (ASCII, 40 bytes)
    pub mn: [u8; 40],
    /// Firmware Revision (ASCII, 8 bytes)
    pub fr: [u8; 8],
    /// Recommended Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier
    pub ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub cmic: u8,
    /// Maximum Data Transfer Size
    pub mdts: u8,
    /// Controller ID
    pub cntlid: u16,
    /// Version
    pub ver: u32,
    /// RTD3 Resume Latency
    pub rtd3r: u32,
    /// RTD3 Entry Latency
    pub rtd3e: u32,
    /// Optional Asynchronous Events Supported
    pub oaes: u32,
    /// Controller Attributes
    pub ctratt: u32,
    /// Read Recovery Levels Supported
    pub rrls: u16,
    /// Reserved
    pub reserved1: [u8; 9],
    /// Controller Type
    pub cntrltype: u8,
    /// FRU Globally Unique Identifier
    pub fguid: [u8; 16],
    /// Command Retry Delay Times
    pub crdt: [u16; 3],
    /// Reserved
    pub reserved2: [u8; 106],
    /// Reserved for NVMe Management Interface
    pub reserved3: [u8; 16],
    /// Optional Admin Command Support
    pub oacs: u16,
    /// Abort Command Limit
    pub acl: u8,
    /// Asynchronous Event Request Limit
    pub aerl: u8,
    /// Firmware Updates
    pub frmw: u8,
    /// Log Page Attributes
    pub lpa: u8,
    /// Error Log Page Entries
    pub elpe: u8,
    /// Number of Power States Support
    pub npss: u8,
    /// Admin Vendor Specific Command Configuration
    pub avscc: u8,
    /// Autonomous Power State Transition Attributes
    pub apsta: u8,
    /// Warning Composite Temperature Threshold
    pub wctemp: u16,
    /// Critical Composite Temperature Threshold
    pub cctemp: u16,
    /// Maximum Time for Firmware Activation
    pub mtfa: u16,
    /// Host Memory Buffer Preferred Size
    pub hmpre: u32,
    /// Host Memory Buffer Minimum Size
    pub hmmin: u32,
    /// Total NVM Capacity
    pub tnvmcap: [u8; 16],
    /// Unallocated NVM Capacity
    pub unvmcap: [u8; 16],
    /// Replay Protected Memory Block Support
    pub rpmbs: u32,
    /// Extended Device Self-test Time
    pub edstt: u16,
    /// Device Self-test Options
    pub dsto: u8,
    /// Firmware Update Granularity
    pub fwug: u8,
    /// Keep Alive Support
    pub kas: u16,
    /// Host Controlled Thermal Management Attributes
    pub hctma: u16,
    /// Minimum Thermal Management Temperature
    pub mntmt: u16,
    /// Maximum Thermal Management Temperature
    pub mxtmt: u16,
    /// Sanitize Capabilities
    pub sanicap: u32,
    /// Host Memory Buffer Minimum Descriptor Entry Size
    pub hmminds: u32,
    /// Host Memory Maximum Descriptors Entries
    pub hmmaxd: u16,
    /// NVM Set Identifier Maximum
    pub nsetidmax: u16,
    /// Endurance Group Identifier Maximum
    pub endgidmax: u16,
    /// ANA Transition Time
    pub anatt: u8,
    /// Asymmetric Namespace Access Capabilities
    pub anacap: u8,
    /// ANA Group Identifier Maximum
    pub anagrpmax: u32,
    /// Number of ANA Group Identifiers
    pub nanagrpid: u32,
    /// Persistent Event Log Size
    pub pels: u32,
    /// Reserved
    pub reserved4: [u8; 156],
    /// Submission Queue Entry Size
    pub sqes: u8,
    /// Completion Queue Entry Size
    pub cqes: u8,
    /// Maximum Outstanding Commands
    pub maxcmd: u16,
    /// Number of Namespaces
    pub nn: u32,
    /// Optional NVM Command Support
    pub oncs: u16,
    /// Fused Operation Support
    pub fuses: u16,
    /// Format NVM Attributes
    pub fna: u8,
    /// Volatile Write Cache
    pub vwc: u8,
    /// Atomic Write Unit Normal
    pub awun: u16,
    /// Atomic Write Unit Power Fail
    pub awupf: u16,
    /// NVM Vendor Specific Command Configuration
    pub nvscc: u8,
    /// Namespace Write Protection Capabilities
    pub nwpc: u8,
    /// Atomic Compare & Write Unit
    pub acwu: u16,
    /// Reserved
    pub reserved5: u16,
    /// SGL Support
    pub sgls: u32,
    /// Maximum Number of Allowed Namespaces
    pub mnan: u32,
    /// Reserved
    pub reserved6: [u8; 224],
    /// NVM Subsystem NVMe Qualified Name
    pub subnqn: [u8; 256],
    /// Reserved
    pub reserved7: [u8; 768],
    /// NVMe over Fabrics specific
    pub reserved8: [u8; 256],
    /// Power State Descriptors
    pub psd: [[u8; 32]; 32],
    /// Vendor Specific
    pub vs: [u8; 1024],
}

impl Default for IdentifyController {
    fn default() -> Self {
        // SAFETY: All zeros is valid for this structure
        unsafe { core::mem::zeroed() }
    }
}

impl IdentifyController {
    /// Get serial number as string.
    #[must_use]
    pub fn serial_number(&self) -> &str {
        core::str::from_utf8(&self.sn)
            .unwrap_or("")
            .trim_end_matches(|c: char| c.is_whitespace() || c == '\0')
    }

    /// Get model number as string.
    #[must_use]
    pub fn model_number(&self) -> &str {
        core::str::from_utf8(&self.mn)
            .unwrap_or("")
            .trim_end_matches(|c: char| c.is_whitespace() || c == '\0')
    }

    /// Get firmware revision as string.
    #[must_use]
    pub fn firmware_revision(&self) -> &str {
        core::str::from_utf8(&self.fr)
            .unwrap_or("")
            .trim_end_matches(|c: char| c.is_whitespace() || c == '\0')
    }

    /// Get maximum data transfer size in bytes.
    ///
    /// Returns `None` if MDTS is 0 (no limit).
    #[must_use]
    pub fn max_transfer_size(&self, page_size: usize) -> Option<usize> {
        if self.mdts == 0 {
            None
        } else {
            Some(page_size << self.mdts)
        }
    }
}

/// NVMe Identify Namespace data structure (4096 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdentifyNamespace {
    /// Namespace Size (in logical blocks)
    pub nsze: u64,
    /// Namespace Capacity (in logical blocks)
    pub ncap: u64,
    /// Namespace Utilisation (in logical blocks)
    pub nuse: u64,
    /// Namespace Features
    pub nsfeat: u8,
    /// Number of LBA Formats
    pub nlbaf: u8,
    /// Formatted LBA Size
    pub flbas: u8,
    /// Metadata Capabilities
    pub mc: u8,
    /// End-to-end Data Protection Capabilities
    pub dpc: u8,
    /// End-to-end Data Protection Type Settings
    pub dps: u8,
    /// Namespace Multi-path I/O and Namespace Sharing Capabilities
    pub nmic: u8,
    /// Reservation Capabilities
    pub rescap: u8,
    /// Format Progress Indicator
    pub fpi: u8,
    /// Deallocate Logical Block Features
    pub dlfeat: u8,
    /// Namespace Atomic Write Unit Normal
    pub nawun: u16,
    /// Namespace Atomic Write Unit Power Fail
    pub nawupf: u16,
    /// Namespace Atomic Compare & Write Unit
    pub nacwu: u16,
    /// Namespace Atomic Boundary Size Normal
    pub nabsn: u16,
    /// Namespace Atomic Boundary Offset
    pub nabo: u16,
    /// Namespace Atomic Boundary Size Power Fail
    pub nabspf: u16,
    /// Namespace Optimal I/O Boundary
    pub noiob: u16,
    /// NVM Capacity
    pub nvmcap: [u8; 16],
    /// Namespace Preferred Write Granularity
    pub npwg: u16,
    /// Namespace Preferred Write Alignment
    pub npwa: u16,
    /// Namespace Preferred Deallocate Granularity
    pub npdg: u16,
    /// Namespace Preferred Deallocate Alignment
    pub npda: u16,
    /// Namespace Optimal Write Size
    pub nows: u16,
    /// Reserved
    pub reserved1: [u8; 18],
    /// ANA Group Identifier
    pub anagrpid: u32,
    /// Reserved
    pub reserved2: [u8; 3],
    /// Namespace Attributes
    pub nsattr: u8,
    /// NVM Set Identifier
    pub nvmsetid: u16,
    /// Endurance Group Identifier
    pub endgid: u16,
    /// Namespace Globally Unique Identifier
    pub nguid: [u8; 16],
    /// IEEE Extended Unique Identifier
    pub eui64: [u8; 8],
    /// LBA Format Support
    pub lbaf: [LbaFormat; 16],
    /// Reserved
    pub reserved3: [u8; 192],
    /// Vendor Specific
    pub vs: [u8; 3712],
}

impl Default for IdentifyNamespace {
    fn default() -> Self {
        // SAFETY: All zeros is valid for this structure
        unsafe { core::mem::zeroed() }
    }
}

impl IdentifyNamespace {
    /// Get the size of the namespace in logical blocks.
    #[inline]
    #[must_use]
    pub const fn size_blocks(&self) -> u64 {
        self.nsze
    }

    /// Get the currently selected LBA format index.
    #[inline]
    #[must_use]
    pub const fn lba_format_index(&self) -> usize {
        (self.flbas & 0xF) as usize
    }

    /// Get the currently selected LBA format.
    #[inline]
    #[must_use]
    pub fn lba_format(&self) -> LbaFormat {
        self.lbaf[self.lba_format_index()]
    }

    /// Get the logical block size in bytes.
    #[inline]
    #[must_use]
    pub fn block_size(&self) -> usize {
        1 << self.lba_format().lba_data_size()
    }

    /// Get the namespace size in bytes.
    #[inline]
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.nsze * (self.block_size() as u64)
    }
}

/// LBA Format descriptor
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LbaFormat {
    /// Metadata Size (in bytes)
    pub ms: u16,
    /// LBA Data Size (as power of 2)
    pub lbads: u8,
    /// Relative Performance
    pub rp: u8,
}

impl LbaFormat {
    /// Get the LBA data size in bytes.
    #[inline]
    #[must_use]
    pub const fn lba_data_size(&self) -> u8 {
        self.lbads
    }

    /// Get the metadata size in bytes.
    #[inline]
    #[must_use]
    pub const fn metadata_size(&self) -> u16 {
        self.ms
    }
}

// Size assertions
const _: () = {
    assert!(core::mem::size_of::<IdentifyController>() == 4096);
    assert!(core::mem::size_of::<IdentifyNamespace>() == 4096);
};
