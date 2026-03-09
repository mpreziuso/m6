//! ARM SMMUv3 register definitions
//!
//! Based on ARM System Memory Management Unit Architecture Specification
//! SMMU v3.0 to v3.3 (ARM IHI 0070).
//!
//! Note: Event queue structures are re-exported from m6-arch for sharing
//! with the userspace SMMU monitoring driver.

// -- Register Offsets

/// Identification Register 0
pub const SMMU_IDR0: usize = 0x000;
/// Identification Register 1
pub const SMMU_IDR1: usize = 0x004;
/// Identification Register 5 (contains OAS - Output Address Size)
pub const SMMU_IDR5: usize = 0x014;
/// Control Register 0
pub const SMMU_CR0: usize = 0x020;
/// Control Register 0 Acknowledgement
pub const SMMU_CR0ACK: usize = 0x024;
/// IRQ Control Register
pub const SMMU_IRQ_CTRL: usize = 0x050;
/// IRQ Control Acknowledgement
pub const SMMU_IRQ_CTRLACK: usize = 0x054;
/// Global Error Register
pub const SMMU_GERROR: usize = 0x060;
/// Global Error Acknowledge Register
pub const SMMU_GERRORN: usize = 0x064;
/// Global Bypass Attribute
pub const SMMU_GBPA: usize = 0x044;
/// Stream Table Base
pub const SMMU_STRTAB_BASE: usize = 0x080;
/// Stream Table Base Configuration
pub const SMMU_STRTAB_BASE_CFG: usize = 0x088;
/// Command Queue Base
pub const SMMU_CMDQ_BASE: usize = 0x090;
/// Command Queue Producer Index
pub const SMMU_CMDQ_PROD: usize = 0x098;
/// Command Queue Consumer Index
pub const SMMU_CMDQ_CONS: usize = 0x09C;
// Re-export event queue register offsets from m6-arch (shared with userspace)
pub use m6_arch::smmu::{SMMU_EVENTQ_BASE, SMMU_EVENTQ_CONS, SMMU_EVENTQ_PROD};

// -- IRQ_CTRL Register Bits

/// Global error interrupt enable
pub const IRQ_CTRL_GERROR_IRQEN: u32 = 1 << 0;
/// Event queue interrupt enable
pub const IRQ_CTRL_EVENTQ_IRQEN: u32 = 1 << 2;

// -- GERROR Register Bits

/// Command queue error
pub const GERROR_CMDQ_ERR: u32 = 1 << 0;
/// Event queue overflow
pub const GERROR_EVENTQ_ABT: u32 = 1 << 2;
/// MSI write abort
pub const GERROR_MSI_CMDQ_ABT: u32 = 1 << 4;
/// MSI write abort (event)
pub const GERROR_MSI_EVENTQ_ABT: u32 = 1 << 5;
/// MSI write abort (gerror)
pub const GERROR_MSI_GERROR_ABT: u32 = 1 << 8;
/// SFM (Stall Force Model) event
pub const GERROR_SFM_ERR: u32 = 1 << 9;

// -- CR0 Register Bits

/// SMMU Enable
pub const CR0_SMMUEN: u32 = 1 << 0;
/// Event Queue Enable
pub const CR0_EVENTQEN: u32 = 1 << 2;
/// Command Queue Enable
pub const CR0_CMDQEN: u32 = 1 << 3;

// -- GBPA Register Bits

/// Abort all incoming transactions
pub const GBPA_ABORT: u32 = 1 << 20;
/// Update flag
pub const GBPA_UPDATE: u32 = 1 << 31;

// -- Stream Table Entry (STE)

/// Stream Table Entry - 64 bytes
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamTableEntry {
    pub dwords: [u64; 8],
}

impl StreamTableEntry {
    /// Size of an STE in bytes.
    pub const SIZE: usize = 64;

    /// Create a bypass STE (invalid, transactions pass through).
    #[inline]
    pub const fn bypass() -> Self {
        Self { dwords: [0; 8] }
    }

    /// Create a valid STE with Stage 1 translation only.
    ///
    /// # Arguments
    /// - `cd_table_addr`: Physical address of the Context Descriptor table
    /// - `s1cdmax`: Log2(number of context descriptors) - supports 2^s1cdmax CDs
    pub fn new_s1_only(cd_table_addr: u64, s1cdmax: u8) -> Self {
        let mut ste = Self::bypass();

        // DWORD 0: V, Config, S1Fmt, S1ContextPtr, S1CDMax
        // ARM IHI 0070 Table 5.2; Linux STRTAB_STE_0_* definitions.
        // Config: 0=Abort, 4=Bypass, 5=S1 translate + S2 bypass, 6=S2 only
        // S1ContextPtr [51:6] — address goes directly, mask low 6 bits
        // S1CDMax [63:59] — log2(max CDs)
        ste.dwords[0] = 1 // V (Valid) [0]
            | (0b101 << 1) // Config = S1 translate + S2 bypass [3:1]
            | (cd_table_addr & !0x3F) // S1ContextPtr [51:6]
            | ((s1cdmax as u64 & 0x1F) << 59); // S1CDMax [63:59]

        // DWORD 1: S1DSS, S1STALLD, S1CIR, S1COR, S1CSH, STRW, SHCFG
        // S1DSS = SSID0 (0b01): non-SSID transactions (PCIe without PASID) use CD[0]
        // S1STALLD = 1 [27]: disable stall on translation fault (terminate instead).
        //   Without this, faults stall DMA and software must RESUME/TERMINATE —
        //   M6 doesn't implement stall recovery, so DMA hangs forever.
        // S1CIR/S1COR = non-cacheable (0b00): SMMU is non-coherent (COHACC=0),
        //   we do explicit cache maintenance for CD table and page tables
        // SHCFG = Inner Shareable (0b01) [45:44]
        ste.dwords[1] = 0b01 // S1DSS = SSID0 [1:0]
            | (1u64 << 27)    // S1STALLD = disable stall [27]
            | (0b01u64 << 44); // SHCFG = Inner Shareable [45:44]

        ste
    }
}

// -- Context Descriptor (CD)

/// Context Descriptor - 64 bytes
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextDescriptor {
    pub dwords: [u64; 8],
}

impl ContextDescriptor {
    /// Size of a CD in bytes.
    pub const SIZE: usize = 64;

    /// Create an invalid CD.
    #[inline]
    pub const fn invalid() -> Self {
        Self { dwords: [0; 8] }
    }

    /// Create a valid CD with Stage 1 translation.
    ///
    /// # Arguments
    /// - `ttb0`: Physical address of the page table root
    /// - `asid`: Address Space ID for IOTLB tagging
    /// - `t0sz`: Translation table size (upper bits to ignore, typically 16 for 48-bit)
    /// - `ips`: Intermediate Physical Size (raw 3-bit value from IDR5.OAS)
    pub fn new_stage1(ttb0: u64, asid: u16, t0sz: u8, ips: u8) -> Self {
        let mut cd = Self::invalid();

        // DWORD 0: control, TCR-like fields, and ASID
        // Bit layout verified against Linux CTXDESC_CD_0_* and ARM IHI 0070.
        cd.dwords[0] = (t0sz as u64)              // T0SZ [5:0]
            // TG0 = 4KB granule (0b00) [7:6] — no-op
            // IRGN0/ORGN0 = Non-cacheable (0b00) [9:8] / [11:10]
            // SMMU is non-coherent (COHACC=0) — page table walks must bypass
            // caches, going directly to DRAM. We do explicit cache maintenance.
            | (0b11 << 12)                         // SH0 = Inner shareable [13:12]
            // EPD0 = 0 (TTBR0 walks enabled) [14] — no-op
            | (1u64 << 30)                         // EPD1 = 1 (disable TTBR1 walks) [30]
            | (1u64 << 31)                         // V (Valid) [31]
            | ((ips as u64 & 0x7) << 32)           // IPS [34:32]
            | (1u64 << 41)                         // AA64 (AArch64 page tables) [41]
            | ((asid as u64) << 48);               // ASID [63:48]

        // DWORD 1: TTB0 [51:4]
        cd.dwords[1] = ttb0 & 0x000F_FFFF_FFFF_FFF0;

        // DWORD 3: MAIR
        // Entry 0 = 0x44 (Normal Non-cacheable, Inner+Outer) — used by IO PTEs
        // with AttrIndx=0. Non-cacheable is correct for non-coherent SMMU DMA.
        cd.dwords[3] = 0x44;

        cd
    }
}

// -- Command Queue Entry

/// Command Queue Entry - 16 bytes
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct CommandEntry {
    pub dwords: [u64; 2],
}

impl CommandEntry {
    /// Size of a command entry in bytes.
    pub const SIZE: usize = 16;

    /// Create a CFGI_STE command (invalidate STE cache).
    ///
    /// SMMUv3 format: DW0[7:0]=0x03, DW0[63:32]=StreamID, DW1[4:0]=Span.
    /// Span=0 invalidates a single STE.
    pub fn cfgi_ste(stream_id: u32) -> Self {
        Self {
            dwords: [
                0x03 | ((stream_id as u64) << 32),
                0, // Span=0 (single STE)
            ],
        }
    }

    /// Create a CFGI_CD command (invalidate context descriptor cache).
    ///
    /// SMMUv3 format: DW0[7:0]=0x05, DW0[31:12]=SSID, DW0[63:32]=StreamID,
    /// DW1[0]=Leaf.
    #[allow(dead_code)]
    pub fn cfgi_cd(stream_id: u32, ssid: u32, leaf: bool) -> Self {
        Self {
            dwords: [
                0x05
                    | (((ssid & 0xF_FFFF) as u64) << 12)
                    | ((stream_id as u64) << 32),
                leaf as u64, // Leaf at DW1[0]
            ],
        }
    }

    /// Create a TLBI_NH_VA command (invalidate TLB by VA, non-hypervisor).
    ///
    /// SMMUv3 format: DW0[7:0]=0x11, DW0[63:48]=ASID,
    /// DW1[0]=Leaf, DW1[63:12]=Address[63:12].
    #[allow(dead_code)]
    pub fn tlbi_nh_va(asid: u16, va: u64, leaf: bool) -> Self {
        Self {
            dwords: [
                0x11 | ((asid as u64) << 48),
                (va & !0xFFF) | (leaf as u64), // Address at [63:12], Leaf at [0]
            ],
        }
    }

    /// Create a TLBI_NH_ASID command (invalidate all TLB entries for an ASID).
    pub fn tlbi_nh_asid(asid: u16) -> Self {
        Self {
            dwords: [
                0x12 // Opcode = TLBI_NH_ASID
                    | ((asid as u64) << 48),
                0,
            ],
        }
    }

    /// Create a CMD_PREFETCH_ADDR command (test page table walk).
    ///
    /// Asks the SMMU to walk the page tables for the given stream and IOVA.
    /// If the walk fails, an event is generated in the event queue.
    /// If it succeeds, the translation is silently cached in the IOTLB.
    ///
    /// SMMUv3 format: DW0[7:0]=0x01, DW0[63:32]=StreamID,
    /// DW1[63:12]=Address[63:12].
    pub fn prefetch_addr(stream_id: u32, iova: u64) -> Self {
        Self {
            dwords: [
                0x01 | ((stream_id as u64) << 32),
                iova & !0xFFF, // Address [63:12]
            ],
        }
    }

    /// Create a CMD_SYNC command (wait for completion).
    pub fn cmd_sync() -> Self {
        Self {
            dwords: [
                0x46, // Opcode = CMD_SYNC
                0,
            ],
        }
    }
}

// -- Event Queue Entry (re-exported from m6-arch for sharing with userspace)

pub use m6_arch::smmu::EventEntry;
