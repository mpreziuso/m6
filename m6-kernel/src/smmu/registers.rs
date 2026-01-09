//! ARM SMMUv3 register definitions
//!
//! Based on ARM System Memory Management Unit Architecture Specification
//! SMMU v3.0 to v3.3 (ARM IHI 0070).

// -- Register Offsets

/// Identification Register 0
pub const SMMU_IDR0: usize = 0x000;
/// Identification Register 1
pub const SMMU_IDR1: usize = 0x004;
/// Control Register 0
pub const SMMU_CR0: usize = 0x020;
/// Control Register 0 Acknowledgement
pub const SMMU_CR0ACK: usize = 0x024;
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
/// Event Queue Base
pub const SMMU_EVENTQ_BASE: usize = 0x0A0;
/// Event Queue Producer Index
pub const SMMU_EVENTQ_PROD: usize = 0x100A8;
/// Event Queue Consumer Index
pub const SMMU_EVENTQ_CONS: usize = 0x100AC;

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

        // DWORD 0: V=1, Config=S1 translation, S1ContextPtr
        // Config = 0b100 = S1 translation only
        ste.dwords[0] = 1 // V (Valid)
            | (0b100 << 1) // Config = S1 translation
            | ((cd_table_addr & !0x3F) << 6); // S1ContextPtr (aligned to 64 bytes)

        // DWORD 1: S1CDMax, S1Fmt
        // S1Fmt = 0b00 = Linear CD table
        ste.dwords[1] = ((s1cdmax as u64) << 59) // S1CDMax
            | (0b00 << 4); // S1Fmt = Linear

        // DWORD 2: S2VMID, SHCFG, etc.
        // SHCFG = 0b01 = Inner shareable
        ste.dwords[2] = 0b01 << 12; // SHCFG = Inner shareable

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
    /// - `t0sz`: Translation table size (number of upper bits to ignore, typically 16 for 48-bit)
    pub fn new_stage1(ttb0: u64, asid: u16, t0sz: u8) -> Self {
        let mut cd = Self::invalid();

        // DWORD 0: T0SZ, TG0, IR0, OR0, SH0, EPD0, V
        cd.dwords[0] = (1u64 << 31) // V (Valid)
            | (t0sz as u64) // T0SZ
            | (0b00 << 6)  // TG0 = 4KB granule
            | (0b01 << 8)  // IR0 = Write-back cacheable
            | (0b01 << 10) // OR0 = Write-back cacheable
            | (0b11 << 12) // SH0 = Inner shareable
            | (0 << 14);   // EPD0 = 0 (translation enabled)

        // DWORD 1: TTB0
        cd.dwords[1] = ttb0 & !0xFFF; // 4KB aligned

        // DWORD 2: ASID, etc.
        cd.dwords[2] = (asid as u64) << 48; // ASID in bits [63:48]

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
    pub fn cfgi_ste(stream_id: u32, leaf: bool) -> Self {
        Self {
            dwords: [
                0x03 // Opcode = CFGI_STE
                    | ((stream_id as u64) << 32)
                    | ((leaf as u64) << 4),
                0,
            ],
        }
    }

    /// Create a CFGI_CD command (invalidate context descriptor cache).
    #[allow(dead_code)]
    pub fn cfgi_cd(stream_id: u32, ssid: u32, leaf: bool) -> Self {
        Self {
            dwords: [
                0x05 // Opcode = CFGI_CD
                    | ((stream_id as u64) << 32),
                (ssid as u64) | ((leaf as u64) << 32),
            ],
        }
    }

    /// Create a TLBI_NH_VA command (invalidate TLB by VA, non-hypervisor).
    #[allow(dead_code)]
    pub fn tlbi_nh_va(asid: u16, va: u64, leaf: bool) -> Self {
        Self {
            dwords: [
                0x11 // Opcode = TLBI_NH_VA
                    | ((asid as u64) << 48)
                    | ((leaf as u64) << 4),
                va >> 12, // VA[51:12]
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

// -- Event Queue Entry

/// Event Queue Entry - 32 bytes
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventEntry {
    pub dwords: [u64; 4],
}

impl EventEntry {
    /// Size of an event entry in bytes.
    pub const SIZE: usize = 32;

    /// Get the event type/fault code.
    #[inline]
    pub fn event_type(&self) -> u8 {
        (self.dwords[0] & 0xFF) as u8
    }

    /// Get the stream ID that caused the event.
    #[inline]
    pub fn stream_id(&self) -> u32 {
        ((self.dwords[0] >> 32) & 0xFFFF_FFFF) as u32
    }

    /// Get the faulting address (if applicable).
    #[inline]
    pub fn address(&self) -> u64 {
        self.dwords[2]
    }

    /// Check if this is a translation fault (page not present).
    #[inline]
    pub fn is_translation_fault(&self) -> bool {
        matches!(self.event_type(), 0x10..=0x1F)
    }

    /// Check if this is a permission fault (access denied).
    #[inline]
    pub fn is_permission_fault(&self) -> bool {
        matches!(self.event_type(), 0x08..=0x0F)
    }
}
