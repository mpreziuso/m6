//! Assorted Zircon option/flag types
//!
//! Bitflag and enum option types referenced by the fork. Values mirror the
//! upstream `zx` encodings where they matter; otherwise they are plain
//! sequential discriminants sufficient for the type checker.

use bitflags::bitflags;

bitflags! {
    /// Flags describing a VMO, as returned in `VmoInfo`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct VmoInfoFlags: u32 {
        const PAGED = 1 << 0;
        const RESIZABLE = 1 << 1;
        const IS_COW_CLONE = 1 << 2;
        const PAGER_BACKED = 1 << 5;
        const CONTIGUOUS = 1 << 6;
        const DISCARDABLE = 1 << 7;
        const IMMUTABLE = 1 << 8;
    }
}

bitflags! {
    /// Extended VMAR allocation flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct VmarFlagsExtended: u32 {
        const SPECIFIC_OVERWRITE = 1 << 5;
        const SPECIFIC = 1 << 4;
    }
}

bitflags! {
    /// Options for `wait_async`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct WaitAsyncOpts: u32 {
        const EDGE_TRIGGERED = 1 << 0;
        const TIMESTAMP = 1 << 1;
    }
}

bitflags! {
    /// Options for socket data transfer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TransferDataOptions: u32 {
        const _NONE = 0;
    }
}

bitflags! {
    /// Options for raising a user exception.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RaiseExceptionOptions: u32 {
        const TARGET_JOB_DEBUGGER = 1 << 0;
    }
}

bitflags! {
    /// Options for process creation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ProcessOptions: u32 {
        const SHARED = 1 << 0;
    }
}

bitflags! {
    /// Options for marking a process critical to a job.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct JobCriticalOptions: u32 {
        const RETCODE_NONZERO = 1 << 0;
    }
}

bitflags! {
    /// Reported CPU feature flags (aarch64 ISA features). Bit positions are
    /// shim-local (distinct per feature); the kernel maps each set flag to the
    /// corresponding Linux HWCAP bit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CpuFeatureFlags: u32 {
        const ARM64_FEATURE_ISA_FP = 1 << 0;
        const ARM64_FEATURE_ISA_ASIMD = 1 << 1;
        const ARM64_FEATURE_ISA_AES = 1 << 2;
        const ARM64_FEATURE_ISA_PMULL = 1 << 3;
        const ARM64_FEATURE_ISA_SHA1 = 1 << 4;
        const ARM64_FEATURE_ISA_SHA256 = 1 << 5;
        const ARM64_FEATURE_ISA_CRC32 = 1 << 6;
        const ARM64_FEATURE_ISA_ATOMICS = 1 << 7;
        const ARM64_FEATURE_ISA_RDM = 1 << 8;
        const ARM64_FEATURE_ISA_SHA3 = 1 << 9;
        const ARM64_FEATURE_ISA_SM3 = 1 << 10;
        const ARM64_FEATURE_ISA_SM4 = 1 << 11;
        const ARM64_FEATURE_ISA_DP = 1 << 12;
        const ARM64_FEATURE_ISA_SHA512 = 1 << 13;
        const ARM64_FEATURE_ISA_FHM = 1 << 14;
        const ARM64_FEATURE_ISA_TS = 1 << 15;
        const ARM64_FEATURE_ISA_DPB = 1 << 16;
        const ARM64_FEATURE_ISA_I8MM = 1 << 17;
        const ARM64_FEATURE_ISA_RNDR = 1 << 18;
    }
}

bitflags! {
    /// Options for clock creation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct ClockOpts: u32 {
        const MONOTONIC = 1 << 0;
        const CONTINUOUS = 1 << 1;
        const AUTO_START = 1 << 2;
        const BOOT = 1 << 3;
    }
}

bitflags! {
    /// Options for pager creation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct PagerOptions: u32 {
        const _NONE = 0;
    }
}

/// VMO range operations (for `op_range`).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VmoOp {
    Commit,
    Decommit,
    Zero,
    Prefetch,
    DontNeed,
    AlwaysNeed,
}

#[allow(non_upper_case_globals)]
impl VmoOp {
    pub const COMMIT: Self = Self::Commit;
    pub const DECOMMIT: Self = Self::Decommit;
    pub const ZERO: Self = Self::Zero;
    pub const PREFETCH: Self = Self::Prefetch;
    pub const DONT_NEED: Self = Self::DontNeed;
    pub const ALWAYS_NEED: Self = Self::AlwaysNeed;
}

/// VMAR range operations (for `op_range`).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VmarOp {
    Commit,
    Decommit,
    Prefetch,
    AlwaysNeed,
}

#[allow(non_upper_case_globals)]
impl VmarOp {
    pub const COMMIT: Self = Self::Commit;
    pub const DECOMMIT: Self = Self::Decommit;
    pub const PREFETCH: Self = Self::Prefetch;
    pub const ALWAYS_NEED: Self = Self::AlwaysNeed;
}
