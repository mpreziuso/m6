//! Root task capability slot layout
//!
//! Defines well-known capability slot indices in the root task's CSpace.
//! This is the single source of truth for the boot-time capability layout.
//!
//! Both kernel bootstrap and userspace code must use these values to ensure
//! synchronisation when adding new control capabilities.

/// Well-known capability slot indices in root task's CSpace.
///
/// This is the single source of truth for root task capability slots.
/// Both kernel bootstrap and userspace code should use these values.
///
/// # Adding New Capabilities
///
/// Insert new capabilities BEFORE `FirstUntyped` and update all subsequent
/// values. See `docs/capability-slot-management.md` for details.
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Root CNode (self-reference).
    RootCNode = 0,
    /// Root TCB.
    RootTcb = 1,
    /// Root VSpace.
    RootVSpace = 2,
    /// IRQ control capability.
    IrqControl = 3,
    /// ASID control capability.
    AsidControl = 4,
    /// Scheduling control capability.
    SchedControl = 5,
    /// Timer control capability.
    TimerControl = 6,
    /// ASID pool for spawning child processes.
    AsidPool = 7,
    /// First SMMU control capability (optional, only if SMMU present).
    /// Additional SMMUs use consecutive slots (8, 9, 10, 11 for up to 4 SMMUs).
    SmmuControl = 8,
    /// First untyped memory slot (offset by number of SMMUs).
    FirstUntyped = 12,
}

impl Slot {
    /// Maximum number of SMMUs supported.
    pub const MAX_SMMUS: usize = 4;

    /// Get the slot index for a given SMMU control by index (0-3).
    #[inline]
    pub const fn smmu_control(idx: usize) -> usize {
        Self::SmmuControl as usize + idx
    }

    /// Get the slot index for a given untyped region index.
    #[inline]
    pub const fn untyped(idx: usize) -> usize {
        Self::FirstUntyped as usize + idx
    }
}
