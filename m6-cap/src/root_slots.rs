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
    /// SMMU control capability (optional, only if SMMU present).
    SmmuControl = 8,
    /// First untyped memory slot.
    FirstUntyped = 9,
}

impl Slot {
    /// Get the slot index for a given untyped region index.
    #[inline]
    pub const fn untyped(idx: usize) -> usize {
        Self::FirstUntyped as usize + idx
    }
}
