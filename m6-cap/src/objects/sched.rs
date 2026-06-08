//! Scheduling capabilities
//!
//! The scheduling system uses capability-based CPU time management:
//!
//! - **SchedControl**: Authority to create and configure scheduling contexts
//! - **SchedContext**: CPU time budget that threads consume to execute
//!
//! # MCS Scheduling
//!
//! M6 uses Mixed-Criticality Scheduling (MCS) concepts:
//!
//! - Each scheduling context has a budget and period
//! - Threads consume budget as they run
//! - Budget replenishes after the period elapses
//! - This enables temporal isolation between components

use crate::slot::ObjectRef;

/// Time in microseconds.
pub type Microseconds = u64;

/// CPU utilisation, in parts-per-million. One full CPU's worth of CPU time is
/// [`FULL_CPU_PPM`]; admission accounting in [`SchedControlObject`] is expressed
/// in these units so that budgets with *different periods* can be summed
/// meaningfully (a raw budget-microsecond sum is dimensionless across periods).
pub type UtilisationPpm = u64;

/// Parts-per-million representing one fully-utilised CPU (`budget == period`).
pub const FULL_CPU_PPM: UtilisationPpm = 1_000_000;

/// Scheduling context object metadata.
///
/// A scheduling context provides CPU time budget to threads.
/// Multiple threads can share a scheduling context.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SchedContextObject {
    /// Budget in microseconds per period.
    pub budget: Microseconds,
    /// Period in microseconds.
    pub period: Microseconds,
    /// Remaining budget in current period.
    pub remaining: Microseconds,
    /// Start of current period (in system ticks).
    pub period_start: u64,
    /// Extra budget for temporary boosts.
    pub extra_budget: Microseconds,
    /// TCB currently using this context.
    pub bound_tcb: ObjectRef,
    /// Core this context is bound to (-1 for any).
    pub core_affinity: i8,
    /// Whether the context is currently active.
    pub is_active: bool,
    /// Number of TCBs that can use this context.
    pub refcount: u16,
    /// Utilisation (parts-per-million) this context currently contributes to
    /// its admitting [`SchedControlObject`], or 0 if not yet admitted. Tracked
    /// so that reconfigure/destroy can adjust the control's running total by
    /// the right delta. See [`SchedContextObject::utilisation_ppm`].
    pub admitted_ppm: UtilisationPpm,
    /// The SchedControl this context's budget was admitted against (NULL until
    /// first configured). Lets destroy release the utilisation symmetrically.
    pub admitting_control: ObjectRef,
}

impl SchedContextObject {
    /// Minimum budget (10 microseconds).
    pub const MIN_BUDGET: Microseconds = 10;

    /// Minimum period (100 microseconds).
    pub const MIN_PERIOD: Microseconds = 100;

    /// Create a new scheduling context.
    ///
    /// # Parameters
    ///
    /// - `budget`: Budget in microseconds per period
    /// - `period`: Period in microseconds
    #[inline]
    #[must_use]
    pub const fn new(budget: Microseconds, period: Microseconds) -> Self {
        Self {
            budget,
            period,
            remaining: budget,
            period_start: 0,
            extra_budget: 0,
            bound_tcb: ObjectRef::NULL,
            core_affinity: -1,
            is_active: false,
            refcount: 0,
            admitted_ppm: 0,
            admitting_control: ObjectRef::NULL,
        }
    }

    /// Create a default scheduling context (10ms budget, 10ms period = 100%).
    #[inline]
    #[must_use]
    pub const fn default_context() -> Self {
        Self::new(10_000, 10_000) // 10ms budget, 10ms period
    }

    /// Check if budget is available.
    #[inline]
    #[must_use]
    pub const fn has_budget(&self) -> bool {
        self.remaining > 0 || self.extra_budget > 0
    }

    /// Consume budget.
    ///
    /// # Parameters
    ///
    /// - `amount`: Microseconds to consume
    ///
    /// # Returns
    ///
    /// Actual amount consumed (may be less if insufficient budget).
    pub fn consume(&mut self, amount: Microseconds) -> Microseconds {
        // First consume from extra budget
        if self.extra_budget > 0 {
            if self.extra_budget >= amount {
                self.extra_budget -= amount;
                return amount;
            }
            let from_extra = self.extra_budget;
            self.extra_budget = 0;
            let remaining_to_consume = amount - from_extra;
            return from_extra + self.consume_regular(remaining_to_consume);
        }
        self.consume_regular(amount)
    }

    fn consume_regular(&mut self, amount: Microseconds) -> Microseconds {
        if self.remaining >= amount {
            self.remaining -= amount;
            amount
        } else {
            let consumed = self.remaining;
            self.remaining = 0;
            consumed
        }
    }

    /// Replenish budget at the start of a new period.
    pub fn replenish(&mut self, current_ticks: u64) {
        self.remaining = self.budget;
        self.period_start = current_ticks;
    }

    /// Add extra budget (for priority inheritance, etc.).
    #[inline]
    pub fn add_extra_budget(&mut self, amount: Microseconds) {
        self.extra_budget = self.extra_budget.saturating_add(amount);
    }

    /// Utilisation as a percentage (0-100).
    #[inline]
    #[must_use]
    pub const fn utilisation_percent(&self) -> u8 {
        if self.period == 0 {
            return 0;
        }
        ((self.budget * 100) / self.period) as u8
    }

    /// Utilisation in parts-per-million (`budget / period`, [`FULL_CPU_PPM`] ==
    /// one full CPU). This is the unit used for SchedControl admission so that
    /// budgets with different periods compose correctly. Returns 0 for an
    /// unconfigured context (`period == 0`). Computed in `u128` to avoid
    /// overflow on large budgets.
    #[inline]
    #[must_use]
    pub const fn utilisation_ppm(&self) -> UtilisationPpm {
        if self.period == 0 {
            return 0;
        }
        ((self.budget as u128 * FULL_CPU_PPM as u128) / self.period as u128) as UtilisationPpm
    }

    /// Check if the scheduling parameters are valid.
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.budget >= Self::MIN_BUDGET
            && self.period >= Self::MIN_PERIOD
            && self.budget <= self.period
    }
}

impl Default for SchedContextObject {
    fn default() -> Self {
        Self::default_context()
    }
}

/// Scheduling control object metadata.
///
/// There is exactly one SchedControl capability in the system, given to the
/// root task at boot. It is the admission authority for CPU-time budgets: the
/// sum of the utilisations ([`SchedContextObject::utilisation_ppm`]) of all
/// contexts configured through it may not exceed [`Self::capacity_ppm`]. This
/// is what bounds aggregate CPU demand and prevents over-subscription — the
/// "time partitioning for security domains" guarantee.
///
/// Accounting is in utilisation (parts-per-million), not raw budget
/// microseconds, so contexts with different periods compose correctly.
///
/// Limitation: there is a single global SchedControl, so admission bounds the
/// *aggregate* utilisation across all CPUs. Contexts pinned to one core via
/// `core_affinity` are not separately bounded per-core (that would need
/// per-CPU SchedControl caps, as in seL4 MCS). The default `core_affinity`
/// (-1, any core) is the case this protects.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct SchedControlObject {
    /// Sum of the utilisations of all admitted contexts, in parts-per-million.
    pub allocated_ppm: UtilisationPpm,
    /// Number of scheduling contexts currently admitted.
    pub context_count: u32,
    /// Maximum admissible aggregate utilisation, in parts-per-million
    /// (typically `cpu_count * FULL_CPU_PPM`).
    pub capacity_ppm: UtilisationPpm,
}

impl SchedControlObject {
    /// Create a new scheduling control object.
    ///
    /// # Parameters
    ///
    /// - `capacity_ppm`: maximum admissible aggregate utilisation (ppm)
    #[inline]
    #[must_use]
    pub const fn new(capacity_ppm: UtilisationPpm) -> Self {
        Self {
            allocated_ppm: 0,
            context_count: 0,
            capacity_ppm,
        }
    }

    /// Check whether `util_ppm` more utilisation can be admitted without
    /// exceeding the capacity ceiling.
    #[inline]
    #[must_use]
    pub const fn can_admit(&self, util_ppm: UtilisationPpm) -> bool {
        self.allocated_ppm.saturating_add(util_ppm) <= self.capacity_ppm
    }

    /// Admit a newly-configured context contributing `util_ppm` utilisation.
    /// Callers must have checked [`Self::can_admit`] first when growing.
    #[inline]
    pub fn admit(&mut self, util_ppm: UtilisationPpm) {
        self.allocated_ppm = self.allocated_ppm.saturating_add(util_ppm);
        self.context_count = self.context_count.saturating_add(1);
    }

    /// Adjust an already-admitted context's contribution from `old_ppm` to
    /// `new_ppm` without changing the admitted-context count (reconfigure).
    /// Callers must have checked [`Self::can_admit`] for any positive delta.
    #[inline]
    pub fn reconfigure(&mut self, old_ppm: UtilisationPpm, new_ppm: UtilisationPpm) {
        self.allocated_ppm = self.allocated_ppm.saturating_sub(old_ppm).saturating_add(new_ppm);
    }

    /// Release an admitted context's `util_ppm` contribution (on destroy),
    /// decrementing the admitted-context count.
    #[inline]
    pub fn release(&mut self, util_ppm: UtilisationPpm) {
        self.allocated_ppm = self.allocated_ppm.saturating_sub(util_ppm);
        self.context_count = self.context_count.saturating_sub(1);
    }

    /// Remaining admissible utilisation (ppm).
    #[inline]
    #[must_use]
    pub const fn remaining_ppm(&self) -> UtilisationPpm {
        self.capacity_ppm.saturating_sub(self.allocated_ppm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_sched_context_creation() {
        let ctx = SchedContextObject::new(5000, 10000);
        assert!(ctx.is_valid());
        assert!(ctx.has_budget());
        assert_eq!(ctx.utilisation_percent(), 50);
    }

    #[test_case]
    fn test_sched_context_consume() {
        let mut ctx = SchedContextObject::new(1000, 10000);
        assert_eq!(ctx.consume(500), 500);
        assert_eq!(ctx.remaining, 500);
        assert_eq!(ctx.consume(600), 500); // Only 500 remaining
        assert!(!ctx.has_budget());
    }

    #[test_case]
    fn test_sched_context_replenish() {
        let mut ctx = SchedContextObject::new(1000, 10000);
        ctx.consume(1000);
        assert!(!ctx.has_budget());
        ctx.replenish(100);
        assert!(ctx.has_budget());
        assert_eq!(ctx.remaining, 1000);
    }

    #[test_case]
    fn test_sched_context_utilisation_ppm() {
        // 50% of one CPU.
        assert_eq!(SchedContextObject::new(5_000, 10_000).utilisation_ppm(), 500_000);
        // 100%.
        assert_eq!(SchedContextObject::new(10_000, 10_000).utilisation_ppm(), FULL_CPU_PPM);
        // Same utilisation, different period: still 50%.
        assert_eq!(SchedContextObject::new(500, 1_000).utilisation_ppm(), 500_000);
        // Unconfigured context contributes nothing.
        assert_eq!(SchedContextObject::new(0, 0).utilisation_ppm(), 0);
    }

    #[test_case]
    fn test_sched_control_admission() {
        // Capacity = one full CPU.
        let mut ctrl = SchedControlObject::new(FULL_CPU_PPM);
        assert!(ctrl.can_admit(500_000));
        ctrl.admit(500_000);
        assert_eq!(ctrl.context_count, 1);
        assert_eq!(ctrl.remaining_ppm(), 500_000);
        // The other half still fits, but one ppm more does not.
        assert!(ctrl.can_admit(500_000));
        assert!(!ctrl.can_admit(500_001));

        // Reconfigure the admitted context up to 80% — count unchanged.
        ctrl.reconfigure(500_000, 800_000);
        assert_eq!(ctrl.context_count, 1);
        assert_eq!(ctrl.allocated_ppm, 800_000);
        assert!(!ctrl.can_admit(200_001));

        // Release frees the capacity and decrements the count.
        ctrl.release(800_000);
        assert_eq!(ctrl.context_count, 0);
        assert_eq!(ctrl.allocated_ppm, 0);
        assert!(ctrl.can_admit(FULL_CPU_PPM));
    }
}
