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
/// There is exactly one SchedControl capability in the system,
/// given to the root task at boot.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct SchedControlObject {
    /// Total CPU time allocated (sum of all context budgets).
    pub total_allocated: Microseconds,
    /// Number of scheduling contexts created.
    pub context_count: u32,
    /// Maximum allocatable time per period (platform-dependent).
    pub max_allocatable: Microseconds,
}

impl SchedControlObject {
    /// Create a new scheduling control object.
    ///
    /// # Parameters
    ///
    /// - `max_allocatable`: Maximum allocatable time per period
    #[inline]
    #[must_use]
    pub const fn new(max_allocatable: Microseconds) -> Self {
        Self {
            total_allocated: 0,
            context_count: 0,
            max_allocatable,
        }
    }

    /// Check if more time can be allocated.
    #[inline]
    #[must_use]
    pub const fn can_allocate(&self, budget: Microseconds) -> bool {
        self.total_allocated.saturating_add(budget) <= self.max_allocatable
    }

    /// Record allocation of a new scheduling context.
    #[inline]
    pub fn record_allocation(&mut self, budget: Microseconds) {
        self.total_allocated = self.total_allocated.saturating_add(budget);
        self.context_count = self.context_count.saturating_add(1);
    }

    /// Record deallocation of a scheduling context.
    #[inline]
    pub fn record_deallocation(&mut self, budget: Microseconds) {
        self.total_allocated = self.total_allocated.saturating_sub(budget);
        self.context_count = self.context_count.saturating_sub(1);
    }

    /// Remaining allocatable time.
    #[inline]
    #[must_use]
    pub const fn remaining_allocatable(&self) -> Microseconds {
        self.max_allocatable.saturating_sub(self.total_allocated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sched_context_creation() {
        let ctx = SchedContextObject::new(5000, 10000);
        assert!(ctx.is_valid());
        assert!(ctx.has_budget());
        assert_eq!(ctx.utilisation_percent(), 50);
    }

    #[test]
    fn test_sched_context_consume() {
        let mut ctx = SchedContextObject::new(1000, 10000);
        assert_eq!(ctx.consume(500), 500);
        assert_eq!(ctx.remaining, 500);
        assert_eq!(ctx.consume(600), 500); // Only 500 remaining
        assert!(!ctx.has_budget());
    }

    #[test]
    fn test_sched_context_replenish() {
        let mut ctx = SchedContextObject::new(1000, 10000);
        ctx.consume(1000);
        assert!(!ctx.has_budget());
        ctx.replenish(100);
        assert!(ctx.has_budget());
        assert_eq!(ctx.remaining, 1000);
    }

    #[test]
    fn test_sched_control() {
        let mut ctrl = SchedControlObject::new(100_000);
        assert!(ctrl.can_allocate(50_000));
        ctrl.record_allocation(50_000);
        assert!(ctrl.can_allocate(50_000));
        assert!(!ctrl.can_allocate(50_001));
    }
}
