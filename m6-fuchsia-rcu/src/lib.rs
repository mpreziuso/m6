// M6 Starnix-fork shim: `fuchsia_rcu`.
//
// This is a minimal-core, single-CPU bring-up reimplementation of the upstream
// Fuchsia `fuchsia_rcu` crate. It mirrors the upstream public API exactly so the
// Starnix fork compiles unchanged, but the underlying RCU machinery is greatly
// simplified: read-side critical sections are no-ops and deferred reclamation
// leaks replaced values rather than reclaiming them after a grace period. See
// `state_machine.rs` for the full description of the simplification.
//
// This is adequate for single-CPU bring-up only; it must be replaced with a real
// RCU implementation before relying on it under concurrency.

#![no_std]

extern crate alloc;

mod rcu_arc;
mod rcu_cell;
mod rcu_option_arc;
mod rcu_option_cell;
mod rcu_ptr;
mod rcu_read_scope;
mod state_machine;

pub use rcu_arc::RcuArc;
pub use rcu_cell::RcuCell;
pub use rcu_option_arc::RcuOptionArc;
pub use rcu_option_cell::RcuOptionCell;
pub use rcu_ptr::RcuReadGuard;
pub use rcu_read_scope::RcuReadScope;
pub use state_machine::{rcu_drop, rcu_run_callbacks, rcu_synchronize};

/// Lower-level building blocks, matching the upstream `subtle` module.
pub mod subtle {
    pub use super::rcu_ptr::{RcuPtr, RcuPtrRef};
}
