// M6 Starnix-fork shim: `starnix_rcu`.
//
// Minimal-core, single-CPU bring-up reimplementation of the upstream
// `starnix_rcu` crate. It mirrors the upstream public API (`RcuHashMap`,
// `rcu_hash_map::{Entry, ...}`, `RcuReadScope`, `RcuString`) so the Starnix fork
// compiles unchanged.
//
// The concurrency model is simplified: `RcuHashMap` is backed by a
// `spin::RwLock` rather than a lock-free RCU hash map, and read references handed
// out for the lifetime of an `RcuReadScope` are backed by leaked heap
// allocations (values are never reclaimed). This inherits the same simplification
// documented in the `fuchsia_rcu` shim and is adequate for single-CPU bring-up
// only.

#![no_std]

extern crate alloc;

pub mod rcu_hash_map;
mod rcu_string;

pub use fuchsia_rcu::RcuReadScope;
pub use rcu_hash_map::RcuHashMap;
pub use rcu_string::RcuString;
