// M6 Starnix-fork shim: `fuchsia_rcu_collections`.
//
// Minimal-core, single-CPU bring-up reimplementation of the upstream
// `fuchsia_rcu_collections` crate. Only the `rcu_array` module required by the
// Starnix fork is provided; it is built on top of the M6 `fuchsia_rcu` shim and
// inherits its simplifications (deferred reclamation leaks replaced values).

#![no_std]

extern crate alloc;

pub mod rcu_array;
