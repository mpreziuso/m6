//! Synchronisation primitives for M6's Starnix compatibility layer.
//!
//! This is a `no_std` fork of Fuchsia's `starnix_sync` crate, replacing
//! Fuchsia-specific primitives with `spin`/`lock_api`-based equivalents. It
//! mirrors the upstream public surface: the lock-ordering graph (`FileOpsCore`,
//! `TaskRelease`, `ProcessGroupState`, etc.), the `Locked<L>` lock-sequence
//! machinery, the ordered lock wrappers, and `InterruptibleEvent`.
//!
//! M6 divergences from upstream:
//! - `Mutex`/`RwLock` are backed by `spin` via `lock_api` rather than
//!   `fuchsia_sync` (`MappedMutexGuard`/`MutexGuard::map` still available).
//! - `InterruptibleEvent` uses a self-contained atomic state machine rather
//!   than a `zx::Futex` (see that module).
//! - `atomic_time`, `port_event`, and the async `AsyncUnlockable` helpers are
//!   omitted as the M6 core does not import them.

#![no_std]

extern crate alloc;

mod interruptible_event;
mod lock_ordering;
mod port_event;
mod lock_relations;
mod lock_sequence;
mod lock_traits;
mod locks;

pub use interruptible_event::*;
pub use lock_ordering::*;
pub use port_event::*;
pub use lock_ordering_macro::*;
pub use lock_relations::*;
pub use lock_sequence::*;
pub use lock_traits::*;
pub use locks::*;

// Allow internal modules and the `lock_ordering!` proc-macro to refer to the
// crate by its external name.
extern crate self as starnix_sync;
