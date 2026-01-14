//! Synchronisation primitives
//!
//! Provides thread synchronisation mechanisms using M6's notification-based
//! IPC for blocking operations.

mod condvar;
mod mutex;
mod once;
mod rwlock;

pub use condvar::Condvar;
pub use mutex::{Mutex, MutexGuard};
pub use once::{Once, OnceLock};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};

// Re-export atomic types from core
pub use core::sync::atomic;
