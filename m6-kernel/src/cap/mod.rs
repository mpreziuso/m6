//! Capability system kernel integration
//!
//! This module integrates the `m6-cap` capability library into the kernel,
//! providing storage and management for kernel objects.
//!
//! # Components
//!
//! - [`object_table`]: Kernel object storage with IrqSpinMutex protection
//! - [`cnode_storage`]: CNode heap allocation implementing [`CNodeOps`]
//! - [`cdt_storage`]: CDT node pool implementing [`CdtOps`]
//! - [`tcb_storage`]: Full TCB with register context
//! - [`bootstrap`]: Root task bootstrap
//!
//! [`CNodeOps`]: m6_cap::CNodeOps
//! [`CdtOps`]: m6_cap::CdtOps

extern crate alloc;

pub mod bootstrap;
pub mod cdt_storage;
pub mod cnode_storage;
pub mod cspace;
pub mod object_table;
pub mod tcb_storage;

// Re-export commonly used types
pub use bootstrap::{RootTask, bootstrap_root_task};
pub use cdt_storage::CdtPool;
pub use cnode_storage::CNodeStorage;
pub use cspace::{SlotLocation, resolve_cnode_slot, resolve_cptr};
pub use object_table::{KernelObject, KernelObjectType, MAX_OBJECTS, ObjectTable};
pub use tcb_storage::TcbFull;

/// Initialise the capability subsystem.
///
/// This must be called during kernel initialisation after the heap is
/// available but before any capability operations are performed.
pub fn init() {
    object_table::init();
    cdt_storage::init();
    log::info!("Capability subsystem initialised");
}
