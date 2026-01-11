//! M6 Capability-Based Security
//!
//! This crate provides capability-based security primitives for the M6
//! microkernel, following seL4's proven capability model.
//!
//! # Overview
//!
//! A **capability** is an unforgeable token that combines:
//! - An object reference (points to a kernel object)
//! - Access rights (defines permitted operations)
//!
//! Capabilities are the *only* way to access kernel resources. They cannot
//! be forged or guessed—they must be explicitly granted. This provides
//! a principled foundation for security.
//!
//! # Core Types
//!
//! - [`CapRights`]: Access permissions (read, write, grant, grant_reply)
//! - [`Badge`]: Immutable identifier for IPC sender identification
//! - [`CapSlot`]: Storage for a single capability (16 bytes)
//! - [`CPtr`]: Capability pointer for addressing slots in the CSpace
//! - [`Cap`]: Type-safe capability handle
//!
//! # Object Types
//!
//! The [`objects`] module defines all kernel object types:
//!
//! | Category | Types |
//! |----------|-------|
//! | Memory | [`Untyped`], [`Frame`], [`DeviceFrame`], `PageTableL0-L3`, [`VSpace`] |
//! | ASID | [`ASIDPool`], [`ASIDControl`] |
//! | IPC | [`Endpoint`], [`Notification`], [`Reply`] |
//! | Execution | [`CNodeObj`], [`TCB`] |
//! | System | [`IRQHandler`], [`IRQControl`], [`SchedContext`], [`SchedControl`] |
//!
//! [`Untyped`]: objects::Untyped
//! [`Frame`]: objects::Frame
//! [`DeviceFrame`]: objects::DeviceFrame
//! [`VSpace`]: objects::VSpace
//! [`ASIDPool`]: objects::ASIDPool
//! [`ASIDControl`]: objects::ASIDControl
//! [`Endpoint`]: objects::Endpoint
//! [`Notification`]: objects::Notification
//! [`Reply`]: objects::Reply
//! [`CNodeObj`]: objects::CNodeObj
//! [`TCB`]: objects::TCB
//! [`IRQHandler`]: objects::IRQHandler
//! [`IRQControl`]: objects::IRQControl
//! [`SchedContext`]: objects::SchedContext
//! [`SchedControl`]: objects::SchedControl
//!
//! # CSpace Structure
//!
//! Capabilities are stored in a hierarchical structure called the CSpace
//! (Capability Space):
//!
//! ```text
//! CSpace
//! └── CNode (root)
//!     ├── Slot 0: Capability to Object A
//!     ├── Slot 1: Capability to CNode B (enables hierarchy)
//!     │   └── CNode B
//!     │       ├── Slot 0: Capability to Object C
//!     │       └── ...
//!     ├── Slot 2: Empty
//!     └── ...
//! ```
//!
//! # Capability Operations
//!
//! The [`ops`] module provides operations for manipulating capabilities:
//!
//! - **Copy**: Duplicate a capability (creates CDT sibling)
//! - **Move**: Transfer a capability between slots
//! - **Mint**: Create a derived capability with reduced rights/badge
//! - **Delete**: Remove a single capability
//! - **Revoke**: Remove all derived capabilities
//!
//! # Derivation Tree (CDT)
//!
//! The [`cdt`] module implements the Capability Derivation Tree, which
//! tracks parent-child relationships for revocation. When a capability
//! is revoked, all its descendants are automatically revoked.
//!
//! # Kernel Integration
//!
//! This crate defines the capability logic; the kernel provides storage.
//! The [`CNodeOps`] and [`CdtOps`] traits define the interface between
//! `m6-cap` and `m6-kernel`.
//!
//! [`CNodeOps`]: cnode::CNodeOps
//! [`CdtOps`]: cdt::CdtOps

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// Module declarations
mod badge;
mod cap;
pub mod cdt;
pub mod cnode;
mod cptr;
mod error;
pub mod objects;
pub mod ops;
mod rights;
pub mod root_slots;
mod slot;

// Re-exports for convenient access
pub use badge::Badge;
pub use cap::{AnyCap, Cap};
pub use cdt::{CdtNode, CdtNodeId, CdtOps, RevocationCallback};
pub use cnode::{CNodeGuard, CNodeMeta, CNodeOps, CNodeRadix, MAX_CNODE_RADIX, MIN_CNODE_RADIX};
pub use cptr::{CPtr, CptrDepth, RawCPtr};
pub use error::{CapError, CapResult};
pub use objects::CapObjectType;
pub use rights::CapRights;
pub use slot::{CapSlot, ObjectRef, ObjectType, SlotFlags};
