//! Device Manager Module
//!
//! This module provides the device manager service implementation.
//! It can be used both by the device-mgr binary and potentially
//! by other components that need to interact with device management.

pub mod dtb;
pub mod ipc;
pub mod manifest;
pub mod pcie;
pub mod registry;
pub mod slots;
pub mod spawn;
