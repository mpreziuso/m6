//! ARM64 (AArch64) page table implementation
//!
//! Implements 4-level page tables with 4KB granule:
//! - L0: 512GB per entry (table only)
//! - L1: 1GB per entry (table or block)
//! - L2: 2MB per entry (table or block)
//! - L3: 4KB per entry (page only)

pub mod descriptors;
pub mod mapping;
pub mod tables;

pub use descriptors::*;
pub use mapping::*;
pub use tables::*;
