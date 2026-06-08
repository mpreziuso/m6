//! Zircon object-info structures
//!
//! `VmoInfo`, `VmarInfo`, `MapInfo` (with its details), and clock detail
//! structures. These are plain data types; the fork reads their fields and, for
//! `MapInfo`, calls `details()`.

use crate::flags::VmoInfoFlags;
use crate::identity::{Koid, Name};
use crate::sys::zx_clock_rate_t;
use crate::time::{Instant, Timeline};
use crate::Rights;

/// Information about a VMO.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct VmoInfo {
    pub koid: Koid,
    pub name: Name,
    pub size_bytes: u64,
    pub committed_bytes: u64,
    pub flags: VmoInfoFlags,
    pub rights: Rights,
    /// Number of mappings to this VMO across all address spaces.
    pub share_count: usize,
}

/// Information about a VMAR.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct VmarInfo {
    pub base: usize,
    pub len: usize,
}

/// Per-mapping details inside a `MapInfo`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct MappingDetails {
    pub mmu_flags: u32,
    pub vmo_koid: Koid,
    pub vmo_offset: u64,
    pub committed_bytes: usize,
    pub populated_bytes: usize,
}

/// The kind of a `MapInfo` entry.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum MapDetails<'a> {
    /// An unspecified entry.
    #[default]
    None,
    /// The root address space.
    AddressSpace,
    /// A VMAR.
    Vmar,
    /// A mapping, with its details.
    Mapping(&'a MappingDetails),
}

impl MapDetails<'_> {
    /// Returns the mapping details if this entry is a mapping.
    pub fn as_mapping(&self) -> Option<&MappingDetails> {
        match self {
            MapDetails::Mapping(d) => Some(d),
            _ => None,
        }
    }
}

/// Information about a single entry in a process's address-space map.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct MapInfo {
    pub name: Name,
    pub base: usize,
    pub size: usize,
    pub depth: usize,
    details: MappingDetails,
    is_mapping: bool,
}

impl MapInfo {
    /// Returns the details for this entry.
    pub fn details(&self) -> MapDetails<'_> {
        if self.is_mapping {
            MapDetails::Mapping(&self.details)
        } else {
            MapDetails::None
        }
    }
}

/// A linear transformation between two timelines.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ClockTransformation<Reference: Timeline, Output: Timeline> {
    pub reference_offset: Instant<Reference>,
    pub synthetic_offset: Instant<Output>,
    pub rate: zx_clock_rate_t,
}

impl<Reference: Timeline, Output: Timeline> ClockTransformation<Reference, Output> {
    /// Applies the inverse transformation, mapping an output instant back to the
    /// reference timeline.
    ///
    /// Stub: applies the offset difference with a unit rate.
    pub fn apply_inverse(&self, output: Instant<Output>) -> Instant<Reference> {
        let delta = output.into_nanos().saturating_sub(self.synthetic_offset.into_nanos());
        Instant::from_nanos(self.reference_offset.into_nanos().saturating_add(delta))
    }
}

/// Details about a clock object.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ClockDetails<Reference: Timeline, Output: Timeline> {
    pub backstop: Instant<Output>,
    pub reference_to_synthetic: ClockTransformation<Reference, Output>,
    pub generation_counter: u32,
}
