//! ASID (Address Space Identifier) allocation
//!
//! ARM64 supports 8 or 16-bit ASIDs depending on implementation.
//! M6 uses 16-bit ASIDs where available, falling back to 8-bit.
//!
//! ASID 0 is reserved for kernel/global mappings. User processes
//! get ASIDs 1-65535 (16-bit) or 1-255 (8-bit).
//!
//! When ASIDs are exhausted, we increment a generation counter and
//! reuse ASIDs. Processes must refresh their ASID when the generation
//! changes, triggering a TLB flush.
//!
//! # Integration with Capabilities
//!
//! The capability system (`m6-cap`) defines `AsidPoolObject` and
//! `AsidControlObject` for fine-grained ASID authority delegation.
//! This module provides the underlying allocator that backs those
//! capabilities.

use m6_arch::sync::IrqSpinMutex;

/// Minimum ASID value (0 is reserved for kernel).
const MIN_ASID: u16 = 1;

/// Maximum ASID value for 8-bit ASID support (conservative default).
const MAX_ASID_8BIT: u16 = 255;

/// Maximum ASID value for 16-bit ASID support.
const MAX_ASID_16BIT: u16 = 0xFFFF;

/// Allocated ASID with generation tracking.
///
/// The generation allows detecting when an ASID has been recycled.
/// When switching to a VSpace, if its generation doesn't match the
/// current global generation, a TLB invalidation is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocatedAsid {
    /// The ASID value.
    pub asid: u16,
    /// Generation when this ASID was allocated.
    pub generation: u64,
}

impl AllocatedAsid {
    /// Create a new allocated ASID.
    #[inline]
    #[must_use]
    pub const fn new(asid: u16, generation: u64) -> Self {
        Self { asid, generation }
    }

    /// Check if this ASID is still valid (generation matches current).
    #[inline]
    #[must_use]
    pub fn is_valid(&self, current_gen: u64) -> bool {
        self.generation == current_gen
    }
}

/// ASID allocator with generation tracking.
///
/// This allocator hands out ASIDs sequentially. When ASIDs are
/// exhausted, it wraps around and increments the generation counter.
/// VSpaces with stale generations must invalidate their TLB entries
/// before the ASID can be safely reused.
pub struct AsidAllocator {
    /// Next ASID to allocate.
    next_asid: u16,
    /// Generation counter - incremented on ASID rollover.
    generation: u64,
    /// Maximum ASID value (depends on CPU support).
    max_asid: u16,
}

impl AsidAllocator {
    /// Create a new ASID allocator.
    ///
    /// # Parameters
    ///
    /// * `asid_bits` - Number of ASID bits supported (8 or 16).
    #[must_use]
    pub const fn new(asid_bits: u8) -> Self {
        let max_asid = if asid_bits >= 16 {
            MAX_ASID_16BIT
        } else {
            MAX_ASID_8BIT
        };

        Self {
            next_asid: MIN_ASID,
            generation: 0,
            max_asid,
        }
    }

    /// Create a new ASID allocator with default 8-bit support.
    ///
    /// This is conservative and works on all ARMv8 implementations.
    #[must_use]
    pub const fn new_default() -> Self {
        Self::new(8)
    }

    /// Allocate a new ASID.
    ///
    /// Returns an `AllocatedAsid` containing both the ASID value and
    /// the generation it was allocated in. When the generation changes
    /// from a previously allocated ASID, the process must invalidate
    /// its TLB entries before using the new ASID.
    pub fn allocate(&mut self) -> AllocatedAsid {
        let asid = self.next_asid;
        self.next_asid += 1;

        if self.next_asid > self.max_asid {
            // ASID rollover - wrap around and increment generation
            self.next_asid = MIN_ASID;
            self.generation += 1;
            log::debug!("ASID rollover, new generation: {}", self.generation);
        }

        AllocatedAsid::new(asid, self.generation)
    }

    /// Get the current generation.
    #[inline]
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Get the maximum ASID value.
    #[inline]
    #[must_use]
    pub const fn max_asid(&self) -> u16 {
        self.max_asid
    }

    /// Get the number of available ASIDs.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> u16 {
        self.max_asid
    }
}

impl Default for AsidAllocator {
    fn default() -> Self {
        Self::new_default()
    }
}

/// Global ASID allocator.
///
/// Protected by an interrupt-safe spinlock to allow allocation from
/// any context (though allocation from interrupt handlers should be
/// avoided where possible).
static ASID_ALLOCATOR: IrqSpinMutex<AsidAllocator> =
    IrqSpinMutex::new(AsidAllocator::new_default());

/// Initialise the ASID allocator with the correct ASID width.
///
/// This should be called early during kernel initialisation after
/// determining the CPU's ASID support. If not called, the allocator
/// defaults to 8-bit ASIDs for maximum compatibility.
///
/// # Parameters
///
/// * `asid_bits` - Number of ASID bits supported by the CPU (8 or 16).
pub fn init_asid_allocator(asid_bits: u8) {
    let mut allocator = ASID_ALLOCATOR.lock();
    let max_asid = if asid_bits >= 16 {
        MAX_ASID_16BIT
    } else {
        MAX_ASID_8BIT
    };
    allocator.max_asid = max_asid;
    log::info!(
        "ASID allocator initialised: {}-bit ASIDs (max={})",
        asid_bits,
        max_asid
    );
}

/// Allocate a new ASID.
///
/// Returns an `AllocatedAsid` with the ASID value and generation.
/// The caller should store the generation to detect when the ASID
/// becomes stale due to rollover.
#[must_use]
pub fn allocate_asid() -> AllocatedAsid {
    ASID_ALLOCATOR.lock().allocate()
}

/// Get the current ASID generation.
///
/// Used to check if a stored ASID is still valid. If the stored
/// generation doesn't match the current generation, the ASID has
/// been recycled and TLB entries must be invalidated.
#[inline]
#[must_use]
pub fn current_generation() -> u64 {
    ASID_ALLOCATOR.lock().generation()
}

/// Check if an ASID allocation is still valid.
///
/// Returns `true` if the ASID's generation matches the current
/// global generation.
#[inline]
#[must_use]
pub fn is_asid_valid(alloc: &AllocatedAsid) -> bool {
    alloc.generation == current_generation()
}

/// Refresh an ASID allocation if it's stale.
///
/// If the generation has changed, allocates a new ASID and returns
/// `Some(new_allocation)`. If the ASID is still valid, returns `None`.
///
/// The caller is responsible for TLB invalidation when `Some` is returned.
pub fn refresh_asid_if_needed(alloc: &AllocatedAsid) -> Option<AllocatedAsid> {
    let mut allocator = ASID_ALLOCATOR.lock();
    if alloc.generation != allocator.generation() {
        Some(allocator.allocate())
    } else {
        None
    }
}
