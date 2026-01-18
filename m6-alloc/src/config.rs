//! Allocator configuration and size class definitions

/// Page size constant (4KB for ARM64)
pub const PAGE_SIZE: usize = 4096;

/// Minimum allocation size (pointer-sized for freelist storage)
pub const MIN_ALLOC_SIZE: usize = 8;

/// Maximum small allocation size (use size classes up to this)
pub const MAX_SMALL_SIZE: usize = 2048;

/// Large allocation threshold (above this, use direct mapping)
pub const LARGE_THRESHOLD: usize = MAX_SMALL_SIZE;

/// Maximum number of spans the allocator can manage
pub const MAX_SPANS: usize = 1024;

/// Maximum number of large allocations tracked in side table
pub const MAX_LARGE_ENTRIES: usize = 256;

/// Size of quarantine queue (when feature enabled)
#[cfg(feature = "quarantine")]
pub const QUARANTINE_SIZE: usize = 128;

/// Maximum bytes in quarantine before forced flush
#[cfg(feature = "quarantine")]
pub const MAX_QUARANTINE_BYTES: usize = 64 * 1024;

/// A size class definition
#[derive(Debug, Clone, Copy)]
pub struct SizeClass {
    /// Slot size in bytes
    pub size: usize,
    /// Number of pages per span for this class
    pub span_pages: usize,
}

impl SizeClass {
    /// Create a new size class
    pub const fn new(size: usize, span_pages: usize) -> Self {
        Self { size, span_pages }
    }

    /// Number of slots per span
    pub const fn slots_per_span(&self) -> usize {
        (self.span_pages * PAGE_SIZE) / self.size
    }

    /// Total bytes per span
    pub const fn span_bytes(&self) -> usize {
        self.span_pages * PAGE_SIZE
    }
}

/// Size classes using powers of 2 with intermediate sizes
/// Following jemalloc-style spacing for good coverage
pub const SIZE_CLASSES: &[SizeClass] = &[
    // Tiny sizes (8-byte aligned)
    SizeClass::new(8, 1),  // 0: 512 slots/span
    SizeClass::new(16, 1), // 1: 256 slots/span
    SizeClass::new(32, 1), // 2: 128 slots/span
    SizeClass::new(48, 1), // 3: 85 slots/span
    SizeClass::new(64, 1), // 4: 64 slots/span
    // Small sizes (16-byte aligned)
    SizeClass::new(80, 1),  // 5: 51 slots/span
    SizeClass::new(96, 1),  // 6: 42 slots/span
    SizeClass::new(112, 1), // 7: 36 slots/span
    SizeClass::new(128, 1), // 8: 32 slots/span
    // Medium sizes
    SizeClass::new(192, 1),  // 9: 21 slots/span
    SizeClass::new(256, 1),  // 10: 16 slots/span
    SizeClass::new(384, 2),  // 11: 21 slots/span
    SizeClass::new(512, 2),  // 12: 16 slots/span
    SizeClass::new(768, 2),  // 13: 10 slots/span
    SizeClass::new(1024, 2), // 14: 8 slots/span
    SizeClass::new(1536, 3), // 15: 8 slots/span
    SizeClass::new(2048, 4), // 16: 8 slots/span
];

/// Number of size classes
pub const NUM_SIZE_CLASSES: usize = SIZE_CLASSES.len();
