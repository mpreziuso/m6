//! Statistics collection for the allocator
//!
//! Feature-gated under the `stats` feature.

/// Allocator statistics
#[derive(Debug, Clone, Default)]
pub struct AllocatorStats {
    /// Total bytes currently allocated (live)
    pub live_bytes: usize,
    /// Total bytes committed (mapped pages)
    pub committed_bytes: usize,
    /// Peak live bytes
    pub peak_live_bytes: usize,
    /// Total allocations since start
    pub total_allocs: u64,
    /// Total frees since start
    pub total_frees: u64,
    /// Number of active spans
    pub active_spans: usize,
    /// Number of large allocations
    pub large_alloc_count: usize,
}

impl AllocatorStats {
    /// Create new empty statistics
    pub const fn new() -> Self {
        Self {
            live_bytes: 0,
            committed_bytes: 0,
            peak_live_bytes: 0,
            total_allocs: 0,
            total_frees: 0,
            active_spans: 0,
            large_alloc_count: 0,
        }
    }

    /// Update peak if current live bytes exceed it
    pub fn update_peak(&mut self) {
        if self.live_bytes > self.peak_live_bytes {
            self.peak_live_bytes = self.live_bytes;
        }
    }

    /// Get fragmentation ratio (1.0 = no fragmentation)
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.committed_bytes == 0 {
            1.0
        } else {
            self.live_bytes as f64 / self.committed_bytes as f64
        }
    }
}
