//! SMMU management capabilities
//!
//! The SMMU system has two capability types:
//!
//! - **SmmuControl**: Singleton capability to manage the SMMU
//! - **IOSpace**: Managed via SmmuControl, provides DMA isolation
//!
//! # Stream IDs
//!
//! PCIe devices are identified by Stream IDs (derived from the Requester ID).
//! Each stream ID must be bound to exactly one IOSpace for DMA to function.

use crate::slot::ObjectRef;

/// Stream ID type (PCIe Requester ID).
pub type StreamId = u32;

/// Maximum stream ID (practical limit, hardware may support more).
pub const MAX_STREAM_ID: StreamId = 0xFFFF;

/// Number of inline bitmap words for stream tracking.
const STREAM_BITMAP_WORDS: usize = 16;

/// Maximum streams tracked inline (16 * 64 = 1024).
pub const MAX_INLINE_STREAMS: usize = STREAM_BITMAP_WORDS * 64;

/// SMMU control object metadata.
///
/// There is one SmmuControl capability per SMMU in the system,
/// given to the root task at boot.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SmmuControlObject {
    /// Physical base address of the SMMU registers.
    pub base_addr: u64,
    /// Virtual base address of the SMMU registers (kernel mapping).
    pub virt_addr: u64,
    /// SMMU instance index (for multi-SMMU systems).
    pub smmu_index: u8,
    /// Whether the SMMU is initialised and operational.
    pub is_ready: bool,
    /// Maximum stream ID supported by this SMMU.
    pub max_streams: u32,
    /// Number of allocated IOSpaces.
    pub iospace_count: u16,
    /// Next IOASID to assign.
    pub next_ioasid: u16,
    /// Bitmap of claimed stream IDs (supports up to 1024 inline).
    pub claimed_streams: [u64; STREAM_BITMAP_WORDS],
}

impl SmmuControlObject {
    /// Create a new SMMU control object.
    #[inline]
    #[must_use]
    pub const fn new(base_addr: u64, virt_addr: u64, smmu_index: u8, max_streams: u32) -> Self {
        Self {
            base_addr,
            virt_addr,
            smmu_index,
            is_ready: false,
            max_streams,
            iospace_count: 0,
            next_ioasid: 1, // 0 is reserved/invalid
            claimed_streams: [0; STREAM_BITMAP_WORDS],
        }
    }

    /// Mark the SMMU as ready.
    #[inline]
    pub fn set_ready(&mut self) {
        self.is_ready = true;
    }

    /// Check if a stream ID is valid for this SMMU.
    #[inline]
    #[must_use]
    pub const fn is_valid_stream(&self, stream_id: StreamId) -> bool {
        stream_id < self.max_streams
    }

    /// Check if a stream ID is available (not claimed).
    #[inline]
    #[must_use]
    pub fn is_stream_available(&self, stream_id: StreamId) -> bool {
        if !self.is_valid_stream(stream_id) {
            return false;
        }
        if (stream_id as usize) >= MAX_INLINE_STREAMS {
            // Stream IDs beyond inline bitmap are always available
            // (would need extended tracking for production use)
            return true;
        }
        let word_idx = (stream_id / 64) as usize;
        let bit_idx = (stream_id % 64) as usize;
        self.claimed_streams[word_idx] & (1u64 << bit_idx) == 0
    }

    /// Claim a stream ID.
    ///
    /// Returns `true` if successfully claimed, `false` if already claimed or invalid.
    pub fn claim_stream(&mut self, stream_id: StreamId) -> bool {
        if !self.is_stream_available(stream_id) {
            return false;
        }
        if (stream_id as usize) < MAX_INLINE_STREAMS {
            let word_idx = (stream_id / 64) as usize;
            let bit_idx = (stream_id % 64) as usize;
            self.claimed_streams[word_idx] |= 1u64 << bit_idx;
        }
        true
    }

    /// Release a stream ID.
    pub fn release_stream(&mut self, stream_id: StreamId) {
        if !self.is_valid_stream(stream_id) {
            return;
        }
        if (stream_id as usize) < MAX_INLINE_STREAMS {
            let word_idx = (stream_id / 64) as usize;
            let bit_idx = (stream_id % 64) as usize;
            self.claimed_streams[word_idx] &= !(1u64 << bit_idx);
        }
    }

    /// Allocate an IOASID.
    ///
    /// Returns the allocated IOASID, or `None` if exhausted.
    pub fn alloc_ioasid(&mut self) -> Option<u16> {
        if self.next_ioasid == 0 {
            // Wrapped around, exhausted
            return None;
        }
        let ioasid = self.next_ioasid;
        self.next_ioasid = self.next_ioasid.wrapping_add(1);
        Some(ioasid)
    }

    /// Increment the IOSpace count.
    #[inline]
    pub fn increment_iospaces(&mut self) {
        self.iospace_count = self.iospace_count.saturating_add(1);
    }

    /// Decrement the IOSpace count.
    #[inline]
    pub fn decrement_iospaces(&mut self) {
        self.iospace_count = self.iospace_count.saturating_sub(1);
    }

    /// Get the number of claimed streams.
    #[must_use]
    pub fn claimed_stream_count(&self) -> u32 {
        self.claimed_streams
            .iter()
            .map(|&word| word.count_ones())
            .sum()
    }
}

/// Stream table entry binding.
///
/// Associates a stream ID with an IOSpace.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct StreamBinding {
    /// The bound IOSpace.
    pub iospace: ObjectRef,
    /// Notification for fault delivery.
    pub fault_notification: ObjectRef,
    /// Badge for fault notification.
    pub fault_badge: u64,
}

impl StreamBinding {
    /// Create a new stream binding.
    #[inline]
    #[must_use]
    pub const fn new(iospace: ObjectRef) -> Self {
        Self {
            iospace,
            fault_notification: ObjectRef::NULL,
            fault_badge: 0,
        }
    }

    /// Check if a fault handler is configured.
    #[inline]
    #[must_use]
    pub const fn has_fault_handler(&self) -> bool {
        self.fault_notification.is_valid()
    }

    /// Configure the fault handler.
    #[inline]
    pub fn set_fault_handler(&mut self, notification: ObjectRef, badge: u64) {
        self.fault_notification = notification;
        self.fault_badge = badge;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smmu_control_creation() {
        let ctrl = SmmuControlObject::new(0xfc900000, 0xffff_fffe_fc90_0000, 0, 1024);
        assert!(!ctrl.is_ready);
        assert_eq!(ctrl.max_streams, 1024);
        assert_eq!(ctrl.iospace_count, 0);
    }

    #[test]
    fn test_stream_claiming() {
        let mut ctrl = SmmuControlObject::new(0xfc900000, 0xffff_fffe_fc90_0000, 0, 1024);

        assert!(ctrl.is_stream_available(0));
        assert!(ctrl.claim_stream(0));
        assert!(!ctrl.is_stream_available(0));
        assert!(!ctrl.claim_stream(0)); // Already claimed

        ctrl.release_stream(0);
        assert!(ctrl.is_stream_available(0));
    }

    #[test]
    fn test_ioasid_allocation() {
        let mut ctrl = SmmuControlObject::new(0xfc900000, 0xffff_fffe_fc90_0000, 0, 1024);

        let ioasid1 = ctrl.alloc_ioasid();
        assert_eq!(ioasid1, Some(1));

        let ioasid2 = ctrl.alloc_ioasid();
        assert_eq!(ioasid2, Some(2));
    }

    #[test]
    fn test_claimed_stream_count() {
        let mut ctrl = SmmuControlObject::new(0xfc900000, 0xffff_fffe_fc90_0000, 0, 1024);

        ctrl.claim_stream(0);
        ctrl.claim_stream(64);
        ctrl.claim_stream(128);
        assert_eq!(ctrl.claimed_stream_count(), 3);
    }

    #[test]
    fn test_stream_binding() {
        let mut binding = StreamBinding::new(ObjectRef::from_index(1));
        assert!(!binding.has_fault_handler());

        binding.set_fault_handler(ObjectRef::from_index(2), 0x42);
        assert!(binding.has_fault_handler());
        assert_eq!(binding.fault_badge, 0x42);
    }
}
