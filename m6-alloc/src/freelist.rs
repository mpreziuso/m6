//! Encoded freelist with pointer obfuscation and validation
//!
//! The freelist uses XOR encoding with a per-process secret to harden
//! against heap exploitation. Each pointer is also mixed with its storage
//! address to prevent pointer swapping attacks.

use core::sync::atomic::Ordering;

use crate::error::FreelistError;
use crate::span::SpanMeta;

/// Encoded freelist pointer
///
/// Format: encoded = ptr ^ secret ^ (slot_addr.rotate_left(12))
///
/// The rotation mixes the slot address into the encoding to prevent
/// an attacker from swapping encoded pointers between slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedPtr(pub u64);

impl EncodedPtr {
    /// Null/empty encoded pointer
    pub const NULL: Self = Self(0);

    /// Check if this is a null pointer
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Encode a pointer for storage in the freelist
    ///
    /// # Arguments
    /// * `ptr` - The actual pointer to encode
    /// * `slot_addr` - The address where this encoded pointer will be stored
    /// * `secret` - The per-process encoding secret
    ///
    /// # Returns
    /// The encoded pointer value
    pub fn encode(ptr: *mut u8, slot_addr: usize, secret: u64) -> Self {
        if ptr.is_null() {
            return Self::NULL;
        }

        let ptr_val = ptr as u64;
        let addr_mix = (slot_addr as u64).rotate_left(12);
        Self(ptr_val ^ secret ^ addr_mix)
    }

    /// Decode and validate a freelist pointer
    ///
    /// # Arguments
    /// * `slot_addr` - The address where this encoded pointer was stored
    /// * `secret` - The per-process encoding secret
    /// * `span` - The span containing this slot (for validation)
    ///
    /// # Returns
    /// The decoded pointer on success, or an error if validation fails
    pub fn decode(
        self,
        slot_addr: usize,
        secret: u64,
        span: &SpanMeta,
    ) -> Result<*mut u8, FreelistError> {
        if self.is_null() {
            return Ok(core::ptr::null_mut());
        }

        let addr_mix = (slot_addr as u64).rotate_left(12);
        let decoded = self.0 ^ secret ^ addr_mix;
        let ptr = decoded as usize;

        // Validate alignment (must be at least pointer-aligned)
        if !ptr.is_multiple_of(core::mem::align_of::<usize>()) {
            return Err(FreelistError::BadAlignment);
        }

        // Validate range (must be within span)
        if ptr < span.base_addr() {
            return Err(FreelistError::OutOfRange);
        }

        if ptr >= span.end_addr() {
            return Err(FreelistError::OutOfRange);
        }

        // Validate slot boundary
        let offset = ptr - span.base_addr();
        let slot_size = span.slot_size();
        if !offset.is_multiple_of(slot_size) {
            return Err(FreelistError::NotSlotAligned);
        }

        Ok(decoded as *mut u8)
    }

    /// Decode without full validation (for trusted contexts)
    ///
    /// Only use this when the pointer is known to be valid.
    pub fn decode_unchecked(self, slot_addr: usize, secret: u64) -> *mut u8 {
        if self.is_null() {
            return core::ptr::null_mut();
        }

        let addr_mix = (slot_addr as u64).rotate_left(12);
        let decoded = self.0 ^ secret ^ addr_mix;
        decoded as *mut u8
    }
}

/// Initialise a span's freelist
///
/// Links all slots together in a freelist, with each slot's first 8 bytes
/// containing an encoded pointer to the next free slot.
///
/// # Safety
/// The span must be mapped and writable.
pub unsafe fn init_span_freelist(span: &SpanMeta, secret: u64) {
    let slot_size = span.slot_size();
    let total_slots = span.total_slots();
    let base = span.base_addr();

    // Link slots together: slot[i] -> slot[i+1]
    for i in 0..total_slots - 1 {
        let current_addr = base + (i * slot_size);
        let next_addr = base + ((i + 1) * slot_size);
        let encoded = EncodedPtr::encode(next_addr as *mut u8, current_addr, secret);

        // SAFETY: Caller guarantees span is mapped
        unsafe {
            let ptr = current_addr as *mut u64;
            ptr.write(encoded.0);
        }
    }

    // Last slot points to null
    let last_addr = base + ((total_slots - 1) * slot_size);
    unsafe {
        let ptr = last_addr as *mut u64;
        ptr.write(EncodedPtr::NULL.0);
    }

    // Set freelist head to first slot
    let first_encoded = EncodedPtr::encode(base as *mut u8, base, secret);
    span.freelist_head.store(first_encoded.0, Ordering::Release);
}

/// Pop a slot from a span's freelist
///
/// # Safety
/// The span must be mapped and the freelist must be valid.
///
/// # Returns
/// The address of the allocated slot, or None if the span is full.
pub unsafe fn pop_freelist(span: &SpanMeta, secret: u64) -> Result<Option<usize>, FreelistError> {
    let head_encoded = EncodedPtr(span.freelist_head.load(Ordering::Acquire));

    if head_encoded.is_null() {
        return Ok(None);
    }

    // The head is stored at a "virtual" address for the span head
    // We use the span base address as the storage location
    let head_ptr = head_encoded.decode(span.base_addr(), secret, span)?;
    let head_addr = head_ptr as usize;

    // Read the next pointer from the slot we're about to return
    // SAFETY: Caller guarantees span is mapped
    let next_encoded = unsafe {
        let ptr = head_addr as *const u64;
        EncodedPtr(ptr.read())
    };

    // Re-encode the next pointer for the new head position
    if next_encoded.is_null() {
        span.freelist_head.store(0, Ordering::Release);
    } else {
        let next_ptr = next_encoded.decode(head_addr, secret, span)?;
        let new_head = EncodedPtr::encode(next_ptr, span.base_addr(), secret);
        span.freelist_head.store(new_head.0, Ordering::Release);
    }

    Ok(Some(head_addr))
}

/// Push a slot back onto a span's freelist
///
/// # Safety
/// The span must be mapped and the slot_addr must be a valid slot in the span.
pub unsafe fn push_freelist(span: &SpanMeta, slot_addr: usize, secret: u64) {
    let old_head = EncodedPtr(span.freelist_head.load(Ordering::Acquire));

    // Write the old head into the slot being freed
    // The encoded value uses the slot_addr as the storage location
    let old_head_ptr = if old_head.is_null() {
        core::ptr::null_mut()
    } else {
        old_head.decode_unchecked(span.base_addr(), secret)
    };
    let new_next = EncodedPtr::encode(old_head_ptr, slot_addr, secret);

    // SAFETY: Caller guarantees slot is valid
    unsafe {
        let ptr = slot_addr as *mut u64;
        ptr.write(new_next.0);
    }

    // Update head to point to the freed slot
    let new_head = EncodedPtr::encode(slot_addr as *mut u8, span.base_addr(), secret);
    span.freelist_head.store(new_head.0, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_null() {
        let encoded = EncodedPtr::encode(core::ptr::null_mut(), 0x1000, 0xDEADBEEF);
        assert!(encoded.is_null());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let secret = 0xDEADBEEF12345678u64;
        let slot_addr = 0x1000usize;
        let ptr = 0x2000 as *mut u8;

        let encoded = EncodedPtr::encode(ptr, slot_addr, secret);
        assert!(!encoded.is_null());
        assert_ne!(encoded.0, ptr as u64); // Should be obfuscated

        let decoded = encoded.decode_unchecked(slot_addr, secret);
        assert_eq!(decoded, ptr);
    }

    #[test]
    fn test_different_slot_addrs_produce_different_encodings() {
        let secret = 0xDEADBEEF12345678u64;
        let ptr = 0x2000 as *mut u8;

        let encoded1 = EncodedPtr::encode(ptr, 0x1000, secret);
        let encoded2 = EncodedPtr::encode(ptr, 0x1008, secret);

        assert_ne!(encoded1.0, encoded2.0);
    }
}
