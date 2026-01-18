//! Size class selection
//!
//! Determines which size class to use for a given allocation request.

use crate::config::{MAX_SMALL_SIZE, SIZE_CLASSES};

/// Find the appropriate size class for a given allocation size
///
/// # Arguments
/// * `size` - The requested allocation size in bytes
///
/// # Returns
/// The index of the size class to use, or None if the size exceeds
/// the maximum small allocation size (use large allocation path).
pub fn find_size_class(size: usize) -> Option<usize> {
    // Zero-size allocations use the smallest class
    if size == 0 {
        return Some(0);
    }

    // Large allocations don't use size classes
    if size > MAX_SMALL_SIZE {
        return None;
    }

    // Linear search through size classes
    // This is fast for small arrays and cache-friendly
    for (idx, class) in SIZE_CLASSES.iter().enumerate() {
        if class.size >= size {
            return Some(idx);
        }
    }

    None
}

/// Find a size class that satisfies both size and alignment requirements
///
/// # Arguments
/// * `size` - The requested allocation size in bytes
/// * `align` - The required alignment in bytes
///
/// # Returns
/// The index of the size class to use, or None if no suitable class exists.
pub fn find_size_class_aligned(size: usize, align: usize) -> Option<usize> {
    // The effective size must be at least the alignment
    let effective_size = size.max(align);

    // Large allocations don't use size classes
    if effective_size > MAX_SMALL_SIZE {
        return None;
    }

    // Find a class that's large enough and has suitable alignment
    for (idx, class) in SIZE_CLASSES.iter().enumerate() {
        // The slot size must be at least the effective size
        // and the slot size must be a multiple of the alignment
        if class.size >= effective_size && class.size % align == 0 {
            return Some(idx);
        }
    }

    // No suitable size class - use large allocation
    None
}

/// Get the slot size for a size class
pub fn slot_size(class_idx: usize) -> usize {
    SIZE_CLASSES[class_idx].size
}

/// Get the number of pages per span for a size class
pub fn span_pages(class_idx: usize) -> usize {
    SIZE_CLASSES[class_idx].span_pages
}

/// Get the number of slots per span for a size class
pub fn slots_per_span(class_idx: usize) -> usize {
    SIZE_CLASSES[class_idx].slots_per_span()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NUM_SIZE_CLASSES;

    #[test]
    fn test_zero_size() {
        assert_eq!(find_size_class(0), Some(0));
    }

    #[test]
    fn test_exact_sizes() {
        // Test exact size class boundaries
        assert_eq!(find_size_class(8), Some(0));
        assert_eq!(find_size_class(16), Some(1));
        assert_eq!(find_size_class(32), Some(2));
        assert_eq!(find_size_class(2048), Some(NUM_SIZE_CLASSES - 1));
    }

    #[test]
    fn test_intermediate_sizes() {
        // Test sizes between classes
        assert_eq!(find_size_class(9), Some(1)); // 9 -> 16
        assert_eq!(find_size_class(17), Some(2)); // 17 -> 32
        assert_eq!(find_size_class(33), Some(3)); // 33 -> 48
    }

    #[test]
    fn test_large_sizes() {
        // Sizes above MAX_SMALL_SIZE should return None
        assert_eq!(find_size_class(2049), None);
        assert_eq!(find_size_class(4096), None);
        assert_eq!(find_size_class(1024 * 1024), None);
    }

    #[test]
    fn test_aligned_selection() {
        // Alignment 8 should work with most classes
        assert_eq!(find_size_class_aligned(8, 8), Some(0));

        // Alignment 16 needs at least 16-byte slots
        assert_eq!(find_size_class_aligned(8, 16), Some(1));

        // Alignment 64 needs 64-byte or larger slots that are 64-aligned
        let result = find_size_class_aligned(8, 64);
        assert!(result.is_some());
        let class = SIZE_CLASSES[result.unwrap()];
        assert!(class.size >= 64);
        assert_eq!(class.size % 64, 0);
    }

    #[test]
    fn test_large_alignment() {
        // Very large alignments should fall back to large allocation
        assert_eq!(find_size_class_aligned(8, 4096), None);
    }
}
