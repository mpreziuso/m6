//! Memory region abstractions
//!
//! Provides type-safe memory region handling for both physical and virtual
//! address spaces, with alignment and iteration helpers.

use crate::PAGE_SIZE;
use crate::address::{Address, MemKind, PA, Physical, VA, Virtual};

/// A contiguous memory region in either physical or virtual address space
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion<K: MemKind> {
    start: Address<K, ()>,
    size: usize,
}

/// Physical memory region
pub type PhysMemoryRegion = MemoryRegion<Physical>;

/// Virtual memory region
pub type VirtMemoryRegion = MemoryRegion<Virtual>;

impl<K: MemKind> MemoryRegion<K> {
    #[inline]
    pub const fn new(start: Address<K, ()>, size: usize) -> Self {
        Self { start, size }
    }

    #[inline]
    pub const fn empty() -> Self {
        Self {
            start: Address::null(),
            size: 0,
        }
    }

    #[inline]
    pub const fn start(&self) -> Address<K, ()> {
        self.start
    }

    #[inline]
    pub fn end(&self) -> Address<K, ()> {
        self.start + self.size as u64
    }

    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    pub const fn page_count(&self) -> usize {
        self.size.div_ceil(PAGE_SIZE)
    }

    #[inline]
    pub const fn is_page_aligned(&self) -> bool {
        self.start.is_page_aligned() && (self.size & (PAGE_SIZE - 1)) == 0
    }

    #[inline]
    pub fn contains_addr(&self, addr: Address<K, ()>) -> bool {
        addr.value() >= self.start.value() && addr.value() < self.end().value()
    }

    #[inline]
    pub fn contains(&self, other: &Self) -> bool {
        !other.is_empty()
            && other.start.value() >= self.start.value()
            && other.end().value() <= self.end().value()
    }

    #[inline]
    pub fn overlaps(&self, other: &Self) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && self.start.value() < other.end().value()
            && other.start.value() < self.end().value()
    }

    /// Advance the region by the given number of pages
    ///
    /// Returns a new region starting after the specified pages.
    #[inline]
    pub fn add_pages(self, pages: usize) -> Self {
        let bytes = pages * PAGE_SIZE;
        if bytes >= self.size {
            Self::empty()
        } else {
            Self {
                start: self.start + bytes as u64,
                size: self.size - bytes,
            }
        }
    }

    /// Split region at a page boundary
    ///
    /// Returns (before, after) where `before` contains pages before the split
    /// and `after` contains pages at and after the split.
    #[inline]
    pub fn split_at_page(self, page_index: usize) -> (Self, Self) {
        let split_offset = page_index * PAGE_SIZE;
        if split_offset >= self.size {
            (self, Self::empty())
        } else {
            (
                Self::new(self.start, split_offset),
                Self::new(self.start + split_offset as u64, self.size - split_offset),
            )
        }
    }

    /// Align region to page boundaries (expand)
    ///
    /// Aligns start down and end up to page boundaries.
    #[inline]
    pub fn page_align_expand(self) -> Self {
        let aligned_start = self.start.page_align_down();
        let aligned_end = (self.start + self.size as u64).page_align_up();
        Self::new(aligned_start, (aligned_end - aligned_start) as usize)
    }

    /// Align region to page boundaries (shrink)
    ///
    /// Aligns start up and end down to page boundaries.
    /// May result in an empty region.
    #[inline]
    pub fn page_align_shrink(self) -> Self {
        let aligned_start = self.start.page_align_up();
        let end = self.start + self.size as u64;
        let aligned_end = end.page_align_down();

        if aligned_end.value() <= aligned_start.value() {
            Self::empty()
        } else {
            Self::new(aligned_start, (aligned_end - aligned_start) as usize)
        }
    }

    #[inline]
    pub fn iter_pages(&self) -> PageIterator<K> {
        PageIterator {
            current: self.start.page_align_down(),
            end: self.end(),
        }
    }
}

impl PhysMemoryRegion {
    #[inline]
    pub const fn from_raw(start: u64, size: usize) -> Self {
        Self::new(PA::new(start), size)
    }
}

impl VirtMemoryRegion {
    #[inline]
    pub const fn from_raw(start: u64, size: usize) -> Self {
        Self::new(VA::new(start), size)
    }
}

pub struct PageIterator<K: MemKind> {
    current: Address<K, ()>,
    end: Address<K, ()>,
}

impl<K: MemKind> Iterator for PageIterator<K> {
    type Item = Address<K, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.value() >= self.end.value() {
            None
        } else {
            let addr = self.current;
            self.current = self.current + PAGE_SIZE as u64;
            Some(addr)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.current.value() >= self.end.value() {
            (0, Some(0))
        } else {
            let remaining =
                ((self.end.value() - self.current.value()) as usize).div_ceil(PAGE_SIZE);
            (remaining, Some(remaining))
        }
    }
}

impl<K: MemKind> ExactSizeIterator for PageIterator<K> {}

impl<K: MemKind> core::fmt::Debug for MemoryRegion<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MemoryRegion {{ {:#x}..{:#x} ({} bytes) }}",
            self.start.value(),
            self.end().value(),
            self.size
        )
    }
}

impl<K: MemKind> Default for MemoryRegion<K> {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phys(start: u64, size: usize) -> PhysMemoryRegion {
        PhysMemoryRegion::new(PA::new(start), size)
    }

    #[test_case]
    fn test_overlaps_no_overlap() {
        let a = phys(0x1000, 0x1000);
        let b = phys(0x3000, 0x1000);
        assert!(!a.overlaps(&b));
        assert!(!b.overlaps(&a));
    }

    #[test_case]
    fn test_overlaps_adjacent_not_overlapping() {
        let a = phys(0x1000, 0x1000); // ends at 0x2000
        let b = phys(0x2000, 0x1000); // starts at 0x2000
        assert!(!a.overlaps(&b));
        assert!(!b.overlaps(&a));
    }

    #[test_case]
    fn test_overlaps_partial() {
        let a = phys(0x1000, 0x2000); // 0x1000..0x3000
        let b = phys(0x2000, 0x2000); // 0x2000..0x4000
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
    }

    #[test_case]
    fn test_overlaps_full_containment() {
        let outer = phys(0x1000, 0x4000);
        let inner = phys(0x2000, 0x1000);
        assert!(outer.overlaps(&inner));
        assert!(inner.overlaps(&outer));
    }

    #[test_case]
    fn test_overlaps_empty_regions() {
        let a = phys(0x1000, 0x1000);
        let empty = PhysMemoryRegion::empty();
        assert!(!a.overlaps(&empty));
        assert!(!empty.overlaps(&a));
    }

    #[test_case]
    fn test_contains_full() {
        let outer = phys(0x1000, 0x4000);
        let inner = phys(0x2000, 0x1000);
        assert!(outer.contains(&inner));
        assert!(!inner.contains(&outer));
    }

    #[test_case]
    fn test_contains_exact_boundaries() {
        let a = phys(0x1000, 0x2000);
        assert!(a.contains(&a));
    }

    #[test_case]
    fn test_contains_partial() {
        let a = phys(0x1000, 0x2000); // 0x1000..0x3000
        let b = phys(0x2000, 0x2000); // 0x2000..0x4000
        assert!(!a.contains(&b)); // b extends beyond a
        assert!(!b.contains(&a));
    }

    #[test_case]
    fn test_split_at_page_sizes_sum() {
        let r = phys(0x0, PAGE_SIZE * 4);
        let (before, after) = r.split_at_page(2);
        assert_eq!(before.size() + after.size(), r.size());
        assert_eq!(before.size(), PAGE_SIZE * 2);
        assert_eq!(after.size(), PAGE_SIZE * 2);
    }

    #[test_case]
    fn test_split_at_page_boundaries() {
        let r = phys(0x1000, PAGE_SIZE * 3);
        let (before, after) = r.split_at_page(1);
        assert_eq!(before.start().value(), 0x1000);
        assert_eq!(before.size(), PAGE_SIZE);
        assert_eq!(after.start().value(), 0x1000 + PAGE_SIZE as u64);
        assert_eq!(after.size(), PAGE_SIZE * 2);
    }

    #[test_case]
    fn test_split_at_page_zero() {
        let r = phys(0x1000, PAGE_SIZE * 3);
        let (before, after) = r.split_at_page(0);
        assert_eq!(before.size(), 0);
        assert!(before.is_empty());
        assert_eq!(after.size(), PAGE_SIZE * 3);
    }

    #[test_case]
    fn test_split_at_page_beyond_end() {
        let r = phys(0x1000, PAGE_SIZE * 2);
        let (before, after) = r.split_at_page(10);
        assert_eq!(before.size(), PAGE_SIZE * 2);
        assert!(after.is_empty());
    }

    #[test_case]
    fn test_page_align_expand_aligned() {
        let r = phys(0x2000, PAGE_SIZE * 3);
        let expanded = r.page_align_expand();
        assert_eq!(expanded.start().value(), 0x2000);
        assert_eq!(expanded.size(), PAGE_SIZE * 3);
    }

    #[test_case]
    fn test_page_align_expand_unaligned() {
        let r = phys(0x1800, 0x2000); // start unaligned, end unaligned
        let expanded = r.page_align_expand();
        assert!(expanded.start().is_page_aligned());
        assert!(expanded.size() % PAGE_SIZE == 0);
        // Expanded start is below original start
        assert!(expanded.start().value() <= r.start().value());
        // Expanded end is at or above original end
        assert!(expanded.end().value() >= r.end().value());
    }

    #[test_case]
    fn test_page_align_shrink_aligned() {
        let r = phys(0x2000, PAGE_SIZE * 3);
        let shrunk = r.page_align_shrink();
        assert_eq!(shrunk.start().value(), 0x2000);
        assert_eq!(shrunk.size(), PAGE_SIZE * 3);
    }

    #[test_case]
    fn test_page_align_shrink_unaligned() {
        // Region that shrinks to empty
        let r = phys(0x1001, 0x100); // entirely within one page
        let shrunk = r.page_align_shrink();
        assert!(shrunk.is_empty());
    }

    #[test_case]
    fn test_iter_pages_count() {
        let r = phys(0x0, PAGE_SIZE * 5);
        let count = r.iter_pages().count();
        assert_eq!(count, r.page_count());
        assert_eq!(count, 5);
    }

    #[test_case]
    fn test_iter_pages_order() {
        let r = phys(0x2000, PAGE_SIZE * 3);
        let mut iter = r.iter_pages();
        assert_eq!(iter.next().unwrap().value(), 0x2000);
        assert_eq!(iter.next().unwrap().value(), 0x2000 + PAGE_SIZE as u64);
        assert_eq!(iter.next().unwrap().value(), 0x2000 + 2 * PAGE_SIZE as u64);
        assert!(iter.next().is_none());
    }

    #[test_case]
    fn test_add_pages() {
        let r = phys(0x1000, PAGE_SIZE * 4);
        let r2 = r.add_pages(2);
        assert_eq!(r2.start().value(), 0x1000 + 2 * PAGE_SIZE as u64);
        assert_eq!(r2.size(), PAGE_SIZE * 2);
    }

    #[test_case]
    fn test_add_pages_all() {
        let r = phys(0x1000, PAGE_SIZE * 4);
        let r2 = r.add_pages(4);
        assert!(r2.is_empty());
    }
}
