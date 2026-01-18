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
