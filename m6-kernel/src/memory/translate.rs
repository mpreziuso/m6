//! Physical/Virtual Address Translation
//!
//! Provides utilities for converting between physical and virtual addresses
//! using the direct physical map.

use super::layout::virt;

/// Convert a physical address to a virtual address using the direct physical map.
///
/// # Arguments
///
/// * `phys` - Physical address to convert
///
/// # Returns
///
/// Virtual address in the direct physical map region.
///
/// # Panics
///
/// Panics if the physical address is outside the direct map range.
/// For a fallible version, use `phys_to_virt_checked`.
#[inline]
#[must_use]
pub fn phys_to_virt(phys: u64) -> u64 {
    let max = super::max_phys_addr();
    assert!(
        phys < max,
        "Physical address {:#x} exceeds direct map size ({:#x})",
        phys,
        max
    );
    virt::PHYS_MAP_BASE + phys
}

/// Convert a physical address to a virtual address, returning None if out of range.
///
/// This is the safe, fallible version of `phys_to_virt`.
#[inline]
#[must_use]
pub fn phys_to_virt_checked(phys: u64) -> Option<u64> {
    if phys < super::max_phys_addr() {
        Some(virt::PHYS_MAP_BASE + phys)
    } else {
        None
    }
}

/// Convert a virtual address from the direct physical map to a physical address.
///
/// # Arguments
///
/// * `virt_addr` - Virtual address in the direct physical map region
///
/// # Returns
///
/// The corresponding physical address.
///
/// # Panics
///
/// Panics if the virtual address is not in the direct physical map region.
/// For a fallible version, use `virt_to_phys_checked`.
#[inline]
#[must_use]
pub fn virt_to_phys(virt_addr: u64) -> u64 {
    let max = super::max_phys_addr();
    let phys_map_end = virt::PHYS_MAP_BASE + max;
    assert!(
        (virt::PHYS_MAP_BASE..phys_map_end).contains(&virt_addr),
        "Virtual address {:#x} not in direct physical map ({:#x}..{:#x})",
        virt_addr,
        virt::PHYS_MAP_BASE,
        phys_map_end
    );
    virt_addr - virt::PHYS_MAP_BASE
}

/// Convert a virtual address to a physical address, returning None if out of range.
///
/// This is the safe, fallible version of `virt_to_phys`.
#[inline]
#[must_use]
pub fn virt_to_phys_checked(virt_addr: u64) -> Option<u64> {
    let max = super::max_phys_addr();
    let phys_map_end = virt::PHYS_MAP_BASE + max;
    if (virt::PHYS_MAP_BASE..phys_map_end).contains(&virt_addr) {
        Some(virt_addr - virt::PHYS_MAP_BASE)
    } else {
        None
    }
}

/// Convert a physical address to a mutable pointer via the direct physical map.
///
/// # Safety
///
/// The caller must ensure:
/// - The physical address is valid and maps to accessible memory
/// - No other code is concurrently accessing the memory (or access is synchronised)
/// - The resulting pointer is used correctly for the intended type T
/// - The physical address is properly aligned for type T
///
/// # Panics
///
/// Panics if the physical address is outside the direct map range.
#[inline]
#[must_use]
pub unsafe fn phys_to_ptr<T>(phys: u64) -> *mut T {
    phys_to_virt(phys) as *mut T
}

/// Convert a physical address to a mutable pointer, returning None if out of range.
///
/// # Safety
///
/// Same requirements as `phys_to_ptr`, except this returns None instead of panicking
/// for out-of-range addresses.
#[inline]
#[must_use]
pub unsafe fn phys_to_ptr_checked<T>(phys: u64) -> Option<*mut T> {
    phys_to_virt_checked(phys).map(|v| v as *mut T)
}
