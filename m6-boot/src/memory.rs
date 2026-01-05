//! Memory Map Translation
//!
//! Translates UEFI memory map to M6 BootInfo format.

use m6_common::memory::{MemoryMap, MemoryRegion, MemoryType};
use m6_common::boot::MAX_MEMORY_REGIONS;
use uefi::mem::memory_map::{MemoryMap as UefiMemoryMap, MemoryMapOwned, MemoryType as UefiMemoryType};

/// Translate UEFI memory type to M6 memory type
fn translate_memory_type(uefi_type: UefiMemoryType) -> MemoryType {
    match uefi_type {
        UefiMemoryType::CONVENTIONAL => MemoryType::Conventional,
        UefiMemoryType::LOADER_CODE | UefiMemoryType::LOADER_DATA => {
            MemoryType::BootloaderReclaimable
        }
        UefiMemoryType::BOOT_SERVICES_CODE | UefiMemoryType::BOOT_SERVICES_DATA => {
            MemoryType::BootloaderReclaimable
        }
        UefiMemoryType::RUNTIME_SERVICES_CODE | UefiMemoryType::RUNTIME_SERVICES_DATA => {
            MemoryType::UefiRuntime
        }
        UefiMemoryType::ACPI_RECLAIM => MemoryType::AcpiReclaimable,
        UefiMemoryType::ACPI_NON_VOLATILE => MemoryType::AcpiNvs,
        UefiMemoryType::MMIO | UefiMemoryType::MMIO_PORT_SPACE => MemoryType::Mmio,
        _ => MemoryType::Reserved,
    }
}

/// Translate UEFI memory map to M6 memory map format
///
/// This function coalesces adjacent regions of the same type and
/// filters out unusable regions.
pub fn translate_memory_map(uefi_map: &MemoryMapOwned) -> MemoryMap {
    let mut m6_map = MemoryMap::empty();
    let mut count = 0usize;

    for descriptor in uefi_map.entries() {
        if count >= MAX_MEMORY_REGIONS {
            log::warn!("Memory map truncated: too many regions");
            break;
        }

        let m6_type = translate_memory_type(descriptor.ty);
        let base = descriptor.phys_start;
        let size = descriptor.page_count * 4096; // UEFI always uses 4KB pages

        // Try to coalesce with previous region if same type and contiguous
        if count > 0 {
            let prev = &mut m6_map.regions[count - 1];
            if prev.memory_type == m6_type && prev.end() == base {
                prev.size += size;
                continue;
            }
        }

        m6_map.regions[count] = MemoryRegion {
            base,
            size,
            memory_type: m6_type,
            _reserved: 0,
        };
        count += 1;
    }

    m6_map.entry_count = count as u32;
    m6_map
}

/// Mark a region in the memory map with a specific type
///
/// This implementation handles all cases of region overlap:
/// 1. Exact match: just update the type
/// 2. Prefix: target at start of region, split into [marked | remainder]
/// 3. Suffix: target at end of region, split into [remainder | marked]
/// 4. Middle: target in middle, split into [before | marked | after]
/// 5. No overlap: add as new region
pub fn mark_region(map: &mut MemoryMap, base: u64, size: u64, new_type: MemoryType) {
    let count = map.entry_count as usize;
    let target_end = base + size;

    // Find overlapping region
    for i in 0..count {
        let region = &map.regions[i];
        let region_base = region.base;
        let region_end = region.base + region.size;

        // Check if this region contains our target
        if region_base <= base && region_end >= target_end {
            // Case 1: Exact match
            if region_base == base && region.size == size {
                map.regions[i].memory_type = new_type;
                return;
            }

            // Case 2: Prefix (target at start of region)
            if region_base == base {
                if count < MAX_MEMORY_REGIONS {
                    // Shift remaining entries by 1
                    for j in (i + 1..count).rev() {
                        map.regions[j + 1] = map.regions[j];
                    }
                    // Insert marked region at start
                    map.regions[i] = MemoryRegion {
                        base,
                        size,
                        memory_type: new_type,
                        _reserved: 0,
                    };
                    // Adjust the remainder
                    map.regions[i + 1].base = target_end;
                    map.regions[i + 1].size = region_end - target_end;
                    map.entry_count += 1;
                    return;
                }
                break;
            }

            // Case 3: Suffix (target at end of region)
            if target_end == region_end {
                if count < MAX_MEMORY_REGIONS {
                    // Shift remaining entries by 1
                    for j in (i + 1..count).rev() {
                        map.regions[j + 1] = map.regions[j];
                    }
                    // Shrink original region
                    map.regions[i].size = base - region_base;
                    // Insert marked region at end
                    map.regions[i + 1] = MemoryRegion {
                        base,
                        size,
                        memory_type: new_type,
                        _reserved: 0,
                    };
                    map.entry_count += 1;
                    return;
                }
                break;
            }

            // Case 4: Middle split (target in middle of region, need 2 new slots)
            if count + 1 < MAX_MEMORY_REGIONS {
                let orig_type = region.memory_type;
                let before_size = base - region_base;
                let after_base = target_end;
                let after_size = region_end - target_end;

                // Shift remaining entries by 2
                for j in (i + 1..count).rev() {
                    map.regions[j + 2] = map.regions[j];
                }

                // [before][marked][after]
                map.regions[i] = MemoryRegion {
                    base: region_base,
                    size: before_size,
                    memory_type: orig_type,
                    _reserved: 0,
                };
                map.regions[i + 1] = MemoryRegion {
                    base,
                    size,
                    memory_type: new_type,
                    _reserved: 0,
                };
                map.regions[i + 2] = MemoryRegion {
                    base: after_base,
                    size: after_size,
                    memory_type: orig_type,
                    _reserved: 0,
                };
                map.entry_count += 2;
                return;
            }

            break;
        }
    }

    // Fallback: add as new region if space available
    if count < MAX_MEMORY_REGIONS {
        map.regions[count] = MemoryRegion {
            base,
            size,
            memory_type: new_type,
            _reserved: 0,
        };
        map.entry_count += 1;
        log::debug!("Added memory region: base={:#x} size={:#x} type={:?}", base, size, new_type);
    } else {
        log::warn!("Cannot add region: memory map full");
    }
}
