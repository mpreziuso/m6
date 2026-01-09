//! User address space layout
//!
//! Defines the virtual memory layout for userspace processes.
//!
//! # Memory Layout (48-bit virtual addresses)
//!
//! ```text
//! 0x0000_0000_0000_0000 - 0x0000_0000_0000_FFFF : Null guard region (unmapped)
//! 0x0000_0000_0001_0000 - 0x0000_0000_FFFF_FFFF : ELF load region (code/data)
//! 0x0000_0001_0000_0000 - 0x0000_7FFE_FFFF_FFFF : Heap/mmap region
//! 0x0000_7FFF_BFF0_0000 - 0x0000_7FFF_BFF0_0FFF : Stack guard page (unmapped)
//! 0x0000_7FFF_BFF0_1000 - 0x0000_7FFF_BFFF_FFFF : Bootstrap stack (64 KiB)
//! 0x0000_7FFF_C000_0000 - 0x0000_7FFF_DFFF_FFFF : IPC buffer region (reserved)
//! 0x0000_7FFF_E000_0000 - 0x0000_7FFF_E000_0FFF : UserBootInfo page (read-only)
//! 0x0000_7FFF_E000_1000 - 0x0000_7FFF_FFFF_FFFF : Reserved
//! ```

/// Null guard region size (64 KiB).
/// Any access below this address will fault.
pub const NULL_GUARD_SIZE: u64 = 0x0001_0000;

/// Minimum user virtual address (above null guard).
/// This is where ELF binaries are loaded.
pub const USER_BASE: u64 = 0x0000_0000_0001_0000;

/// Default ELF load address (matches linker script).
pub const ELF_LOAD_BASE: u64 = USER_BASE;

/// Heap region start.
pub const HEAP_BASE: u64 = 0x0000_0001_0000_0000;

/// Maximum heap region size (127 TiB theoretical).
pub const HEAP_MAX_SIZE: u64 = 0x0000_7FFE_0000_0000;

/// Stack guard page address (single unmapped page to detect overflow).
pub const STACK_GUARD_ADDR: u64 = 0x0000_7FFF_BFF0_0000;

/// Stack guard page size (4 KiB).
pub const STACK_GUARD_SIZE: u64 = 0x1000;

/// Bootstrap stack base address (bottom of stack region).
pub const STACK_BASE: u64 = STACK_GUARD_ADDR + STACK_GUARD_SIZE;

/// Bootstrap stack size (64 KiB).
/// This is a temporary stack provided by the kernel; init should replace it.
pub const BOOTSTRAP_STACK_SIZE: u64 = 64 * 1024;

/// Stack top address (initial SP value, stack grows down).
pub const STACK_TOP: u64 = STACK_BASE + BOOTSTRAP_STACK_SIZE;

/// IPC buffer region base.
pub const IPC_BUFFER_BASE: u64 = 0x0000_7FFF_C000_0000;

/// IPC buffer region size (8 GiB reserved).
pub const IPC_BUFFER_SIZE: u64 = 0x0000_0000_2000_0000;

/// UserBootInfo page address (read-only mapping).
/// This is where the kernel maps the boot information structure.
pub const USER_BOOT_INFO_ADDR: u64 = 0x0000_7FFF_E000_0000;

/// Maximum user virtual address (just below kernel space).
pub const USER_MAX: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Maximum stack size per thread (16 MiB).
/// Used when init allocates its own stack.
pub const MAX_STACK_SIZE: u64 = 16 * 1024 * 1024;

/// Check if an address is in the user address space.
#[inline]
pub const fn is_user_addr(addr: u64) -> bool {
    addr >= NULL_GUARD_SIZE && addr <= USER_MAX
}

/// Check if an address range is entirely in user space.
#[inline]
pub const fn is_user_range(start: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }
    let end = match start.checked_add(size.saturating_sub(1)) {
        Some(e) => e,
        None => return false,
    };
    is_user_addr(start) && is_user_addr(end)
}

/// Number of bootstrap stack pages.
pub const BOOTSTRAP_STACK_PAGES: usize = (BOOTSTRAP_STACK_SIZE as usize) / 0x1000;
