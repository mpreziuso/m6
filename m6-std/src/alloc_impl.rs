//! Global allocator setup
//!
//! Configures m6-alloc as the global allocator for the alloc crate.

use m6_alloc::M6GlobalAlloc;

/// The global allocator instance.
///
/// This is automatically used by Vec, Box, String, etc. once the runtime
/// has initialised the allocator.
#[global_allocator]
static ALLOCATOR: M6GlobalAlloc = M6GlobalAlloc;

/// Check if the allocator is ready for use.
#[inline]
pub fn is_ready() -> bool {
    m6_alloc::is_initialised()
}
