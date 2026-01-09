//! Capability Derivation Tree (CDT) storage
//!
//! The CDT tracks parent-child relationships between capabilities for
//! revocation. This module implements the [`CdtOps`] trait from `m6-cap`.
//!
//! # Design
//!
//! - Pool of CDT nodes allocated on heap
//! - Free list for allocation
//! - Index 0 is reserved (NULL)

extern crate alloc;

use alloc::boxed::Box;
use m6_arch::IrqSpinMutex;
use m6_cap::{CdtNode, CdtNodeId, CdtOps};
use spin::Once;

/// Maximum number of CDT nodes.
pub const MAX_CDT_NODES: usize = 131072; // 128K nodes

/// CDT node pool.
pub struct CdtPool {
    /// Node storage array (boxed to avoid stack overflow).
    nodes: Box<[CdtNode]>,
    /// Head of free list (node index).
    free_head: u32,
    /// Number of allocated nodes.
    allocated: u32,
}

impl CdtPool {
    /// Create a new CDT pool.
    fn new() -> Self {
        // Allocate on heap to avoid stack overflow
        let mut nodes: Box<[CdtNode]> = (0..MAX_CDT_NODES)
            .map(|_| CdtNode::default())
            .collect();

        // Build free list: index 0 is NULL, so start at 1
        // Use next_sibling as free list link when not in use
        for i in 1..MAX_CDT_NODES - 1 {
            nodes[i].next_sibling = CdtNodeId::from_index((i + 1) as u32);
        }
        // Last entry points to 0 (end of list)
        nodes[MAX_CDT_NODES - 1].next_sibling = CdtNodeId::NULL;

        Self {
            nodes,
            free_head: 1, // Start at index 1 (0 is NULL)
            allocated: 0,
        }
    }

    /// Get the number of allocated nodes.
    #[inline]
    pub fn allocated(&self) -> u32 {
        self.allocated
    }

    /// Get the number of free nodes.
    #[inline]
    pub fn free_count(&self) -> u32 {
        (MAX_CDT_NODES as u32 - 1).saturating_sub(self.allocated)
    }
}

impl CdtOps for CdtPool {
    fn alloc_node(&mut self) -> Option<CdtNodeId> {
        if self.free_head == 0 {
            return None;
        }

        let index = self.free_head;
        let node = &mut self.nodes[index as usize];

        // Get next free from the link
        let next_free = node.next_sibling.index();
        self.free_head = next_free;

        // Initialise the node
        *node = CdtNode::default();

        self.allocated += 1;
        Some(CdtNodeId::from_index(index))
    }

    fn free_node(&mut self, id: CdtNodeId) {
        let index = id.index();
        if index == 0 || index as usize >= MAX_CDT_NODES {
            return;
        }

        let node = &mut self.nodes[index as usize];

        // Add to free list using next_sibling as link
        node.next_sibling = CdtNodeId::from_index(self.free_head);
        self.free_head = index;
        self.allocated = self.allocated.saturating_sub(1);
    }

    fn get_node(&self, id: CdtNodeId) -> Option<&CdtNode> {
        let index = id.index() as usize;
        if index == 0 || index >= MAX_CDT_NODES {
            return None;
        }
        Some(&self.nodes[index])
    }

    fn get_node_mut(&mut self, id: CdtNodeId) -> Option<&mut CdtNode> {
        let index = id.index() as usize;
        if index == 0 || index >= MAX_CDT_NODES {
            return None;
        }
        Some(&mut self.nodes[index])
    }
}

/// Global CDT pool.
///
/// Lazily initialised on first access. Protected by [`IrqSpinMutex`].
static CDT_POOL: Once<IrqSpinMutex<CdtPool>> = Once::new();

/// Get the global CDT pool, initialising if necessary.
fn get_pool() -> &'static IrqSpinMutex<CdtPool> {
    CDT_POOL.call_once(|| {
        log::debug!("CDT pool initialised with {} nodes", MAX_CDT_NODES - 1);
        IrqSpinMutex::new(CdtPool::new())
    })
}

/// Initialise the global CDT pool.
///
/// This is called during kernel initialisation. It's safe to call multiple
/// times (subsequent calls are no-ops).
pub fn init() {
    let _ = get_pool();
}

/// Access the CDT pool with a closure.
pub fn with_cdt<F, R>(f: F) -> R
where
    F: FnOnce(&mut CdtPool) -> R,
{
    f(&mut get_pool().lock())
}

/// Allocate a CDT node.
pub fn alloc_node() -> Option<CdtNodeId> {
    get_pool().lock().alloc_node()
}

/// Free a CDT node.
pub fn free_node(id: CdtNodeId) {
    get_pool().lock().free_node(id)
}

/// Get CDT statistics.
pub fn stats() -> (u32, u32) {
    let pool = get_pool().lock();
    (pool.allocated(), pool.free_count())
}
