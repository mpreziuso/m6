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
//! - Slot-to-CDT mapping for efficient lookup

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use m6_arch::IrqSpinMutex;
use m6_cap::{CdtNode, CdtNodeId, CdtOps, ObjectRef};
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
        let mut nodes: Box<[CdtNode]> = (0..MAX_CDT_NODES).map(|_| CdtNode::default()).collect();

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

// -- Slot-to-CDT mapping

/// Key for slot-to-CDT mapping: (cnode ObjectRef index, slot index).
type SlotKey = (u32, u32);

/// Slot-to-CDT node mapping.
///
/// Maps (cnode_ref, slot_index) to CdtNodeId for efficient lookup.
/// This allows finding the CDT node for a capability in O(log n) time.
struct SlotCdtMap {
    map: BTreeMap<SlotKey, CdtNodeId>,
}

impl SlotCdtMap {
    fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

/// Global slot-to-CDT mapping.
static SLOT_CDT_MAP: Once<IrqSpinMutex<SlotCdtMap>> = Once::new();

fn get_slot_map() -> &'static IrqSpinMutex<SlotCdtMap> {
    SLOT_CDT_MAP.call_once(|| IrqSpinMutex::new(SlotCdtMap::new()))
}

/// Look up the CDT node ID for a capability slot.
///
/// # Arguments
///
/// * `cnode` - The CNode containing the capability
/// * `index` - The slot index within the CNode
///
/// # Returns
///
/// The CDT node ID if the slot is tracked, or `None` if not.
pub fn lookup_cdt_node(cnode: ObjectRef, index: u32) -> Option<CdtNodeId> {
    let key = (cnode.index(), index);
    get_slot_map().lock().map.get(&key).copied()
}

/// Register a CDT node for a capability slot.
///
/// This should be called when a new capability is created that needs
/// to be tracked in the CDT (copy, mint operations).
///
/// # Arguments
///
/// * `cnode` - The CNode containing the capability
/// * `index` - The slot index within the CNode
/// * `node` - The CDT node ID to associate with the slot
pub fn register_cdt_node(cnode: ObjectRef, index: u32, node: CdtNodeId) {
    let key = (cnode.index(), index);
    get_slot_map().lock().map.insert(key, node);
}

/// Unregister a CDT node for a capability slot.
///
/// This should be called when a capability is deleted or moved.
///
/// # Arguments
///
/// * `cnode` - The CNode containing the capability
/// * `index` - The slot index within the CNode
///
/// # Returns
///
/// The CDT node ID that was unregistered, or `None` if not tracked.
pub fn unregister_cdt_node(cnode: ObjectRef, index: u32) -> Option<CdtNodeId> {
    let key = (cnode.index(), index);
    get_slot_map().lock().map.remove(&key)
}

/// Update the slot mapping when a capability is moved.
///
/// This atomically removes the old mapping and creates a new one.
///
/// # Arguments
///
/// * `old_cnode` - The source CNode
/// * `old_index` - The source slot index
/// * `new_cnode` - The destination CNode
/// * `new_index` - The destination slot index
pub fn move_cdt_mapping(
    old_cnode: ObjectRef,
    old_index: u32,
    new_cnode: ObjectRef,
    new_index: u32,
) {
    let mut map = get_slot_map().lock();
    let old_key = (old_cnode.index(), old_index);
    if let Some(node) = map.map.remove(&old_key) {
        let new_key = (new_cnode.index(), new_index);
        map.map.insert(new_key, node);
    }
}

/// Rotate CDT mappings for three slots.
///
/// Used by the CapRotate syscall to atomically update mappings for
/// a three-way capability rotation.
pub fn rotate_cdt_mappings(cnode: ObjectRef, slot1: u32, slot2: u32, slot3: u32) {
    let mut map = get_slot_map().lock();
    let cnode_idx = cnode.index();

    let key1 = (cnode_idx, slot1);
    let key2 = (cnode_idx, slot2);
    let key3 = (cnode_idx, slot3);

    // Get all three values
    let node1 = map.map.remove(&key1);
    let node2 = map.map.remove(&key2);
    let node3 = map.map.remove(&key3);

    // Rotate: 1->2, 2->3, 3->1
    if let Some(n) = node1 {
        map.map.insert(key2, n);
    }
    if let Some(n) = node2 {
        map.map.insert(key3, n);
    }
    if let Some(n) = node3 {
        map.map.insert(key1, n);
    }
}

/// Get the number of entries in the slot-to-CDT map.
pub fn slot_map_size() -> usize {
    get_slot_map().lock().map.len()
}
