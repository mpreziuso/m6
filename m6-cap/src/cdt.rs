//! Capability Derivation Tree (CDT)
//!
//! The CDT tracks parent-child relationships between capabilities for
//! revocation. When a capability is revoked, all its descendants are
//! also revoked automatically.
//!
//! # Structure
//!
//! The CDT uses a parent-pointer tree with sibling lists:
//!
//! - Each node points to its parent
//! - Each parent points to its first child
//! - Children are linked as a doubly-linked sibling list
//!
//! This structure allows:
//! - O(1) insertion (add to front of child list)
//! - O(1) removal (unlink from sibling list)
//! - O(n) revocation (traverse all descendants)
//!
//! # Derivation Rules
//!
//! - **Retype**: Creates a child of the untyped memory capability
//! - **Copy**: Creates a sibling (same parent as source)
//! - **Mint**: Creates a child of the source capability
//! - **Move**: Transfers CDT membership (no new node)
//! - **Delete**: Removes the node, reparenting children to grandparent
//! - **Revoke**: Removes all descendants (recursive)

use core::fmt;

use crate::slot::ObjectRef;

/// CDT node index (into CDT node pool).
///
/// Similar to [`ObjectRef`], this is an index rather than a pointer
/// for safety and revocation efficiency.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CdtNodeId(u32);

impl CdtNodeId {
    /// Null node (no CDT entry).
    pub const NULL: Self = Self(0);

    /// Create from raw index.
    #[inline]
    #[must_use]
    pub const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Get the raw index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }

    /// Check if this is a null node.
    #[inline]
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if this is a valid (non-null) node.
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for CdtNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "CdtNodeId::NULL")
        } else {
            write!(f, "CdtNodeId({})", self.0)
        }
    }
}

impl fmt::Display for CdtNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "null")
        } else {
            write!(f, "cdt#{}", self.0)
        }
    }
}

/// CDT node - represents one capability in the derivation tree.
///
/// # Structure
///
/// Uses a parent pointer + sibling list structure:
/// - `parent`: Points to the capability this was derived from
/// - `first_child`: First child in the derivation chain
/// - `next_sibling`: Next sibling (same parent)
/// - `prev_sibling`: Previous sibling (for O(1) removal)
///
/// # Back-reference
///
/// Each CDT node has a back-reference to the capability slot it
/// represents. This allows revocation to clear the slot.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct CdtNode {
    /// Object this capability refers to.
    pub object_ref: ObjectRef,

    /// Parent capability in derivation tree.
    pub parent: CdtNodeId,

    /// First child capability.
    pub first_child: CdtNodeId,

    /// Next sibling (capabilities derived from same parent).
    pub next_sibling: CdtNodeId,

    /// Previous sibling (for O(1) removal).
    pub prev_sibling: CdtNodeId,

    /// Back-reference to the CNode containing this capability.
    pub slot_cnode: ObjectRef,

    /// Index within the CNode.
    pub slot_index: u32,
}

impl CdtNode {
    /// Create a new CDT node.
    #[inline]
    #[must_use]
    pub const fn new(object_ref: ObjectRef, slot_cnode: ObjectRef, slot_index: u32) -> Self {
        Self {
            object_ref,
            parent: CdtNodeId::NULL,
            first_child: CdtNodeId::NULL,
            next_sibling: CdtNodeId::NULL,
            prev_sibling: CdtNodeId::NULL,
            slot_cnode,
            slot_index,
        }
    }

    /// Check if this node has children.
    #[inline]
    #[must_use]
    pub const fn has_children(&self) -> bool {
        self.first_child.is_valid()
    }

    /// Check if this node has siblings.
    #[inline]
    #[must_use]
    pub const fn has_siblings(&self) -> bool {
        self.next_sibling.is_valid() || self.prev_sibling.is_valid()
    }

    /// Check if this is a root node (no parent).
    #[inline]
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.parent.is_null()
    }

    /// Check if this is a leaf node (no children).
    #[inline]
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.first_child.is_null()
    }
}

impl Default for CdtNode {
    fn default() -> Self {
        Self {
            object_ref: ObjectRef::NULL,
            parent: CdtNodeId::NULL,
            first_child: CdtNodeId::NULL,
            next_sibling: CdtNodeId::NULL,
            prev_sibling: CdtNodeId::NULL,
            slot_cnode: ObjectRef::NULL,
            slot_index: 0,
        }
    }
}

/// CDT operations trait.
///
/// Implemented by the kernel's CDT storage. This trait defines the
/// interface for managing the capability derivation tree.
pub trait CdtOps {
    /// Allocate a new CDT node.
    ///
    /// # Returns
    ///
    /// The ID of the new node, or `None` if out of memory.
    fn alloc_node(&mut self) -> Option<CdtNodeId>;

    /// Free a CDT node.
    ///
    /// The node should be removed from the tree before freeing.
    fn free_node(&mut self, id: CdtNodeId);

    /// Get a node by ID.
    fn get_node(&self, id: CdtNodeId) -> Option<&CdtNode>;

    /// Get a mutable node by ID.
    fn get_node_mut(&mut self, id: CdtNodeId) -> Option<&mut CdtNode>;

    /// Insert a child under a parent.
    ///
    /// The child is added to the front of the parent's child list.
    fn insert_child(&mut self, parent: CdtNodeId, child: CdtNodeId) {
        if parent.is_null() || child.is_null() {
            return;
        }

        // Get the current first child of the parent
        let old_first = if let Some(parent_node) = self.get_node(parent) {
            parent_node.first_child
        } else {
            return;
        };

        // Update child's links
        if let Some(child_node) = self.get_node_mut(child) {
            child_node.parent = parent;
            child_node.next_sibling = old_first;
            child_node.prev_sibling = CdtNodeId::NULL;
        }

        // Update old first child's prev_sibling
        if old_first.is_valid()
            && let Some(old_first_node) = self.get_node_mut(old_first)
        {
            old_first_node.prev_sibling = child;
        }

        // Update parent's first_child
        if let Some(parent_node) = self.get_node_mut(parent) {
            parent_node.first_child = child;
        }
    }

    /// Insert a sibling after an existing node.
    ///
    /// The new sibling is added immediately after `after` in the sibling list.
    fn insert_sibling(&mut self, after: CdtNodeId, sibling: CdtNodeId) {
        if after.is_null() || sibling.is_null() {
            return;
        }

        // Get the parent and next sibling of `after`
        let (parent, next) = if let Some(after_node) = self.get_node(after) {
            (after_node.parent, after_node.next_sibling)
        } else {
            return;
        };

        // Update sibling's links
        if let Some(sibling_node) = self.get_node_mut(sibling) {
            sibling_node.parent = parent;
            sibling_node.prev_sibling = after;
            sibling_node.next_sibling = next;
        }

        // Update `after`'s next_sibling
        if let Some(after_node) = self.get_node_mut(after) {
            after_node.next_sibling = sibling;
        }

        // Update old next's prev_sibling
        if next.is_valid()
            && let Some(next_node) = self.get_node_mut(next)
        {
            next_node.prev_sibling = sibling;
        }
    }

    /// Remove a node from its parent's child list.
    ///
    /// This does not free the node or handle its children.
    fn remove_from_parent(&mut self, node: CdtNodeId) {
        if node.is_null() {
            return;
        }

        // Get the node's links
        let (parent, prev, next) = if let Some(n) = self.get_node(node) {
            (n.parent, n.prev_sibling, n.next_sibling)
        } else {
            return;
        };

        // Update previous sibling's next pointer
        if prev.is_valid() {
            if let Some(prev_node) = self.get_node_mut(prev) {
                prev_node.next_sibling = next;
            }
        } else if parent.is_valid() {
            // This was the first child, update parent's first_child
            if let Some(parent_node) = self.get_node_mut(parent) {
                parent_node.first_child = next;
            }
        }

        // Update next sibling's prev pointer
        if next.is_valid()
            && let Some(next_node) = self.get_node_mut(next)
        {
            next_node.prev_sibling = prev;
        }

        // Clear the node's links
        if let Some(n) = self.get_node_mut(node) {
            n.parent = CdtNodeId::NULL;
            n.prev_sibling = CdtNodeId::NULL;
            n.next_sibling = CdtNodeId::NULL;
        }
    }

    /// Reparent children to a new parent.
    ///
    /// Used during delete to move children to the grandparent.
    fn reparent_children(&mut self, from: CdtNodeId, to: CdtNodeId) {
        if from.is_null() {
            return;
        }

        // Get the first child
        let mut child = if let Some(from_node) = self.get_node(from) {
            from_node.first_child
        } else {
            return;
        };

        // If no children, nothing to do
        if child.is_null() {
            return;
        }

        // If new parent is null, just clear parent pointers
        if to.is_null() {
            while child.is_valid() {
                let next = if let Some(child_node) = self.get_node(child) {
                    child_node.next_sibling
                } else {
                    break;
                };

                if let Some(child_node) = self.get_node_mut(child) {
                    child_node.parent = CdtNodeId::NULL;
                }

                child = next;
            }
            return;
        }

        // Move all children to the new parent's child list
        while child.is_valid() {
            let next = if let Some(child_node) = self.get_node(child) {
                child_node.next_sibling
            } else {
                break;
            };

            // Remove from current position
            self.remove_from_parent(child);
            // Add to new parent
            self.insert_child(to, child);

            child = next;
        }

        // Clear from's first_child
        if let Some(from_node) = self.get_node_mut(from) {
            from_node.first_child = CdtNodeId::NULL;
        }
    }

    /// Count descendants of a node (for statistics).
    fn count_descendants(&self, node: CdtNodeId) -> usize {
        if node.is_null() {
            return 0;
        }

        let first_child = if let Some(n) = self.get_node(node) {
            n.first_child
        } else {
            return 0;
        };

        let mut count = 0;
        let mut child = first_child;

        while child.is_valid() {
            count += 1;
            count += self.count_descendants(child);

            child = if let Some(c) = self.get_node(child) {
                c.next_sibling
            } else {
                break;
            };
        }

        count
    }
}

/// Callback for revocation operations.
///
/// Called for each capability that is revoked, allowing the kernel
/// to clean up the associated slot.
pub trait RevocationCallback {
    /// Called when a capability is being revoked.
    ///
    /// # Parameters
    ///
    /// - `node`: The CDT node being revoked
    fn on_revoke(&mut self, node: &CdtNode);
}

/// Revoke a node and all its descendants.
///
/// This is the core revocation algorithm. It traverses the subtree
/// rooted at `node` and revokes all capabilities in post-order
/// (children before parent).
///
/// # Parameters
///
/// - `cdt`: The CDT storage
/// - `node`: The root of the subtree to revoke
/// - `callback`: Called for each revoked capability
///
/// # Returns
///
/// The number of capabilities revoked.
pub fn revoke_subtree<C: CdtOps, R: RevocationCallback>(
    cdt: &mut C,
    node: CdtNodeId,
    callback: &mut R,
) -> usize {
    if node.is_null() {
        return 0;
    }

    let mut count = 0;

    // Get the first child
    let first_child = if let Some(n) = cdt.get_node(node) {
        n.first_child
    } else {
        return 0;
    };

    // Recursively revoke all children
    let mut child = first_child;
    while child.is_valid() {
        // Get next sibling before we potentially free this child
        let next = if let Some(c) = cdt.get_node(child) {
            c.next_sibling
        } else {
            break;
        };

        // Recursively revoke this child and its descendants
        count += revoke_subtree(cdt, child, callback);

        child = next;
    }

    // Revoke this node
    if let Some(n) = cdt.get_node(node) {
        callback.on_revoke(n);
    }
    count += 1;

    // Remove from parent and free
    cdt.remove_from_parent(node);
    cdt.free_node(node);

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdt_node_id() {
        assert!(CdtNodeId::NULL.is_null());
        assert!(!CdtNodeId::from_index(1).is_null());
    }

    #[test]
    fn test_cdt_node_creation() {
        let node = CdtNode::new(ObjectRef::from_index(1), ObjectRef::from_index(2), 5);
        assert!(node.is_root());
        assert!(node.is_leaf());
        assert!(!node.has_children());
        assert!(!node.has_siblings());
    }
}
