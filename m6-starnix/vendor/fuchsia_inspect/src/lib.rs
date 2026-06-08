//! Minimal no-op `fuchsia_inspect` shim for the M6 Starnix fork.
//!
//! Upstream Starnix records rich diagnostics into a Fuchsia Inspect tree. M6 has
//! no Inspect runtime, so this crate provides the same API surface as inert
//! no-ops: nodes and properties swallow their values. This keeps the forked
//! diagnostics code compiling and behaviourally harmless until an M6-native
//! diagnostics sink exists.

#![no_std]

extern crate alloc;

use alloc::string::String;

/// An Inspect node. All record/create operations are no-ops.
#[derive(Debug, Default, Clone)]
pub struct Node;

impl Node {
    /// Creates a child node. Returns a fresh inert node.
    pub fn create_child(&self, _name: impl Into<String>) -> Node {
        Node
    }

    /// Records a child node, invoking `f` with a fresh inert node.
    pub fn record_child<F: FnOnce(&Node)>(&self, _name: impl Into<String>, f: F) {
        f(&Node);
    }

    /// Records a lazily-computed child. The producer is dropped unused.
    pub fn record_lazy_child<F>(&self, _name: impl Into<String>, _f: F) {}

    /// Records an already-created property/node. No-op (it is simply dropped).
    pub fn record<T>(&self, _value: T) {}

    pub fn record_uint(&self, _name: impl Into<String>, _value: u64) {}
    pub fn record_int(&self, _name: impl Into<String>, _value: i64) {}
    pub fn record_double(&self, _name: impl Into<String>, _value: f64) {}
    pub fn record_bool(&self, _name: impl Into<String>, _value: bool) {}
    pub fn record_string(&self, _name: impl Into<String>, _value: impl Into<String>) {}

    /// Creates a uint linear histogram property. Returns an inert property.
    pub fn create_uint_linear_histogram(
        &self,
        _name: impl Into<String>,
        _params: LinearHistogramParams,
    ) -> UintLinearHistogramProperty {
        UintLinearHistogramProperty
    }

    /// Creates a string array property. Returns an inert property.
    pub fn create_string_array(
        &self,
        _name: impl Into<String>,
        _size: usize,
    ) -> StringArrayProperty {
        StringArrayProperty
    }
}

/// Parameters for a linear histogram.
#[derive(Debug, Default, Copy, Clone)]
pub struct LinearHistogramParams {
    pub floor: i64,
    pub step_size: u64,
    pub buckets: usize,
}

/// An inert uint linear histogram property.
#[derive(Debug, Default)]
pub struct UintLinearHistogramProperty;

impl UintLinearHistogramProperty {
    pub fn insert(&self, _value: u64) {}
}

/// An inert string array property.
#[derive(Debug, Default)]
pub struct StringArrayProperty;

impl StringArrayProperty {
    pub fn set(&self, _index: usize, _value: impl Into<String>) {}
}

/// The Inspect tree root holder.
#[derive(Debug, Default)]
pub struct Inspector {
    root: Node,
}

impl Inspector {
    /// Returns the root node of the tree.
    pub fn root(&self) -> &Node {
        &self.root
    }
}
