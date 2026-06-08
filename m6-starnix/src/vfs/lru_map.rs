// M6 bring-up shim for the `linked_hash_map` crate (not available no_std/offline).
//
// `FileSystem` uses an insertion-ordered, LRU-refreshable map for its DirEntry
// cache. This provides exactly the surface that consumer needs
// (`new`/`insert`/`remove`/`get_refresh`/`len`/`pop_front`), backed by a
// `VecDeque` for ordering plus a `HashMap` for lookup. Refresh/remove are O(n)
// in the ordering deque rather than the O(1) of a real intrusive linked list;
// adequate for bring-up, revisit if the dirent cache becomes hot.

#[allow(unused_imports)]
use m6_starnix_std::prelude::*;
use core::hash::Hash;
use m6_starnix_std::collections::{HashMap, VecDeque};

/// An insertion-ordered map with LRU refresh, mirroring the subset of
/// `linked_hash_map::LinkedHashMap` that the VFS dirent cache uses.
pub struct LinkedHashMap<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Hash + Eq + Clone, V> LinkedHashMap<K, V> {
    /// Creates an empty map.
    pub fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new() }
    }

    /// Inserts a key/value pair at the back (most-recent) position. If the key
    /// already existed it is moved to the back and the old value returned.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let prev = self.map.insert(key.clone(), value);
        if prev.is_some() {
            self.order.retain(|k| k != &key);
        }
        self.order.push_back(key);
        prev
    }

    /// Removes a key, returning its value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.map.remove(key);
        if removed.is_some() {
            self.order.retain(|k| k != key);
        }
        removed
    }

    /// Touches a key, moving it to the back (most-recent) position, and returns
    /// a reference to its value if present.
    pub fn get_refresh(&mut self, key: &K) -> Option<&mut V> {
        if self.map.contains_key(key) {
            self.order.retain(|k| k != key);
            self.order.push_back(key.clone());
            self.map.get_mut(key)
        } else {
            None
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Removes and returns the front (least-recent) entry.
    pub fn pop_front(&mut self) -> Option<(K, V)> {
        let key = self.order.pop_front()?;
        let value = self.map.remove(&key)?;
        Some((key, value))
    }
}

impl<K: Hash + Eq + Clone, V> Default for LinkedHashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
