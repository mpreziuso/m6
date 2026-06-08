// Forked from Fuchsia's Starnix for M6 (no_std).
// Original: Copyright 2025 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Trait to add helper methods on map-like entry types.
pub trait EntryExt<'a, K: 'a, V: 'a> {
    fn or_insert_with_fallible<E, F: FnOnce() -> Result<V, E>>(
        self,
        default: F,
    ) -> Result<&'a mut V, E>;
}

impl<'a, K: Ord + 'a, V: 'a> EntryExt<'a, K, V> for m6_starnix_std::collections::btree_map::Entry<'a, K, V> {
    fn or_insert_with_fallible<E, F: FnOnce() -> Result<V, E>>(
        self,
        default: F,
    ) -> Result<&'a mut V, E> {
        let r = match self {
            m6_starnix_std::collections::btree_map::Entry::Occupied(o) => o.into_mut(),
            m6_starnix_std::collections::btree_map::Entry::Vacant(v) => v.insert(default()?),
        };
        Ok(r)
    }
}

// M6 adaptation: the collections shim uses hashbrown, whose `Entry` carries an
// extra hasher generic `S` (and an allocator, defaulted to `Global`).
impl<'a, K: 'a + Eq + core::hash::Hash, V: 'a, S: core::hash::BuildHasher> EntryExt<'a, K, V>
    for m6_starnix_std::collections::hash_map::Entry<'a, K, V, S>
{
    fn or_insert_with_fallible<E, F: FnOnce() -> Result<V, E>>(
        self,
        default: F,
    ) -> Result<&'a mut V, E> {
        let r = match self {
            m6_starnix_std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            m6_starnix_std::collections::hash_map::Entry::Vacant(v) => v.insert(default()?),
        };
        Ok(r)
    }
}
