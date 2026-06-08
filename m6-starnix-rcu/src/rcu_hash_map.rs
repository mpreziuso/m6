// A concurrent hash map mirroring the upstream `starnix_rcu::RcuHashMap`.
//
// The upstream type uses a lock-free RCU hash map for reads plus a mutex for
// writes. This bring-up shim instead guards a `hashbrown::HashMap` with a
// `spin::RwLock`. To honour the upstream lifetime contract -- `get` returns a
// `&'a V` bound to an `RcuReadScope` -- each value is stored behind a stable heap
// allocation (`Box`) whose pointer is leaked when the entry is replaced or
// removed. This means values are never reclaimed; see the crate-level note.
//
// SIMPLIFICATION: leaks replaced/removed values, single-CPU bring-up only.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::hash::{BuildHasher, Hash};
use core::ptr::NonNull;
use fuchsia_rcu::RcuReadScope;
use hashbrown::HashMap;
use spin::RwLock;

/// Default hasher, matching upstream's use of a non-cryptographic fast hasher.
pub type DefaultHashBuilder = hashbrown::DefaultHashBuilder;

// -- Stable pointer to a leaked value

/// A pointer to a heap-allocated value that outlives the map entry.
///
/// The pointee is a `Box`-allocated `V` that is never moved while reachable; on
/// removal/replacement it is leaked rather than freed so that any outstanding
/// `&'a V` reference handed to a reader remains valid.
struct ValuePtr<V>(NonNull<V>);

// SAFETY: `V: Send + Sync` and the pointee is an immutable, stable heap
// allocation. Sharing the raw pointer across threads is therefore as safe as
// sharing `&V`/`Box<V>`.
unsafe impl<V: Send + Sync> Send for ValuePtr<V> {}
// SAFETY: See the `Send` impl above.
unsafe impl<V: Send + Sync> Sync for ValuePtr<V> {}

impl<V> ValuePtr<V> {
    fn new(value: V) -> Self {
        let ptr = Box::into_raw(Box::new(value));
        // SAFETY: `Box::into_raw` never returns null.
        Self(unsafe { NonNull::new_unchecked(ptr) })
    }

    /// Borrow the pointee for the lifetime of an `RcuReadScope`.
    ///
    /// # Safety
    ///
    /// The pointee must remain valid for `'a`. This holds because values are
    /// leaked rather than freed while references may exist.
    unsafe fn as_ref<'a>(&self, _scope: &'a RcuReadScope) -> &'a V {
        // SAFETY: The allocation is live and immutable; the caller upholds the
        // lifetime contract via the leak-on-remove policy.
        unsafe { self.0.as_ref() }
    }

    /// Borrow the pointee transiently (no scope).
    fn peek(&self) -> &V {
        // SAFETY: The allocation is live and immutable for as long as this
        // `ValuePtr` is reachable.
        unsafe { self.0.as_ref() }
    }
}

/// A concurrent hash map that uses a `RwLock` for synchronisation.
///
/// Mirrors the public API of `starnix_rcu::RcuHashMap`.
pub struct RcuHashMap<K, V, S = DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    map: RwLock<HashMap<K, ValuePtr<V>, S>>,
}

impl<K, V> Default for RcuHashMap<K, V, DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::with_hasher(DefaultHashBuilder::default())),
        }
    }
}

impl<K, V, S> RcuHashMap<K, V, S>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// Creates a new hash map with the given capacity and hasher.
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
        Self {
            map: RwLock::new(HashMap::with_capacity_and_hasher(capacity, hash_builder)),
        }
    }

    /// Creates a new hash map with the given hasher.
    pub fn with_hasher(hash_builder: S) -> Self {
        Self {
            map: RwLock::new(HashMap::with_hasher(hash_builder)),
        }
    }

    /// Returns a reference to the value associated with the given key.
    ///
    /// The returned reference is bound to the lifetime of the `RcuReadScope`.
    pub fn get<'a, Q>(&self, scope: &'a RcuReadScope, key: &Q) -> Option<&'a V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let guard = self.map.read();
        // SAFETY: The pointee is leaked on removal, so it stays valid for `'a`.
        guard.get(key).map(|p| unsafe { p.as_ref(scope) })
    }

    /// Locks the map for exclusive access, returning a guard that allows
    /// mutation.
    pub fn lock(&self) -> RcuHashMapGuard<'_, K, V, S> {
        RcuHashMapGuard {
            guard: self.map.write(),
        }
    }

    /// Inserts a key-value pair, returning the old value if the key was present.
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.lock().insert(key, value)
    }

    /// Removes a key, returning the value if the key was present.
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.lock().remove(key)
    }

    /// Returns an iterator over the map's entries.
    pub fn iter<'a>(&'a self, scope: &'a RcuReadScope) -> impl Iterator<Item = (&'a K, &'a V)> {
        // We snapshot the (key-ref, value-ptr) pairs while holding the read
        // lock, then hand out references bound to the scope. The pointees are
        // leak-stable, and keys live as long as `self`.
        let guard = self.map.read();
        let entries: Vec<(*const K, &'a V)> = guard
            .iter()
            // SAFETY: keys are owned by `self` (lifetime `'a`); pointees are
            // leak-stable for `'a`.
            .map(|(k, p)| (k as *const K, unsafe { p.as_ref(scope) }))
            .collect();
        drop(guard);
        entries.into_iter().map(|(k, v)| {
            // SAFETY: `k` points into the map owned by `self`, valid for `'a`.
            (unsafe { &*k }, v)
        })
    }

    /// Returns an iterator over the map's keys.
    pub fn keys<'a>(&'a self, scope: &'a RcuReadScope) -> impl Iterator<Item = &'a K> {
        self.iter(scope).map(|(k, _)| k)
    }
}

impl<K, V, S> core::fmt::Debug for RcuHashMap<K, V, S>
where
    K: Eq + Hash + core::fmt::Debug + Clone + Send + Sync + 'static,
    V: core::fmt::Debug + Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let guard = self.map.read();
        let mut dbg = f.debug_map();
        for (k, p) in guard.iter() {
            dbg.entry(k, p.peek());
        }
        dbg.finish()
    }
}

/// A guard that provides exclusive access to the `RcuHashMap`.
pub struct RcuHashMapGuard<'a, K, V, S = DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    guard: spin::RwLockWriteGuard<'a, HashMap<K, ValuePtr<V>, S>>,
}

impl<'a, K, V, S> RcuHashMapGuard<'a, K, V, S>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// Returns a clone of the value associated with the given key.
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.guard.get(key).map(|p| p.peek().clone())
    }

    /// Inserts a key-value pair, returning the old value if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let old = self.guard.insert(key, ValuePtr::new(value));
        old.map(|p| {
            // We clone the old value to return it, leaking the original so any
            // outstanding reader reference remains valid.
            p.peek().clone()
        })
    }

    /// Removes a key, returning the value if present.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.guard.remove(key).map(|p| p.peek().clone())
    }

    /// Removes all values from the map and returns them.
    pub fn drain(&mut self) -> impl Iterator<Item = (K, V)> {
        // Collect first since we cannot iterate and mutate concurrently.
        let drained: Vec<(K, V)> = self
            .guard
            .drain()
            .map(|(k, p)| (k, p.peek().clone()))
            .collect();
        drained.into_iter()
    }

    /// Returns true if the map contains a value for the specified key.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.guard.contains_key(key)
    }

    /// Gets the given key's entry for in-place manipulation.
    pub fn entry<'b>(&'b mut self, key: K) -> Entry<'b, 'a, K, V, S> {
        if self.guard.contains_key(&key) {
            Entry::Occupied(OccupiedEntry { guard: self, key })
        } else {
            Entry::Vacant(VacantEntry { guard: self, key })
        }
    }
}

/// A view into a single entry in the map, which may either be vacant or
/// occupied.
pub enum Entry<'b, 'a, K, V, S = DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// An occupied entry.
    Occupied(OccupiedEntry<'b, 'a, K, V, S>),
    /// A vacant entry.
    Vacant(VacantEntry<'b, 'a, K, V, S>),
}

impl<'b, 'a, K, V, S> Entry<'b, 'a, K, V, S>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// Ensures a value is in the entry, inserting the result of `default` if
    /// empty, and returns an occupied entry.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> OccupiedEntry<'b, 'a, K, V, S> {
        match self {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => entry.insert_entry(default()),
        }
    }
}

/// A view into an occupied entry in a `RcuHashMap`.
pub struct OccupiedEntry<'b, 'a, K, V, S = DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    guard: &'b mut RcuHashMapGuard<'a, K, V, S>,
    key: K,
}

impl<K, V, S> OccupiedEntry<'_, '_, K, V, S>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// Gets a clone of the value in the entry.
    pub fn get(&self) -> V {
        self.guard.get(&self.key).unwrap()
    }

    /// Sets the value of the entry, returning the old value.
    pub fn insert(&mut self, value: V) -> V {
        self.guard.insert(self.key.clone(), value).unwrap()
    }

    /// Removes the entry from the map, returning the value.
    pub fn remove(self) -> V {
        self.guard.remove(&self.key).unwrap()
    }
}

/// A view into a vacant entry in a `RcuHashMap`.
pub struct VacantEntry<'b, 'a, K, V, S = DefaultHashBuilder>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    guard: &'b mut RcuHashMapGuard<'a, K, V, S>,
    key: K,
}

impl<'b, 'a, K, V, S> VacantEntry<'b, 'a, K, V, S>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Send + Sync + 'static,
{
    /// Sets the value of the entry with the `VacantEntry`'s key.
    pub fn insert(self, value: V) {
        self.guard.insert(self.key, value);
    }

    /// Sets the value of the entry, and returns an occupied entry.
    pub fn insert_entry(self, value: V) -> OccupiedEntry<'b, 'a, K, V, S> {
        self.guard.insert(self.key.clone(), value);
        OccupiedEntry {
            guard: self.guard,
            key: self.key,
        }
    }
}
