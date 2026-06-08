//! Collection types
//!
//! Re-exports alloc collections plus hashbrown for HashMap/HashSet.

pub use alloc::collections::*;

// HashMap/HashSet from hashbrown (no_std compatible)
pub use hashbrown::{HashMap, HashSet, hash_set};

/// Mirror of `std::collections::hash_map`, augmented with a `RandomState` shim.
pub mod hash_map {
    pub use hashbrown::hash_map::*;

    /// Default hashing-state, mirroring `std::collections::hash_map::RandomState`.
    ///
    /// `no_std` has no entropy source, so this is a fixed-seed (deterministic)
    /// `BuildHasher` using a self-contained FNV-1a hasher rather than a randomly
    /// seeded SipHash. The API matches std; HashDoS resistance is not provided
    /// until an entropy source is wired in. Self-contained (no reliance on
    /// hashbrown feature unification) so it builds standalone.
    #[derive(Clone, Default)]
    pub struct RandomState;

    impl RandomState {
        /// Constructs a new `RandomState`.
        pub fn new() -> Self {
            Self
        }
    }

    impl core::hash::BuildHasher for RandomState {
        type Hasher = FnvHasher;
        fn build_hasher(&self) -> FnvHasher {
            FnvHasher(0xcbf2_9ce4_8422_2325)
        }
    }

    /// A small FNV-1a hasher backing [`RandomState`].
    pub struct FnvHasher(u64);

    impl core::hash::Hasher for FnvHasher {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.0 ^= b as u64;
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
}
