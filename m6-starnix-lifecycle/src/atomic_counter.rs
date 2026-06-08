
//! Helper class to implement a counter that can be shared across threads.

/// Macro to define an atomic counter for a given base type. This is necessary because rust atomic
/// types are not parametrized on their base type.
macro_rules! atomic_counter_definition {
    ($ty:ty) => {
        paste::paste! {
        #[derive(Debug, Default)]
        pub struct [< Atomic $ty:camel Counter >](core::sync::atomic::[< Atomic $ty:camel >]);

        #[allow(dead_code)]
        impl [< Atomic $ty:camel Counter >] {
            pub const fn new(value: $ty) -> Self {
                Self(core::sync::atomic::[< Atomic $ty:camel >]::new(value))
            }

            pub fn next(&self) -> $ty {
                self.add(1)
            }

            pub fn add(&self, amount: $ty) -> $ty {
                self.0.fetch_add(amount, core::sync::atomic::Ordering::Relaxed)
            }

            pub fn get(&self) -> $ty {
                self.0.load(core::sync::atomic::Ordering::Relaxed)
            }
            pub fn reset(&mut self, value: $ty) {
                *self.0.get_mut() = value;
            }
        }

        impl From<$ty> for [< Atomic $ty:camel Counter >] {
            fn from(value: $ty) -> Self {
                Self::new(value)
            }
        }
        }
    };
}

atomic_counter_definition!(u64);
atomic_counter_definition!(u32);
atomic_counter_definition!(usize);

