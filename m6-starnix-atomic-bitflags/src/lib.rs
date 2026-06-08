// Forked from Fuchsia's Starnix `atomic_bitflags` for M6 (no_std).
// Original: Copyright 2026 The Fuchsia Authors. BSD license.
//
// The only change from upstream is `std::sync::atomic` -> `core::sync::atomic`
// so the generated atomic wrapper compiles under `#![no_std]`.

#![no_std]

pub use {bitflags as __bitflags, paste};

#[macro_export]
macro_rules! atomic_bitflags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $BitFlags:ident: $T:ty {
            $($t:tt)*
        }
    ) => {
        $crate::paste::paste! {
            $crate::__bitflags::bitflags! {
                $(#[$outer])*
                $vis struct $BitFlags: $T {
                    $($t)*
                }
            }

            #[allow(dead_code)]
            #[derive(Debug, Default)]
            $vis struct [<Atomic $BitFlags>] {
                inner: core::sync::atomic::[<Atomic $T:camel>],
            }

            #[allow(dead_code)]
            impl [<Atomic $BitFlags>] {
                pub fn new(initial: $BitFlags) -> Self {
                    Self {
                        inner: core::sync::atomic::[<Atomic $T:camel>]::new(initial.bits()),
                    }
                }

                pub fn load(&self, order: core::sync::atomic::Ordering) -> $BitFlags {
                    $BitFlags::from_bits_truncate(self.inner.load(order))
                }

                pub fn store(&self, val: $BitFlags, order: core::sync::atomic::Ordering) {
                    self.inner.store(val.bits(), order);
                }

                pub fn fetch_or(&self, val: $BitFlags, order: core::sync::atomic::Ordering) -> $BitFlags {
                    $BitFlags::from_bits_truncate(self.inner.fetch_or(val.bits(), order))
                }

                pub fn fetch_and(&self, val: $BitFlags, order: core::sync::atomic::Ordering) -> $BitFlags {
                    $BitFlags::from_bits_truncate(self.inner.fetch_and(val.bits(), order))
                }

                pub fn swap(&self, val: $BitFlags, order: core::sync::atomic::Ordering) -> $BitFlags {
                    $BitFlags::from_bits_truncate(self.inner.swap(val.bits(), order))
                }

                pub fn compare_exchange(
                    &self,
                    current: $BitFlags,
                    new: $BitFlags,
                    success: core::sync::atomic::Ordering,
                    failure: core::sync::atomic::Ordering,
                ) -> Result<$BitFlags, $BitFlags> {
                    self.inner.compare_exchange(current.bits(), new.bits(), success, failure)
                        .map($BitFlags::from_bits_truncate)
                        .map_err($BitFlags::from_bits_truncate)
                }

                pub fn update(
                    &self,
                    value: $BitFlags,
                    mask: $BitFlags,
                    set_order: core::sync::atomic::Ordering,
                    fetch_order: core::sync::atomic::Ordering,
                ) -> $BitFlags {
                    self.inner.fetch_update(set_order, fetch_order, |old| {
                        Some((old & !mask.bits()) | (value.bits() & mask.bits()))
                    }).map($BitFlags::from_bits_truncate).unwrap()
                }
            }
        }
    };
}
