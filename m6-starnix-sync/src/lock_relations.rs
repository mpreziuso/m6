//! Lock ordering relationship traits.
//!
//! Port of Fuchsia's `lock_relations.rs`. These marker traits describe which
//! lock levels may be acquired after which others. The acyclic lock-ordering
//! graph is constructed with the `lock_ordering!` proc-macro (re-exported from
//! the `lock_ordering_macro` crate), which emits `LockAfter` impls for the full
//! transitive closure so `LockBefore` works transitively.

/// Marker trait indicating that `Self` can be locked after `A`.
///
/// If `B: LockAfter<A>`, then lock level `B` can be acquired while `A` is
/// held, but not the reverse.
pub trait LockAfter<A> {}

/// Marker trait indicating that `Self` is an ancestor of `X` in the lock
/// ordering graph.
///
/// A blanket implementation is provided: any `A` where `X: LockAfter<A>`
/// automatically satisfies `A: LockBefore<X>`.
pub trait LockBefore<X> {}

impl<B: LockAfter<A>, A> LockBefore<B> for A {}

/// Marker trait indicating that `Self` is `X` *or* an ancestor of `X`.
///
/// Used when a function must accept a `Locked` context at the exact level
/// or any ancestor — see `Locked::cast_locked`.
pub trait LockEqualOrBefore<X> {}

impl<B, A> LockEqualOrBefore<B> for A where A: LockBefore<B> {}

// -- Lock level declaration macro

/// Declare a lock level as a zero-sized enum and provide the reflexive
/// `LockEqualOrBefore` implementation.
///
/// M6: ported from upstream `lock_level!`; upstream asserted
/// `size_of::<Locked<$A>>() == 0` via `std::mem` — we use `core::mem` to stay
/// `no_std`.
#[macro_export]
macro_rules! lock_level {
    ($A:ident) => {
        pub enum $A {}
        impl $crate::LockEqualOrBefore<$A> for $A {}
        static_assertions::const_assert_eq!(core::mem::size_of::<$crate::Locked<$A>>(), 0);
    };
}
