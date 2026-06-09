#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! M6 userspace cryptography facade.
//!
//! Thin, audited wrappers over RustCrypto (and the cryptographer-authored
//! `blake3` / dalek) implementations. M6 keeps cryptography in userspace as
//! *policy*; the kernel only supplies entropy via the `GetRandom`
//! self-invocation, which this crate exposes through [`rng::M6Rng`].
//!
//! Consumers (M6FS, multi-user auth, update verification) depend on this crate
//! rather than the raw primitives, so the choice of implementation stays in one
//! place.
//!
//! ## Deferred
//! AES-XTS-256 (IEEE 1619, for M6FS block encryption) is intentionally not yet
//! implemented — see [`block`]. AES-GCM is provided for network/TLS payloads.

extern crate alloc;

pub mod aead;
pub mod block;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kx;
pub mod mac;
pub mod rng;
pub mod sign;
pub mod util;

pub use error::CryptoError;
pub use rng::M6Rng;

// Re-exported so consumers can wrap key material without taking their own
// `zeroize` dependency.
pub use zeroize;
