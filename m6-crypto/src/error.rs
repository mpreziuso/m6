//! Shared error type for the crypto facade.

/// Errors surfaced by [`crate`] primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Output or key buffer length is unacceptable to the primitive.
    InvalidLength,
    /// Key derivation failed.
    Kdf,
    /// AEAD seal/open failed (bad tag, or wrong key/nonce).
    Aead,
    /// Signature verification failed.
    Signature,
    /// The underlying entropy source failed.
    Entropy,
    /// The primitive is not yet implemented (e.g. AES-XTS).
    Unimplemented,
}
