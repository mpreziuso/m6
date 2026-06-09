//! Ed25519 signatures (system updates, user identity — design §10/§11).

use crate::error::CryptoError;
use crate::rng::M6Rng;
use ed25519_dalek::{Signer, Verifier};

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Generate a fresh Ed25519 signing key from kernel entropy.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut M6Rng::new())
}

/// Sign `msg` with `key`.
pub fn sign(key: &SigningKey, msg: &[u8]) -> Signature {
    key.sign(msg)
}

/// Verify `sig` over `msg` against `vk`. Fails closed.
pub fn verify(vk: &VerifyingKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
    vk.verify(msg, sig).map_err(|_| CryptoError::Signature)
}
