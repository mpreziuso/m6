//! X25519 key exchange (future: secure messaging — design §12).

use crate::rng::M6Rng;

pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

/// Generate an ephemeral X25519 secret and its public key from kernel entropy.
///
/// The secret is single-use: consume it with [`EphemeralSecret::diffie_hellman`]
/// to derive a [`SharedSecret`], which should then be run through a KDF
/// (see [`crate::kdf::hkdf_sha256`]) before use as a key.
pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(M6Rng::new());
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Generate a long-lived X25519 static secret and its public key.
pub fn generate_static() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(M6Rng::new());
    let public = PublicKey::from(&secret);
    (secret, public)
}
