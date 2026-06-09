//! Key derivation: HKDF-SHA256 and Argon2id (RustCrypto).

use crate::error::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;

pub use argon2::Params as Argon2Params;

/// HKDF-SHA256 extract-and-expand into `out`.
///
/// `salt` may be empty; `info` binds the output to a context (e.g. `b"block-enc"`).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| CryptoError::InvalidLength)
}

/// Argon2id password hashing into `out` (raw key bytes, no PHC string encoding).
///
/// `out` is typically 32 bytes (a user master key). `params` controls the
/// memory/time cost; `None` uses the `argon2` crate's recommended defaults.
/// Per design §10/§12 the cost should target ~1 second on the RK3588.
pub fn argon2id_derive(
    passphrase: &[u8],
    salt: &[u8],
    params: Option<Argon2Params>,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    use argon2::{Algorithm, Argon2, Version};
    let params = params.unwrap_or_default();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    a2.hash_password_into(passphrase, salt, out)
        .map_err(|_| CryptoError::Kdf)
}
