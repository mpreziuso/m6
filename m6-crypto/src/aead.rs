//! Authenticated encryption: AES-256-GCM (RustCrypto `aes-gcm`).
//!
//! For network/TLS-style payloads (design §12). Filesystem block encryption
//! uses AES-XTS, which is deferred — see [`crate::block`].

use crate::error::CryptoError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use alloc::vec::Vec;

/// Seal `plaintext` under a 256-bit `key` and 96-bit `nonce`, returning
/// `ciphertext || tag`.
///
/// The caller MUST never reuse a `(key, nonce)` pair — GCM nonce reuse is
/// catastrophic. `aad` is authenticated but not encrypted.
pub fn aes256gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Aead)
}

/// Open a `ciphertext || tag` produced by [`aes256gcm_seal`], returning the
/// plaintext. Fails closed on any tag mismatch.
pub fn aes256gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Aead)
}
