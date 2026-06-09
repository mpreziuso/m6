//! Hash functions: SHA-2 family (RustCrypto `sha2`) and BLAKE3.

pub use sha2::{Digest, Sha256, Sha384, Sha512};

/// Re-export the streaming BLAKE3 hasher for incremental hashing.
pub use ::blake3::Hasher as Blake3Hasher;

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// One-shot SHA-512.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// One-shot BLAKE3 (content addressing — design §12).
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *::blake3::hash(data).as_bytes()
}
