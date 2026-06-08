// Minimal stub for Fuchsia's starnix_crypt (fscrypt key management).
//
// Upstream starnix_crypt is ~845 LOC of fscrypt (AES-GCM-SIV, HKDF, FIDL to
// fxfs/inline-encryption). M6 does not yet support fscrypt, and the forked
// Starnix core only references the `EncryptionKeyId` type and an opaque
// `CryptService` handle (returned as `Option<Arc<CryptService>>`, never called).
// This stub provides just that surface so the core compiles; real fscrypt is
// future work, gated behind a feature when added.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use starnix_uapi::error;
use starnix_uapi::errors::Errno;

/// fscrypt key identifier (`FSCRYPT_KEY_IDENTIFIER_SIZE` = 16 bytes).
pub type EncryptionKeyId = [u8; 16];

/// Opaque handle to a filesystem's crypt service.
///
/// Stub: holds no state. Methods are added as the encryption paths are ported.
#[derive(Debug, Default)]
pub struct CryptService {
    _private: (),
}

impl CryptService {
    pub fn new() -> Self {
        Self::default()
    }

    // -- fscrypt key management (stubbed)
    //
    // M6 does not yet implement fscrypt, so these mirror the upstream
    // `starnix_crypt::CryptService` signatures but report no keys present /
    // unsupported. Real implementations are future work.

    /// Adds a wrapping key for `uid`. Stub: fscrypt unsupported.
    pub fn add_wrapping_key(&self, _raw_key: &[u8], _uid: u32) -> Result<EncryptionKeyId, Errno> {
        error!(ENOTSUP)
    }

    /// Removes a wrapping key for `uid`. Stub: no keys exist.
    pub fn forget_wrapping_key(
        &self,
        _wrapping_key_id: EncryptionKeyId,
        _uid: u32,
    ) -> Result<(), Errno> {
        error!(ENOKEY)
    }

    /// Returns the user ids associated with `key`. Stub: no keys exist.
    pub fn get_users_for_key(&self, _key: EncryptionKeyId) -> Option<Vec<u32>> {
        None
    }

    /// Returns whether `key` is present. Stub: no keys exist.
    pub fn contains_key(&self, _key: EncryptionKeyId) -> bool {
        false
    }
}
