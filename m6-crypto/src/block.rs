//! Block-cipher disk encryption — AES-XTS-256 (IEEE 1619).
//!
//! Deferred. M6FS (design §4) requires length-preserving, tweakable block
//! encryption (AES-XTS-256) for data blocks. RustCrypto has no first-party XTS
//! crate; when this is implemented the chosen approach is either:
//!
//!   * the community `xts-mode` crate layered over RustCrypto `aes`, or
//!   * a thin in-house XTS (tweak + sector logic) over the audited `aes` block
//!     cipher.
//!
//! Until then this module is intentionally empty so the dependency surface
//! stays minimal. See the project roadmap (Tier 1).
