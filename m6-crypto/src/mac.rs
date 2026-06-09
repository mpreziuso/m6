//! Message authentication: HMAC-SHA256 (RustCrypto `hmac`).

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 instance type.
pub type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 tag over `data` with `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time verification of an HMAC-SHA256 tag.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}
