//! Small constant-time helpers.

use subtle::ConstantTimeEq;

/// Constant-time equality for secrets (MAC tags, key check values).
///
/// Returns `false` for differing lengths without leaking the comparison via
/// timing. Use this instead of `==` whenever comparing secret-dependent bytes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
