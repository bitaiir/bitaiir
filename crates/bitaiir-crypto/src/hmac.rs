//! HMAC-SHA-256.
//!
//! BitAiir uses HMAC-SHA-256 only inside the RFC 6979 deterministic ECDSA
//! nonce generator (see [`crate::signature`]). It is exposed as a public
//! function here so the test vectors and external callers can validate it
//! independently.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA-256 of `message` under `key`. Returns the 32-byte tag.
///
/// The `hmac` crate's `Hmac::new_from_slice` accepts keys of any length and
/// internally pads or hashes them to the SHA-256 block size, so the caller
/// does not need to worry about key normalization.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}
