//! Base58 and Base58Check encoding.
//!
//! BitAiir uses the same Base58 alphabet as Bitcoin:
//! `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
//!
//! [`encode`] and [`decode`] perform plain Base58 (no checksum). The
//! Base58Check variants append/verify a 4-byte SHA-256d checksum and are
//! used for the WIF and address encodings.

use crate::error::{Error, Result};
use crate::hash::double_sha256;

/// Encode `data` as a plain Base58 string.
///
/// Empty input encodes to the empty string. A single zero byte encodes to
/// `"1"`, two zero bytes to `"11"`, and so on. This matches the canonical
/// Bitcoin behavior and round-trips with [`decode`].
pub fn encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
}

/// Decode a Base58 string into bytes.
///
/// Returns [`Error::Base58Decode`] if the string contains characters outside
/// the Base58 alphabet.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    bs58::decode(s)
        .into_vec()
        .map_err(|e| Error::Base58Decode(e.to_string()))
}

/// Encode `payload` as Base58Check: append a 4-byte SHA-256d checksum, then
/// Base58-encode the whole buffer.
pub fn encode_check(payload: &[u8]) -> String {
    let checksum = double_sha256(payload);
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum[..4]);
    encode(&buf)
}

/// Decode a Base58Check string and verify its 4-byte checksum.
///
/// Returns the payload bytes (without the checksum) on success, or an error
/// if the checksum is invalid or the input is shorter than 4 bytes.
pub fn decode_check(s: &str) -> Result<Vec<u8>> {
    let raw = decode(s)?;
    if raw.len() < 4 {
        return Err(Error::Base58Checksum);
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    let expected = double_sha256(payload);
    if checksum != &expected[..4] {
        return Err(Error::Base58Checksum);
    }
    Ok(payload.to_vec())
}
