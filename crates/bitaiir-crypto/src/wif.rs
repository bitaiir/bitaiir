//! Wallet Import Format (WIF) for BitAiir private keys.
//!
//! WIF is a human-copy-pasteable encoding for a 32-byte private key plus a
//! single bit of metadata (whether the key is meant to be used with the
//! compressed or uncompressed public key form). It is a Base58Check wrapper
//! around the following payload:
//!
//! - 1 byte: version byte.
//! - 32 bytes: the private key, big-endian.
//! - (optional) 1 byte: compression flag `0x01`, present only for
//!   compressed keys.
//!
//! BitAiir uses version byte `0xfe`, which is distinct from Bitcoin mainnet
//! (`0x80`) and Bitcoin testnet (`0xef`). This means a BitAiir WIF cannot
//! be confused with a Bitcoin WIF even if the underlying scalar is the
//! same.

use crate::base58;
use crate::error::{Error, Result};
use crate::key::PrivateKey;

/// The first byte of every BitAiir WIF payload, before Base58Check.
pub const WIF_VERSION_BYTE: u8 = 0xfe;

/// The byte appended after the 32-byte private key when the WIF marks its
/// key as compressed. Its presence (or absence) is the only difference
/// between a compressed and an uncompressed WIF.
const COMPRESSION_FLAG: u8 = 0x01;

/// Encode a private key as a WIF string.
///
/// `compressed` selects whether the resulting WIF carries the compression
/// flag. This does not change the private key itself; it just records which
/// public key serialization (and therefore which address) the key is meant
/// to be paired with.
pub fn encode(private_key: &PrivateKey, compressed: bool) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(WIF_VERSION_BYTE);
    payload.extend_from_slice(&private_key.to_bytes());
    if compressed {
        payload.push(COMPRESSION_FLAG);
    }
    base58::encode_check(&payload)
}

/// Decode a WIF string into a private key and its compression flag.
///
/// Returns [`Error::InvalidWif`] if the string has the wrong length, the
/// wrong version byte, a bad compression flag, or (via
/// [`base58::decode_check`]) a bad Base58Check checksum.
pub fn decode(wif: &str) -> Result<(PrivateKey, bool)> {
    let payload = base58::decode_check(wif)?;

    // After stripping the checksum, a valid payload is either 33 bytes
    // (uncompressed: version + 32-byte key) or 34 bytes (compressed:
    // version + 32-byte key + compression flag).
    let compressed = match payload.len() {
        33 => false,
        34 => true,
        _ => return Err(Error::InvalidWif("unexpected payload length")),
    };

    if payload[0] != WIF_VERSION_BYTE {
        return Err(Error::InvalidWif("wrong version byte"));
    }
    if compressed && payload[33] != COMPRESSION_FLAG {
        return Err(Error::InvalidWif("bad compression flag"));
    }

    // Copy the 32 key bytes into a fixed-size array so `PrivateKey::from_bytes`
    // can type-check the length at compile time.
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&payload[1..33]);

    let private_key = PrivateKey::from_bytes(&key_bytes)?;
    Ok((private_key, compressed))
}
