//! Hash function primitives used throughout BitAiir.
//!
//! This module provides four functions:
//!
//! - [`sha256`] — single SHA-256.
//! - [`double_sha256`] — SHA-256 applied twice (Bitcoin-style "HASH256").
//! - [`ripemd160`] — single RIPEMD-160.
//! - [`hash160`] — RIPEMD-160 applied to SHA-256 (Bitcoin-style "HASH160"),
//!   the function used to derive an address from a public key.
//!
//! Every function returns a fixed-size array (`[u8; 32]` or `[u8; 20]`)
//! rather than a `Vec<u8>`. The size is part of the type, so callers cannot
//! accidentally pass the wrong-length digest into a function that expects
//! one.

use ripemd::{Digest as _, Ripemd160};
use sha2::Sha256;

/// Compute SHA-256 of `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256(SHA-256(`data`)) and return the 32-byte digest.
///
/// This is the "HASH256" function used pervasively in Bitcoin and BitAiir
/// for transaction IDs, block hashes, and the Base58Check checksum.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute RIPEMD-160 of `data` and return the 20-byte digest.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute RIPEMD-160(SHA-256(`data`)) and return the 20-byte digest.
///
/// This is the "HASH160" function used to turn a public key into the raw
/// payload of a P2PKH address.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}
