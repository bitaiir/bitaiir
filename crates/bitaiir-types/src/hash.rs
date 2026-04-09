//! `Hash256`: a 256-bit digest used for block hashes, transaction IDs,
//! and merkle roots.
//!
//! This is a newtype around `[u8; 32]` that carries its own `Display`,
//! `FromStr`, and serde implementations, so hashes flow through JSON, logs,
//! and storage without losing their type identity.
//!
//! # Display convention
//!
//! Hashes are displayed in natural big-endian hex order. This is the same
//! ordering used internally; there is no Bitcoin-style byte reversal. A
//! hash whose bytes are `[0x00, 0x01, ...0x1f]` prints as
//! `"000102...1f"`, and parses back from the same string.

use core::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A 256-bit hash value.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// The all-zero hash. Used as a sentinel for "no previous block" in the
    /// genesis header and for coinbase input references.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wrap a raw 32-byte array as a `Hash256`.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32-byte array.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the hash in big-endian order.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// Hand-written Debug so hashes show up as `Hash256(deadbeef...)` instead of
// the 32-element array `Hash256([222, 173, 190, 239, ...])`, which is
// unreadable in logs.
impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Hash256 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| Error::InvalidLength {
                expected: 32,
                got: v.len(),
            })?;
        Ok(Self(array))
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Hash256> for [u8; 32] {
    fn from(h: Hash256) -> Self {
        h.0
    }
}
