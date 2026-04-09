//! Canonical binary encoding used for consensus hashes.
//!
//! `bitaiir-types` uses `bincode` v2 (via its `serde` bridge) as the
//! canonical binary format for everything that must be hashed
//! deterministically: transactions, block headers, merkle inputs. The
//! shape of the encoded bytes is whatever bincode's `standard()` config
//! produces.
//!
//! This module exists so that if we ever decide to replace bincode with a
//! hand-rolled wire format (for example, to match Bitcoin's
//! variable-length integers byte-for-byte), the change lives in one place
//! and the rest of the crate keeps calling [`to_bytes`] / [`from_bytes`].
//!
//! # Why bincode v2 with the serde bridge?
//!
//! We already `#[derive(Serialize, Deserialize)]` on every protocol type
//! for the RPC layer's JSON output. Using bincode's serde bridge lets us
//! reuse the exact same derives for the binary path, so there is only one
//! source of truth for what fields a type has and in what order. The
//! alternative — deriving bincode's own `Encode` / `Decode` in addition to
//! serde's — would double the derives and create a risk of the two
//! representations drifting apart.

use bincode::config::Config;
use serde::{Serialize, de::DeserializeOwned};

use crate::error::{Error, Result};

/// The bincode configuration used for every canonical encoding in this
/// crate. Centralized here so nobody accidentally hashes a value under a
/// different config and produces a different digest.
#[inline]
fn canonical_config() -> impl Config {
    bincode::config::standard()
}

/// Serialize `value` into a canonical byte vector.
pub fn to_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, canonical_config())
        .map_err(|e| Error::Encode(e.to_string()))
}

/// Deserialize a canonical byte slice into `T`.
///
/// The second element of bincode's tuple return value (the number of bytes
/// consumed) is discarded: this helper assumes the caller gave it exactly
/// one encoded value and does not need to resume decoding.
pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, canonical_config())
        .map_err(|e| Error::Decode(e.to_string()))?;
    Ok(value)
}
