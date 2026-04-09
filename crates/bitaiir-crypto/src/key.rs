//! secp256k1 keys wrapped in BitAiir-specific newtypes.
//!
//! This module provides thin wrappers around `secp256k1::SecretKey` and
//! `secp256k1::PublicKey` so the rest of the BitAiir codebase does not have
//! to import the `secp256k1` crate directly. The newtypes also act as a
//! semantic tag: a `bitaiir_crypto::PrivateKey` is clearly "a BitAiir
//! private key", not "any secp256k1 scalar", which catches category errors
//! at the type level.
//!
//! Private keys deliberately do not implement `Display`, and their `Debug`
//! representation is redacted, so they cannot be accidentally printed to
//! logs or error messages.

use secp256k1::{PublicKey as Secp256k1PublicKey, SECP256K1, SecretKey};

use crate::error::{Error, Result};

/// A secp256k1 private key known to be in the valid range `[1, n-1]`.
///
/// Construct with [`PrivateKey::from_bytes`]. Derive the corresponding
/// public key with [`PrivateKey::public_key`].
#[derive(Clone)]
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Create a `PrivateKey` from a 32-byte big-endian scalar.
    ///
    /// Returns [`Error::InvalidPrivateKey`] if the scalar is zero or greater
    /// than or equal to the curve order `n`. This is enforced by
    /// libsecp256k1 internally.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    /// Return the raw 32-byte big-endian scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    /// Derive the corresponding public key using the global secp256k1
    /// context provided by the `global-context` feature of the `secp256k1`
    /// crate.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key(SECP256K1))
    }

    /// Borrow the inner `secp256k1::SecretKey`. Used by the `signature`
    /// module to call into the upstream signing API without re-wrapping.
    pub(crate) fn as_secp256k1(&self) -> &SecretKey {
        &self.0
    }
}

// Hand-written Debug that never prints the scalar, to avoid leaking secrets
// into logs or error messages. A `PrivateKey` debug-prints as
// `PrivateKey(<redacted>)` regardless of its contents.
impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PrivateKey").field(&"<redacted>").finish()
    }
}

/// A point on the secp256k1 curve, representing a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(Secp256k1PublicKey);

impl PublicKey {
    /// Parse a public key from its SEC1 byte encoding. Accepts both
    /// compressed (33 bytes, starting with `0x02` or `0x03`) and
    /// uncompressed (65 bytes, starting with `0x04`) formats.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        Secp256k1PublicKey::from_slice(data)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Serialize as 33 bytes in SEC1 compressed format: `0x02` or `0x03`
    /// followed by the 32-byte `x` coordinate.
    pub fn to_compressed(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Serialize as 65 bytes in SEC1 uncompressed format: `0x04` followed
    /// by the 32-byte `x` coordinate and then the 32-byte `y` coordinate.
    pub fn to_uncompressed(&self) -> [u8; 65] {
        self.0.serialize_uncompressed()
    }

    /// Wrap a `secp256k1::PublicKey` as a BitAiir `PublicKey`. Used by the
    /// `signature` module to surface the output of ECDSA recovery without
    /// forcing callers to serialize-and-reparse.
    pub(crate) fn from_secp256k1(inner: Secp256k1PublicKey) -> Self {
        Self(inner)
    }
}
