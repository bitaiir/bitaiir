//! BitAiir address derivation.
//!
//! A BitAiir address is a Bitcoin-style P2PKH address with a branding
//! prefix. The derivation procedure is:
//!
//! 1. Serialize the public key (compressed or uncompressed).
//! 2. Compute `HASH160 = RIPEMD-160(SHA-256(pubkey))`.
//! 3. Prepend the version byte `0x00` to produce the 21-byte payload.
//! 4. Base58Check-encode the payload (append SHA-256d checksum, then
//!    Base58).
//! 5. Prepend the literal ASCII prefix `"aiir"` to the resulting string.
//!
//! Step 5 is the BitAiir-specific detail. The `aiir` prefix is NOT included
//! in the checksummed payload; it is a cosmetic marker stacked on top of an
//! otherwise standard P2PKH encoding. Implementations that decode BitAiir
//! addresses must strip `"aiir"` first, then verify the Base58Check body.

use crate::base58;
use crate::hash::hash160;
use crate::key::PublicKey;

/// The version byte placed at the front of the Base58Check payload, before
/// the 20-byte HASH160. `0x00` matches Bitcoin mainnet P2PKH.
pub const ADDRESS_VERSION_BYTE: u8 = 0x00;

/// The literal string prepended to every BitAiir address after
/// Base58Check encoding. Not part of the checksummed payload.
pub const ADDRESS_PREFIX: &str = "aiir";

/// A BitAiir mainnet address.
///
/// Internally this is just a `String`, but the newtype keeps address-typed
/// values distinct from arbitrary strings in the type system, which catches
/// a whole class of "did I pass the address or the message?" mistakes at
/// compile time.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(String);

impl Address {
    /// Derive a BitAiir address from a public key using the compressed SEC1
    /// serialization (33 bytes).
    pub fn from_compressed_public_key(pk: &PublicKey) -> Self {
        Self::from_pubkey_bytes(&pk.to_compressed())
    }

    /// Derive a BitAiir address from a public key using the uncompressed
    /// SEC1 serialization (65 bytes).
    pub fn from_uncompressed_public_key(pk: &PublicKey) -> Self {
        Self::from_pubkey_bytes(&pk.to_uncompressed())
    }

    /// Derive a BitAiir address from an already-serialized public key
    /// (either 33 or 65 bytes). This is the lowest-level entry point and
    /// is useful when the public key bytes come from an external source
    /// such as a signature recovery step.
    pub fn from_pubkey_bytes(pubkey_bytes: &[u8]) -> Self {
        let digest = hash160(pubkey_bytes);

        let mut payload = Vec::with_capacity(1 + digest.len());
        payload.push(ADDRESS_VERSION_BYTE);
        payload.extend_from_slice(&digest);

        let base58_body = base58::encode_check(&payload);
        Self(format!("{ADDRESS_PREFIX}{base58_body}"))
    }

    /// Reconstruct a BitAiir address from the 20-byte `hash160`
    /// recipient hash stored in a `TxOut`.  This is the reverse of the
    /// decode path: `version_byte || hash → base58check → "aiir" prefix`.
    pub fn from_recipient_hash(hash: &[u8; 20]) -> Self {
        let mut payload = Vec::with_capacity(21);
        payload.push(ADDRESS_VERSION_BYTE);
        payload.extend_from_slice(hash);
        let base58_body = base58::encode_check(&payload);
        Self(format!("{ADDRESS_PREFIX}{base58_body}"))
    }

    /// Borrow the address as a string slice, for printing or comparison.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
