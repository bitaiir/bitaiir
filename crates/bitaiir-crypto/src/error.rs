//! Error types for the `bitaiir-crypto` crate.
//!
//! All fallible operations in this crate return [`Result<T>`], which is an
//! alias for `std::result::Result<T, Error>`. The error enum is intentionally
//! coarse: each variant maps to one user-visible failure mode (decoding
//! failed, checksum mismatch, key out of range, etc.) so callers don't have
//! to think about which underlying library raised it.

use thiserror::Error;

/// All errors that the `bitaiir-crypto` crate can produce.
#[derive(Debug, Error)]
pub enum Error {
    /// A Base58 string could not be decoded (unknown character, etc.).
    #[error("base58 decode error: {0}")]
    Base58Decode(String),

    /// A Base58Check checksum did not match the expected value.
    #[error("base58 checksum mismatch")]
    Base58Checksum,

    /// A WIF (Wallet Import Format) string had the wrong version byte,
    /// length, or checksum.
    #[error("invalid WIF: {0}")]
    InvalidWif(&'static str),

    /// A 32-byte private key value was not in the valid range `[1, n-1]`
    /// for the secp256k1 curve.
    #[error("private key is not a valid secp256k1 scalar")]
    InvalidPrivateKey,

    /// A public key could not be parsed from its serialized form.
    #[error("invalid public key encoding")]
    InvalidPublicKey,

    /// A signature could not be decoded or had the wrong shape.
    #[error("invalid signature: {0}")]
    InvalidSignature(&'static str),

    /// An address string did not have the expected `aiir` prefix or
    /// failed checksum verification.
    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
