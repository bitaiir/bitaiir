//! Error type for the `bitaiir-types` crate.
//!
//! The surface is intentionally small: parsing primitives, decoding bytes,
//! and flagging the handful of structural invariants `bitaiir-types`
//! enforces. Consensus-level errors (invalid signature, double-spend, etc.)
//! live in `bitaiir-chain`, which is where protocol rules actually run.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A hex string could not be decoded (odd length, non-hex characters).
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// A hex string was well-formed but did not have the expected length
    /// for the target fixed-size type.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// A bincode encoding step failed. Should not happen for well-formed
    /// `bitaiir-types` values; surfaces as an error for user-supplied ones.
    #[error("encoding error: {0}")]
    Encode(String),

    /// A bincode decoding step failed: the input bytes did not match the
    /// expected schema.
    #[error("decoding error: {0}")]
    Decode(String),
}

pub type Result<T> = core::result::Result<T, Error>;
