//! Cryptographic primitives for BitAiir.
//!
//! This crate is the lowest layer of the BitAiir node. It provides:
//!
//! - Hashing: SHA-256, double SHA-256, RIPEMD-160, HASH160 (RIPEMD-160 of
//!   SHA-256), and HMAC-SHA-256.
//! - Base58 and Base58Check encoding.
//! - secp256k1 private and public keys, wrapped in BitAiir newtypes.
//! - WIF (Wallet Import Format) for private keys, with BitAiir's `0xfe`
//!   version byte.
//! - BitAiir addresses (Base58Check HASH160 with an `"aiir"` prefix).
//! - (Phase C) Bitcoin-style signed messages with public-key recovery.
//!
//! Every public function in this crate is cross-validated against the Python
//! reference implementation in `reference/python/` so we can be confident the
//! Rust port produces byte-for-byte identical output. See
//! `tests/vectors.rs` for the integration test that loads
//! `tests/vectors/crypto.json` and runs each section against the
//! corresponding Rust function.

#![forbid(unsafe_code)]

pub mod address;
pub mod base58;
pub mod error;
pub mod hash;
pub mod hd;
pub mod hmac;
pub mod key;
pub mod signature;
pub mod wif;

pub use address::Address;
pub use error::{Error, Result};
pub use key::{PrivateKey, PublicKey};
pub use signature::{SignedMessage, VerifyOutcome};
