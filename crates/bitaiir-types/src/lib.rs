//! Core protocol data types for BitAiir.
//!
//! This crate defines the on-chain data shapes every other crate in the
//! workspace agrees on: hashes, amounts, transactions, blocks, and the
//! canonical serialization used to compute their digests. It deliberately
//! contains no consensus logic (that lives in `bitaiir-chain`), no I/O,
//! and no networking — `bitaiir-types` is pure data.
//!
//! The layering is:
//!
//! - [`Hash256`] is the fundamental fixed-size digest.
//! - [`Amount`] is an atomic-unit quantity of AIIR.
//! - [`Transaction`], [`TxIn`], [`TxOut`], and [`OutPoint`] describe the
//!   UTXO model.
//! - [`BlockHeader`] and [`Block`] describe the proof-of-work chain.
//! - [`encoding`] and [`merkle`] hold the two shared algorithms used
//!   across those types.
//!
//! See the individual module docs for design notes.

#![forbid(unsafe_code)]

pub mod amount;
pub mod block;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod merkle;
pub mod network;
pub mod transaction;

pub use amount::{ATOMIC_UNITS_PER_AIIR, Amount, MAX_SUPPLY};
pub use block::{Block, BlockHeader};
pub use error::{Error, Result};
pub use hash::Hash256;
pub use merkle::merkle_root;
pub use network::Network;
pub use transaction::{OutPoint, Transaction, TxIn, TxOut};
