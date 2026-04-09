//! Consensus, validation, and state for the BitAiir blockchain.
//!
//! This crate is the heart of the protocol. It implements:
//!
//! - Block validation (header checks, proof-of-work, merkle root, timestamps).
//! - Transaction validation against the UTXO set.
//! - The UTXO set itself, with apply/undo for reorgs.
//! - The mempool: pending transactions waiting to be mined.
//! - Difficulty adjustment.
//! - Coinbase rewards and halving schedule.
//! - Fork choice and chain reorganization.
//!
//! It depends on `bitaiir-types` for data definitions, `bitaiir-crypto` for
//! hashing and signature verification, and `bitaiir-storage` for persistence.

#![forbid(unsafe_code)]
