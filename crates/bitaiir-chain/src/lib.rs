//! Consensus, validation, state, and mining for the BitAiir
//! blockchain.
//!
//! This crate is the heart of the protocol. When fully implemented it
//! will cover:
//!
//! - Block validation (header checks, Proof of Aiir, merkle root,
//!   timestamps, coinbase rules, transaction rules).
//! - Transaction validation against the UTXO set.
//! - The in-memory UTXO set, with apply/undo for reorgs.
//! - The mempool of pending transactions.
//! - Difficulty retargeting (`CompactTarget` adjustment every 144
//!   blocks).
//! - Coinbase rewards and the halving + tail-emission schedule.
//! - Fork choice and chain reorganization.
//! - Mining, both the full-node path (`bitaiird mine=1`) and a
//!   standalone command.
//!
//! It depends on `bitaiir-types` for data definitions and (in a later
//! phase) `bitaiir-crypto` for signature verification and hashing.
//! Persistence is the responsibility of `bitaiir-storage` and is
//! layered on top of this crate; nothing in `bitaiir-chain` touches
//! disk directly.
//!
//! # Implementation phases
//!
//! Work is landing incrementally so each commit can be reviewed and
//! tested on its own:
//!
//! - **Phase 1a** *(this commit)* — consensus math: the [`subsidy`]
//!   schedule (halvings + tail emission) and the [`CompactTarget`]
//!   encoding of block difficulty.
//! - **Phase 1b** — in-memory state containers: `Chain`, `UtxoSet`,
//!   `Mempool`, and their pure-function APIs.
//! - **Phase 1c** — block and transaction validation, with a
//!   temporary stub for the Proof-of-Aiir hash so the validation
//!   path can be tested without waiting on the Argon2id step.
//! - **Phase 1d** — mining: assemble blocks from the mempool, run
//!   Proof of Aiir until a valid nonce is found, splice the winning
//!   block into the chain.
//! - **Phase 2** — swap the Proof-of-Aiir stub for the real
//!   Argon2id-wrapped implementation.
//! - **Phase 3** — enforce the tx-level anti-spam proof of work from
//!   protocol §6.7 during transaction validation.

#![forbid(unsafe_code)]

pub mod chain;
pub mod consensus;
pub mod error;
pub mod genesis;
pub mod mempool;
pub mod mining;
pub mod pow;
pub mod subsidy;
pub mod target;
pub mod tx_pow;
pub mod utxo;
pub mod validation;

#[cfg(test)]
mod test_util;

pub use chain::Chain;
pub use error::{Error, Result};
pub use genesis::mine_genesis;
pub use mempool::Mempool;
pub use mining::{create_test_genesis, mine_block, mine_block_from_params, required_bits};
pub use pow::aiir_pow;
pub use subsidy::{BLOCKS_PER_HALVING, INITIAL_SUBSIDY, TAIL_EMISSION, subsidy};
pub use target::CompactTarget;
pub use tx_pow::{mine_tx_pow, validate_tx_pow};
pub use utxo::UtxoSet;
pub use validation::{validate_block, validate_transaction};
