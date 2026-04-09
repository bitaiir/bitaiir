//! Error type for the `bitaiir-chain` crate.
//!
//! Phase 1b introduces errors for the three state containers: the
//! [`Chain`](crate::chain::Chain), the [`UtxoSet`](crate::utxo::UtxoSet),
//! and the [`Mempool`](crate::mempool::Mempool). These are all
//! *structural* errors: they fire when a caller violates a container
//! invariant (pushing on top of the wrong parent, spending a missing
//! UTXO, inserting a duplicate). Consensus-level errors — invalid
//! proof of work, bad merkle root, over-spending a subsidy — will
//! land in Phase 1c as new variants alongside these.

use bitaiir_types::{Hash256, OutPoint};
use thiserror::Error;

/// Every error returned by `bitaiir-chain` flows through this single
/// enum. The variants are grouped by the subsystem that raises them.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    // --- Chain errors ---------------------------------------------------- //
    /// `Chain::push` was called with a block whose `prev_block_hash`
    /// does not match the current tip of the main chain. The chain
    /// only supports linear growth in Phase 1b; reorgs come later.
    #[error(
        "block parent mismatch: expected prev_block_hash = {expected}, \
         got {got}"
    )]
    ParentMismatch { expected: Hash256, got: Hash256 },

    /// A block with the given hash is already known to the chain.
    /// This prevents accidentally double-inserting the same block.
    #[error("block {0} is already in the chain")]
    DuplicateBlock(Hash256),

    // --- UTXO set errors ------------------------------------------------- //
    /// `UtxoSet::apply_transaction` tried to spend an outpoint that
    /// does not exist in the set. The caller is expected to have
    /// validated the transaction before calling `apply_transaction`,
    /// so this error indicates either a bug in validation or a
    /// direct misuse of the container.
    #[error("utxo set is missing the outpoint being spent: {0:?}")]
    MissingOutpoint(OutPoint),
}

/// Convenience alias used throughout `bitaiir-chain`.
pub type Result<T> = core::result::Result<T, Error>;
