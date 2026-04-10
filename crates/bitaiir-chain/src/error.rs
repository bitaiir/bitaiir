//! Error type for the `bitaiir-chain` crate.
//!
//! Every fallible operation in this crate returns [`Result<T>`], which
//! is an alias for `core::result::Result<T, Error>`. The variants are
//! grouped by the subsystem that raises them: chain state, UTXO set,
//! and block/transaction validation.

use bitaiir_types::{Hash256, OutPoint};
use thiserror::Error;

/// Every error produced by `bitaiir-chain`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    // --- Chain state errors ----------------------------------------------- //
    /// Block's `prev_block_hash` does not match the current tip.
    #[error(
        "block parent mismatch: expected prev_block_hash = {expected}, \
         got {got}"
    )]
    ParentMismatch { expected: Hash256, got: Hash256 },

    /// A block with this hash is already in the chain.
    #[error("block {0} is already in the chain")]
    DuplicateBlock(Hash256),

    // --- UTXO set errors ------------------------------------------------- //
    /// A transaction tried to spend an outpoint not in the UTXO set.
    #[error("utxo set is missing the outpoint being spent: {0:?}")]
    MissingOutpoint(OutPoint),

    // --- Block validation errors (protocol §7.4) ------------------------- //
    /// Rule 1: serialized block size exceeds MAX_BLOCK_SIZE.
    #[error("block too large: {size} bytes (max {max})")]
    BlockTooLarge { size: usize, max: usize },

    /// Rule 2: proof-of-work hash does not meet the target.
    #[error("insufficient proof of work")]
    InsufficientProofOfWork,

    /// Rule 3: the `bits` field does not match the expected difficulty.
    #[error("unexpected difficulty bits: expected {expected:#010x}, got {got:#010x}")]
    WrongDifficulty { expected: u32, got: u32 },

    /// Rule 4: timestamp is not greater than median-time-past.
    #[error("block timestamp {timestamp} is not after median-time-past {mtp}")]
    TimestampTooEarly { timestamp: u64, mtp: u64 },

    /// Rule 5: timestamp is too far in the future.
    #[error("block timestamp {timestamp} is more than {max_future}s ahead of network time {now}")]
    TimestampTooFarInFuture {
        timestamp: u64,
        now: u64,
        max_future: u64,
    },

    /// Rule 7: header `merkle_root` does not match the computed one.
    #[error("merkle root mismatch: header says {header}, computed {computed}")]
    MerkleRootMismatch { header: Hash256, computed: Hash256 },

    /// Rule 8: first transaction is not a valid coinbase.
    #[error("missing or invalid coinbase: {reason}")]
    InvalidCoinbase { reason: &'static str },

    /// Rule 10: the block contains duplicate transactions.
    #[error("block contains duplicate transaction {0}")]
    DuplicateTransaction(Hash256),

    /// Rule 11: coinbase outputs exceed subsidy + fees.
    #[error("coinbase output total {coinbase_total} exceeds allowed {allowed}")]
    CoinbaseOverspend { coinbase_total: u64, allowed: u64 },

    // --- Transaction validation errors (protocol §6.1) ------------------- //
    /// Transaction is too large.
    #[error("transaction too large: {size} bytes (max {max})")]
    TxTooLarge { size: usize, max: usize },

    /// Transaction has no inputs.
    #[error("transaction has no inputs")]
    NoInputs,

    /// Transaction has no outputs.
    #[error("transaction has no outputs")]
    NoOutputs,

    /// An input references a non-existent UTXO.
    #[error("input spends unknown outpoint {0:?}")]
    UnknownInput(OutPoint),

    /// Two inputs reference the same outpoint.
    #[error("duplicate input: outpoint {0:?} appears more than once")]
    DuplicateInput(OutPoint),

    /// Sum of outputs exceeds sum of inputs (money creation).
    #[error("outputs total {outputs} exceeds inputs total {inputs}")]
    OutputsExceedInputs { inputs: u64, outputs: u64 },

    /// The pubkey in a TxIn does not hash to the UTXO's recipient_hash.
    #[error("pubkey hash mismatch for outpoint {0:?}")]
    PubkeyMismatch(OutPoint),

    /// The ECDSA signature in a TxIn is invalid.
    #[error("invalid signature for outpoint {0:?}")]
    InvalidInputSignature(OutPoint),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
