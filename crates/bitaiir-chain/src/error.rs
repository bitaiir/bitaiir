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

    /// A block's `prev_block_hash` is not in the chain's block index.
    /// Returned by `accept_block` when the parent hasn't been seen —
    /// callers can stash such blocks in an orphan pool and retry once
    /// the parent arrives.
    #[error("block's parent {0} is not known to the chain")]
    UnknownParent(Hash256),

    /// Internal invariant violation while walking a chain from a tip
    /// back to the common ancestor (e.g. a block's parent hash is
    /// not in the block index mid-walk).  This indicates corruption
    /// or a programming bug — never user input.
    #[error("chain traversal from {tip} failed at {at}: missing parent link")]
    BrokenChainLink { tip: Hash256, at: Hash256 },

    // --- Mempool errors -------------------------------------------------- //
    /// The mempool is at capacity and the incoming transaction has
    /// lower priority (higher tx-PoW hash, later arrival on ties)
    /// than every transaction currently held, so it's rejected
    /// without evicting anything.
    #[error("mempool is full and incoming tx has lower priority than existing ones")]
    MempoolFull,

    /// The incoming transaction's serialized size alone exceeds the
    /// mempool's configured capacity.  No amount of eviction can
    /// make room for it.
    #[error("transaction size {size} exceeds mempool capacity {max}")]
    TxTooLargeForMempool { size: usize, max: usize },

    // --- UTXO set errors ------------------------------------------------- //
    /// A transaction tried to spend an outpoint not in the UTXO set.
    #[error("utxo set is missing the outpoint being spent: {0}")]
    MissingOutpoint(OutPoint),

    /// `UtxoSet::undo_block` was called with a `BlockUndo` whose
    /// `block_hash` does not match the block being undone.  This
    /// indicates a caller-side pairing bug (wrong undo record).
    #[error("undo record block hash {got} does not match block {expected}")]
    UndoBlockHashMismatch { expected: Hash256, got: Hash256 },

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
    #[error("input spends unknown outpoint {0}")]
    UnknownInput(OutPoint),

    /// Two inputs reference the same outpoint.
    #[error("duplicate input: outpoint {0} appears more than once")]
    DuplicateInput(OutPoint),

    /// Sum of outputs exceeds sum of inputs (money creation).
    #[error("outputs total {outputs} exceeds inputs total {inputs}")]
    OutputsExceedInputs { inputs: u64, outputs: u64 },

    /// The pubkey in a TxIn does not hash to the UTXO's recipient_hash.
    #[error("pubkey hash mismatch for outpoint {0}")]
    PubkeyMismatch(OutPoint),

    /// A non-P2PKH output was spent as if it were P2PKH.
    #[error("invalid output type for P2PKH spend on outpoint {0}")]
    InvalidOutputType(OutPoint),

    /// The ECDSA signature in a TxIn is invalid.
    #[error("invalid signature for outpoint {0}")]
    InvalidInputSignature(OutPoint),

    /// An output_type value is not recognized.
    #[error("unknown output type {0}")]
    UnknownOutputType(u8),

    /// An alias output payload could not be parsed.
    #[error("malformed alias payload")]
    MalformedAliasPayload,

    /// Alias name validation failed.
    #[error("invalid alias name: {0}")]
    InvalidAliasName(&'static str),

    /// Alias registration fee too low.
    #[error("alias registration fee below minimum")]
    AliasFeeInsufficient,

    /// Alias expiry_height is already in the past.
    #[error("alias expiry {0} is in the past")]
    AliasExpiryInPast(u32),

    /// Alias expiry_height is too far in the future.
    #[error("alias expiry {got} exceeds max {max}")]
    AliasExpiryTooFar { max: u32, got: u32 },

    /// An alias with this name already exists.
    #[error("alias already registered: {0}")]
    AliasAlreadyRegistered(String),

    /// An escrow output payload could not be parsed.
    #[error("malformed escrow payload")]
    MalformedEscrowPayload,

    /// Escrow M is invalid (0, or > N).
    #[error("escrow m={m} invalid for n={n}")]
    EscrowInvalidM { m: u8, n: u8 },

    /// Escrow N is invalid (0, or > MAX_ESCROW_N).
    #[error("escrow n={0} out of range")]
    EscrowInvalidN(u8),

    /// Escrow timeout_height is in the past.
    #[error("escrow timeout {0} is in the past")]
    EscrowTimeoutInPast(u32),

    /// Escrow refund_hash is all zeros.
    #[error("escrow refund_hash must not be zero")]
    EscrowZeroRefundHash,

    /// Escrow amount is zero.
    #[error("escrow amount must be > 0")]
    EscrowZeroAmount,

    /// Escrow has duplicate signer hashes.
    #[error("escrow pubkey_hashes contain duplicates")]
    EscrowDuplicateSigner,

    /// Trying to refund before the timeout has passed.
    #[error("escrow refund before timeout for outpoint {0}")]
    EscrowRefundBeforeTimeout(OutPoint),

    /// Wrong number of signatures for M-of-N release.
    #[error("escrow needs {expected_m} sigs, got {got_pks} pks / {got_sigs} sigs")]
    EscrowWrongSigCount {
        expected_m: u8,
        got_pks: usize,
        got_sigs: usize,
    },

    /// A signer's pubkey hash is not in the escrow's authorized list.
    #[error("escrow signer not authorized for outpoint {0}")]
    EscrowUnauthorizedSigner(OutPoint),

    /// The transaction's anti-spam pow_nonce does not meet the target.
    #[error("invalid transaction proof of work (anti-spam nonce)")]
    InvalidTxPow,

    /// A transaction tries to spend a coinbase output that has not
    /// matured (less than 100 blocks old).  The message shows where
    /// the coinbase came from and exactly how many more confirmations
    /// are needed, so the user can gauge how long to wait.
    #[error("coinbase from block {created_at} needs {remaining} more confirmations")]
    ImmatureCoinbase {
        outpoint: OutPoint,
        created_at: u64,
        current_height: u64,
        maturity: u64,
        remaining: u64,
    },
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
