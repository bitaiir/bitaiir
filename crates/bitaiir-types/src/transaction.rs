//! Transactions, inputs, and outputs.
//!
//! BitAiir follows a Bitcoin-style UTXO model: a transaction consumes some
//! number of previously-unspent outputs and produces new outputs. What it
//! deliberately does *not* have is a scripting language. Each output
//! specifies a recipient by their 20-byte HASH160 (the same payload
//! embedded in a BitAiir address), and each input proves authorization
//! with a raw `(signature, pubkey)` pair. No opcodes, no interpreter.
//!
//! This is the simplest model that supports normal payments. Future
//! protocol versions could add a richer script layer without changing the
//! on-chain data definitions here — the `signature` field is already a
//! `Vec<u8>` so it can hold arbitrary unlocking data.

use bitaiir_crypto::hash::double_sha256;
use serde::{Deserialize, Serialize};

use crate::amount::Amount;
use crate::encoding;
use crate::hash::Hash256;

/// A reference to a specific output of a previous transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Transaction ID of the referenced transaction.
    pub txid: Hash256,
    /// Zero-based index of the output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint (`Hash256::ZERO` / `u32::MAX`) used as the
    /// sentinel `prev_out` for coinbase transactions.
    pub const NULL: Self = Self {
        txid: Hash256::ZERO,
        vout: u32::MAX,
    };
}

/// An input to a transaction, spending a previous output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    /// The previous output being consumed.
    pub prev_out: OutPoint,
    /// Compact 64-byte ECDSA signature authorizing the spend. For coinbase
    /// transactions this field is reused as the extra-nonce / miner
    /// payload and may carry arbitrary bytes.
    pub signature: Vec<u8>,
    /// Serialized public key matching the signature: 33 bytes if the
    /// recipient was derived from a compressed pubkey, 65 bytes if
    /// uncompressed. Empty for coinbase inputs.
    pub pubkey: Vec<u8>,
    /// Sequence number, following Bitcoin's convention. `0xffffffff`
    /// disables relative locktime.
    pub sequence: u32,
}

/// An output of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// How much AIIR this output pays, in atomic units.
    pub amount: Amount,
    /// The 20-byte HASH160 of the recipient's public key — the same
    /// payload encoded inside a BitAiir address between the version byte
    /// and the checksum.
    pub recipient_hash: [u8; 20],
}

/// A complete BitAiir transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Protocol version this transaction was produced under.
    pub version: u32,
    /// Inputs being consumed.
    pub inputs: Vec<TxIn>,
    /// Outputs being created.
    pub outputs: Vec<TxOut>,
    /// Earliest block height (interpreted as height for now, never as
    /// timestamp) at which this transaction may be included in a block.
    pub locktime: u32,
}

impl Transaction {
    /// Compute the transaction ID: `double_sha256` of the canonical
    /// encoding of the whole transaction, including signatures.
    ///
    /// A consequence is that re-signing a transaction changes its txid.
    /// Signature normalization (RFC 6979 through libsecp256k1) ensures
    /// that the same `(private_key, message)` pair always yields the same
    /// signature bytes, so well-behaved signers produce stable txids.
    pub fn txid(&self) -> Hash256 {
        // bincode encoding of a well-formed `Transaction` is infallible:
        // every field is either a fixed-size type or a `Vec` of such
        // types. There is no user-supplied `Serialize` impl that could
        // fail, so the `expect` here represents a true invariant.
        let bytes = encoding::to_bytes(self).expect("Transaction always encodes");
        Hash256::from_bytes(double_sha256(&bytes))
    }

    /// Whether this is the coinbase transaction: exactly one input whose
    /// `prev_out` is the null outpoint.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out == OutPoint::NULL
    }
}
