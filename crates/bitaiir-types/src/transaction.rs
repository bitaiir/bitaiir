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

impl core::fmt::Display for OutPoint {
    /// Human-friendly `{txid}:{vout}` format for error messages and
    /// logs.  The txid is shown in full hex so the output can be fed
    /// straight into `/getblock` or a block explorer.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
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
///
/// Besides the usual Bitcoin-shaped fields, every non-coinbase
/// transaction carries an extra `pow_nonce` at the end. This is the
/// Hashcash-style anti-spam proof of work defined in protocol §6.7:
/// the sender mines `pow_nonce` until the transaction's double
/// SHA-256 (with `pow_nonce = 0` for that step) meets a small target,
/// costing roughly two seconds of CPU time on a commodity laptop.
/// The field replaces the minimum-fee rule that Bitcoin uses to
/// throttle spam — BitAiir keeps fees optional and prices abuse in
/// sender-side CPU instead.
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
    /// Sender-side anti-spam proof of work. Coinbase transactions set
    /// this to `0` and are exempt from the check (they are already
    /// rate-limited by the block-level Proof of Aiir). See
    /// [`Transaction::sighash`] for why this field is cleared during
    /// signature computation.
    pub pow_nonce: u64,
}

impl Transaction {
    /// Compute the transaction ID: `double_sha256` of the canonical
    /// encoding of the whole transaction, including signatures **and**
    /// `pow_nonce`.
    ///
    /// A consequence is that changing either the signatures or the
    /// `pow_nonce` changes the txid. Signature normalization
    /// (RFC 6979 through libsecp256k1) ensures that the same
    /// `(private_key, message)` pair always yields the same signature
    /// bytes, so well-behaved signers produce stable txids once they
    /// have mined their anti-spam nonce.
    pub fn txid(&self) -> Hash256 {
        // bincode encoding of a well-formed `Transaction` is infallible:
        // every field is either a fixed-size type or a `Vec` of such
        // types. There is no user-supplied `Serialize` impl that could
        // fail, so the `expect` here represents a true invariant.
        let bytes = encoding::to_bytes(self).expect("Transaction always encodes");
        Hash256::from_bytes(double_sha256(&bytes))
    }

    /// Compute the signing digest (sighash) that each input must sign.
    ///
    /// Per protocol §6.4, the sighash is `double_sha256` of a canonical
    /// encoding of the transaction with two modifications applied to a
    /// clone:
    ///
    /// - Every input's `signature` field is cleared to an empty `Vec`.
    /// - The `pow_nonce` field is cleared to `0`.
    ///
    /// The `pubkey` fields are left intact so the recovered key can be
    /// matched against each input's declared public key.
    ///
    /// Clearing `signature` is the classic reason — a signature cannot
    /// sign over itself. Clearing `pow_nonce` is the BitAiir-specific
    /// twist: the anti-spam proof of work is mined **after** signing,
    /// because mining it requires the final transaction shape. If the
    /// sighash included `pow_nonce`, the sender would face a
    /// chicken-and-egg problem (sign → change nonce → invalidate
    /// signature → re-sign → change nonce again → ...). Excluding it
    /// breaks the loop: the signature covers the "template" of the
    /// transaction, and the spam proof is a free-standing seal on top.
    pub fn sighash(&self) -> Hash256 {
        let mut template = self.clone();
        for input in &mut template.inputs {
            input.signature.clear();
        }
        template.pow_nonce = 0;

        let bytes = encoding::to_bytes(&template).expect("Transaction always encodes");
        Hash256::from_bytes(double_sha256(&bytes))
    }

    /// Whether this is the coinbase transaction: exactly one input whose
    /// `prev_out` is the null outpoint. The full validity of a
    /// coinbase (subsidy cap, maturity, `pow_nonce == 0`) is checked by
    /// `bitaiir-chain` at block validation time, not here.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev_out == OutPoint::NULL
    }
}
