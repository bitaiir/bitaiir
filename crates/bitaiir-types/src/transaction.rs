//! Transactions, inputs, and outputs.
//!
//! BitAiir follows a Bitcoin-style UTXO model: a transaction consumes some
//! number of previously-unspent outputs and produces new outputs.
//!
//! Each output carries an `output_type` discriminator:
//!
//! - **Type 0 (P2PKH):** standard pay-to-pubkey-hash. The `payload` is
//!   the 20-byte HASH160 of the recipient's public key, and spending
//!   requires a `(signature, pubkey)` pair that matches.
//! - **Type 1 (Escrow):** N-of-M multisig with timeout (protocol §21).
//! - **Type 2 (Alias):** on-chain name registry entry (protocol §20).
//!
//! The `signature` field on `TxIn` is a `Vec<u8>` so it can hold
//! concatenated multi-sig data for escrow spends.

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

/// Output type discriminator — protocol §20.2.
pub const OUTPUT_TYPE_P2PKH: u8 = 0;
pub const OUTPUT_TYPE_ESCROW: u8 = 1;
pub const OUTPUT_TYPE_ALIAS: u8 = 2;

/// An output of a transaction.
///
/// `output_type` selects the spending rules; `payload` carries the
/// type-specific data (20-byte hash for P2PKH, `AliasParams` for
/// alias, `EscrowParams` for escrow).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// How much AIIR this output pays, in atomic units.
    pub amount: Amount,
    /// Discriminator: 0 = P2PKH, 1 = escrow, 2 = alias.
    pub output_type: u8,
    /// Type-specific payload.  For P2PKH this is the 20-byte HASH160
    /// of the recipient's public key.
    pub payload: Vec<u8>,
}

/// Alias registration fee: 1 AIIR (provisional, protocol §20.5).
pub const ALIAS_REGISTRATION_FEE: Amount = Amount::from_atomic(100_000_000);

/// Alias validity period in blocks: ~1 year at 5 s/block (provisional).
pub const ALIAS_PERIOD: u32 = 6_300_000;

/// Grace period after expiry where only the owner can still spend.
pub const ALIAS_GRACE_PERIOD: u32 = 50_000;

/// Validate an alias name per protocol §20.3.
pub fn validate_alias_name(name: &[u8]) -> std::result::Result<(), &'static str> {
    if name.is_empty() || name.len() > 32 {
        return Err("alias name must be 1–32 bytes");
    }
    if !name[0].is_ascii_lowercase() {
        return Err("alias name must start with a letter");
    }
    let last = name[name.len() - 1];
    if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
        return Err("alias name must end with alphanumeric");
    }
    for window in name.windows(2) {
        let a = window[0];
        let b = window[1];
        if (a == b'-' || a == b'_') && (b == b'-' || b == b'_') {
            return Err("consecutive punctuation not allowed");
        }
    }
    for &ch in name {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != b'-' && ch != b'_' {
            return Err("invalid character in alias name");
        }
    }
    Ok(())
}

/// Parameters stored in the payload of an alias output (type 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasParams {
    /// Alias name (1–32 bytes, validated per protocol §20.3).
    pub name: Vec<u8>,
    /// HASH160 of the address this alias resolves to.
    pub target_hash: [u8; 20],
    /// HASH160 of the key that can update / renew / deregister.
    pub owner_hash: [u8; 20],
    /// Block height at which this alias expires.
    pub expiry_height: u32,
}

impl TxOut {
    /// Create a standard P2PKH output.
    pub fn p2pkh(amount: Amount, recipient_hash: [u8; 20]) -> Self {
        Self {
            amount,
            output_type: OUTPUT_TYPE_P2PKH,
            payload: recipient_hash.to_vec(),
        }
    }

    /// Create an alias registration output.
    pub fn alias(amount: Amount, params: &AliasParams) -> Self {
        Self {
            amount,
            output_type: OUTPUT_TYPE_ALIAS,
            payload: encoding::to_bytes(params).expect("AliasParams encodes"),
        }
    }

    /// Extract the 20-byte recipient hash from a P2PKH output.
    /// Returns `None` if this is not a P2PKH output or the payload
    /// is malformed.
    pub fn recipient_hash(&self) -> Option<[u8; 20]> {
        if self.output_type == OUTPUT_TYPE_P2PKH && self.payload.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&self.payload);
            Some(h)
        } else {
            None
        }
    }

    /// Parse alias parameters from an alias output.
    pub fn alias_params(&self) -> Option<AliasParams> {
        if self.output_type == OUTPUT_TYPE_ALIAS {
            encoding::from_bytes(&self.payload).ok()
        } else {
            None
        }
    }

    pub fn is_p2pkh(&self) -> bool {
        self.output_type == OUTPUT_TYPE_P2PKH
    }

    pub fn is_alias(&self) -> bool {
        self.output_type == OUTPUT_TYPE_ALIAS
    }
}

/// A complete BitAiir transaction.
///
/// Besides the usual Bitcoin-shaped fields, every non-coinbase
/// transaction carries an extra `pow_nonce` at the end. This is the
/// Hashcash-style anti-spam proof of work defined in protocol §6.7:
/// the sender mines `pow_nonce` until the transaction's double
/// SHA-256 (with `pow_nonce = 0` for that step) meets a target,
/// costing roughly two seconds of CPU time on a commodity laptop at
/// the minimum priority.  The field replaces the minimum-fee rule
/// that Bitcoin uses to throttle spam — BitAiir keeps fees optional
/// and prices abuse in sender-side CPU instead.
///
/// Senders who want their transaction to win ordering in the
/// mempool can declare a higher [`pow_priority`][Transaction::pow_priority]
/// and mine against a proportionally stricter target.  Validation
/// enforces `hash < min_target / pow_priority`, so a tx at priority
/// 5 must have done ~5× the CPU work of a tx at priority 1.  The
/// mempool orders entries by declared `pow_priority` descending,
/// with arrival order as the tiebreaker — priority is deterministic,
/// not probabilistic.
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
    /// Declared mempool priority: a multiplier of the minimum tx-PoW
    /// work.  `1` is the default and cheapest accepted; higher values
    /// require the sender to mine against a proportionally stricter
    /// target (`min_target / pow_priority`).  Validation rejects txs
    /// whose hash does not meet the declared target, so a tx can't
    /// falsely claim priority without paying the CPU cost.
    ///
    /// Coinbase transactions set this to `1` and are exempt from the
    /// check.  Like `pow_nonce`, this field is cleared during
    /// signature computation ([`Transaction::sighash`]) so changing
    /// it doesn't invalidate signatures.
    pub pow_priority: u64,
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
    /// encoding of the transaction with three modifications applied to
    /// a clone:
    ///
    /// - Every input's `signature` field is cleared to an empty `Vec`.
    /// - The `pow_nonce` field is cleared to `0`.
    /// - The `pow_priority` field is cleared to `0`.
    ///
    /// The `pubkey` fields are left intact so the recovered key can be
    /// matched against each input's declared public key.
    ///
    /// Clearing `signature` is the classic reason — a signature cannot
    /// sign over itself. Clearing `pow_nonce` and `pow_priority` is the
    /// BitAiir-specific twist: the anti-spam proof of work is mined
    /// **after** signing, because mining it requires the final
    /// transaction shape. If the sighash included the PoW fields, the
    /// sender would face a chicken-and-egg problem (sign → mine →
    /// invalidate signature → re-sign → re-mine → ...). Excluding them
    /// breaks the loop: the signature covers the "template" of the
    /// transaction, and the spam proof is a free-standing seal on top.
    pub fn sighash(&self) -> Hash256 {
        let mut template = self.clone();
        for input in &mut template.inputs {
            input.signature.clear();
        }
        template.pow_nonce = 0;
        template.pow_priority = 0;

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
