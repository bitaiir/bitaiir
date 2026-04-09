//! Shared test helpers for `bitaiir-chain`.
//!
//! This module is compiled only under `#[cfg(test)]`; it is not part
//! of the public API of the crate. Everything here is `pub(crate)`
//! so the sibling modules (`chain`, `utxo`, `mempool`) can share
//! builders for the small data shapes their tests need.
//!
//! The blocks and transactions these helpers produce are
//! *structurally* well-formed — correct field types, non-zero
//! pow_nonce on non-coinbase transactions, consistent txid/merkle
//! computations — but they are **not** valid under consensus.
//! Nothing in Phase 1b checks consensus validity, so the helpers do
//! not bother to satisfy rules that no test exercises yet.

use bitaiir_types::{Amount, Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};

use crate::target::CompactTarget;

/// Build a minimal coinbase transaction for the block at `height`.
///
/// The coinbase spends the null outpoint, has an empty pubkey, and
/// pays 100 AIIR to a fixed recipient hash. Its input signature
/// carries the little-endian bytes of the height as an extra-nonce
/// so that two coinbases from different heights have distinct txids.
pub(crate) fn sample_coinbase(height: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            signature: height.to_le_bytes().to_vec(),
            pubkey: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount: Amount::from_atomic(100 * 100_000_000),
            recipient_hash: [0x42; 20],
        }],
        locktime: 0,
        pow_nonce: 0,
    }
}

/// Build a minimal non-coinbase transaction that spends a single
/// previous output.
///
/// The fake signature and pubkey fields have the correct shape (64
/// bytes of signature, 33 bytes of compressed pubkey) so tests that
/// care about field lengths can pattern-match without surprises.
/// `pow_nonce` is passed in so callers can make otherwise-identical
/// transactions distinct.
pub(crate) fn sample_normal_tx(spend: OutPoint, pow_nonce: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: spend,
            signature: vec![0xaa; 64],
            pubkey: vec![0x02; 33],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount: Amount::from_atomic(50 * 100_000_000),
            recipient_hash: [0x99; 20],
        }],
        locktime: 0,
        pow_nonce,
    }
}

/// Build a minimal block that extends `prev_hash` at the given
/// `height`.
///
/// The block contains exactly one transaction, the coinbase, whose
/// txid becomes the merkle root (merkle-of-one is the identity).
/// The header uses the initial difficulty and a timestamp that
/// increases with height so two sample blocks never collide on
/// block hash.
pub(crate) fn sample_block(prev_hash: Hash256, height: u64) -> Block {
    let coinbase = sample_coinbase(height);
    let merkle_root = coinbase.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 1_700_000_000 + height,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: height as u32,
        },
        transactions: vec![coinbase],
    }
}
