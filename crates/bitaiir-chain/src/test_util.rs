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

/// Grind the `nonce` field of a block header until the
/// Proof-of-Aiir hash meets the target encoded in `header.bits`.
///
/// With the initial difficulty (`CompactTarget::INITIAL`), roughly
/// one in 256 nonces is valid, so this terminates in under a
/// millisecond. Panics if the target is structurally invalid.
pub(crate) fn mine_test_nonce(header: &mut BlockHeader) {
    let target = CompactTarget::from_bits(header.bits);
    loop {
        let pow_hash = crate::pow::aiir_pow(header);
        if target.hash_meets_target(pow_hash.as_bytes()) {
            return;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// Build a minimal block that extends `prev_hash` at the given
/// `height`, with a valid Proof-of-Aiir nonce.
///
/// The block contains exactly one transaction, the coinbase, whose
/// txid becomes the merkle root (merkle-of-one is the identity).
/// The header uses the initial difficulty and a timestamp that
/// increases with height so two sample blocks never collide on
/// block hash. The nonce is mined by [`mine_test_nonce`].
pub(crate) fn sample_block(prev_hash: Hash256, height: u64) -> Block {
    let coinbase = sample_coinbase(height);
    let merkle_root = coinbase.txid();
    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp: 1_700_000_000 + height,
        bits: CompactTarget::INITIAL.to_bits(),
        nonce: 0,
    };
    mine_test_nonce(&mut header);
    Block {
        header,
        transactions: vec![coinbase],
    }
}
