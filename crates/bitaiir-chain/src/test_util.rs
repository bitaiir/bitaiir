//! Shared test helpers for `bitaiir-chain`.
//!
//! This module is compiled only under `#[cfg(test)]`; it is not part
//! of the public API of the crate. Everything here is `pub(crate)`
//! so the sibling modules can share test builders.
//!
//! All transactions produced by these helpers are **properly signed**
//! using a fixed test private key. This means they pass the full
//! consensus validation path including ECDSA signature verification.

use bitaiir_crypto::hash::hash160;
use bitaiir_crypto::key::{PrivateKey, PublicKey};
use bitaiir_types::{Amount, Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};

use crate::target::CompactTarget;

/// A fixed test private key. Using a constant ensures every test run
/// produces the same addresses, signatures, and txids.
const TEST_KEY_BYTES: [u8; 32] = [0x01; 32];

/// Return the test private key.
pub(crate) fn test_private_key() -> PrivateKey {
    PrivateKey::from_bytes(&TEST_KEY_BYTES).expect("test key is a valid scalar")
}

/// Return the test public key (compressed).
pub(crate) fn test_public_key() -> PublicKey {
    test_private_key().public_key()
}

/// Return the HASH160 of the test public key — this is the
/// `recipient_hash` used in all test coinbase outputs and as the
/// "from" address in test normal transactions.
pub(crate) fn test_recipient_hash() -> [u8; 20] {
    hash160(&test_public_key().to_compressed())
}

/// Build a coinbase transaction for the block at `height`.
///
/// Pays 100 AIIR to the test address (`test_recipient_hash()`).
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
            recipient_hash: test_recipient_hash(),
        }],
        locktime: 0,
        pow_nonce: 0,
        pow_priority: 1,
    }
}

/// Build a properly signed non-coinbase transaction that spends a
/// single previous output and pays 50 AIIR back to the test address.
///
/// The signature is a real ECDSA compact signature over the
/// transaction's sighash, signed with `test_private_key()`. This
/// means the transaction will pass full consensus validation
/// including signature verification.
pub(crate) fn sample_normal_tx(spend: OutPoint, _pow_nonce: u64) -> Transaction {
    let privkey = test_private_key();
    let pubkey = test_public_key();

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: spend,
            signature: Vec::new(), // placeholder, filled below
            pubkey: pubkey.to_compressed().to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount: Amount::from_atomic(50 * 100_000_000),
            recipient_hash: test_recipient_hash(),
        }],
        locktime: 0,
        pow_nonce: 0,
        pow_priority: 1,
    };

    // Sign first (sighash clears pow_nonce internally, so order
    // doesn't matter, but signing before PoW is the natural flow).
    let sighash = tx.sighash();
    tx.inputs[0].signature = privkey.sign_digest(sighash.as_bytes());

    // Mine the anti-spam PoW nonce.
    crate::tx_pow::mine_tx_pow(&mut tx);

    tx
}

/// Grind the `nonce` field of a block header until the Proof-of-Aiir
/// hash meets the target encoded in `header.bits`.
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

/// Build a block extending `prev_hash` at `height`, with a mined
/// PoW nonce. Contains a single coinbase transaction paying to the
/// test address.
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
