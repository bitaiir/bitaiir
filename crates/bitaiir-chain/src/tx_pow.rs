//! Transaction-level anti-spam proof of work (protocol §6.7).
//!
//! Every non-coinbase transaction must carry a `pow_nonce` such that
//! `double_sha256(tx_digest || nonce_le_bytes)` has a certain number
//! of leading zero bytes. This costs the sender roughly two seconds
//! of CPU time on a commodity laptop, making flood attacks
//! uneconomical without charging honest users money.

use bitaiir_crypto::hash::double_sha256;
use bitaiir_types::{Transaction, encoding};

/// Number of leading zero bytes required in the tx PoW hash.
/// Production: 3 bytes (1 in 16.7M, ~1.7s at 10M hash/s).
/// Tests: 1 byte (1 in 256, instant).
#[cfg(not(test))]
const LEADING_ZERO_BYTES: usize = 3;

#[cfg(test)]
const LEADING_ZERO_BYTES: usize = 1;

/// Check whether a hash meets the tx PoW target.
fn meets_target(hash: &[u8; 32]) -> bool {
    hash[..LEADING_ZERO_BYTES].iter().all(|&b| b == 0)
}

/// Compute the tx digest used as input to the PoW:
/// `double_sha256(canonical_encode(tx with pow_nonce = 0))`.
fn tx_digest(tx: &Transaction) -> [u8; 32] {
    let mut template = tx.clone();
    template.pow_nonce = 0;
    let bytes = encoding::to_bytes(&template).expect("Transaction encodes");
    double_sha256(&bytes)
}

/// Mine the anti-spam pow_nonce for a transaction. Mutates
/// `tx.pow_nonce` in place. Coinbase transactions should NOT call
/// this (they are exempt).
pub fn mine_tx_pow(tx: &mut Transaction) {
    let digest = tx_digest(tx);
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(&digest);

    for nonce in 0u64.. {
        data[32..].copy_from_slice(&nonce.to_le_bytes());
        let hash = double_sha256(&data);
        if meets_target(&hash) {
            tx.pow_nonce = nonce;
            return;
        }
    }
}

/// Validate that a transaction's pow_nonce satisfies the anti-spam
/// target. Returns `true` for coinbase transactions (they are
/// exempt per protocol §6.5).
pub fn validate_tx_pow(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return true;
    }

    let digest = tx_digest(tx);
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(&digest);
    data[32..].copy_from_slice(&tx.pow_nonce.to_le_bytes());
    let hash = double_sha256(&data);
    meets_target(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::sample_normal_tx;
    use bitaiir_types::{Hash256, OutPoint};

    #[test]
    fn mine_and_validate_round_trip() {
        use bitaiir_types::{Amount, TxIn, TxOut};

        let spend = OutPoint {
            txid: Hash256::from_bytes([0x11; 32]),
            vout: 0,
        };
        // Build a tx WITHOUT mining PoW to test the full flow.
        let mut tx = bitaiir_types::Transaction {
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
            pow_nonce: 0,
        };
        assert!(!validate_tx_pow(&tx), "zero pow_nonce should fail");

        mine_tx_pow(&mut tx);
        assert_ne!(tx.pow_nonce, 0, "nonce should have been set");
        assert!(validate_tx_pow(&tx), "mined nonce should validate");
    }

    #[test]
    fn coinbase_is_exempt() {
        let cb = crate::test_util::sample_coinbase(0);
        assert!(validate_tx_pow(&cb));
    }

    #[test]
    fn wrong_nonce_fails() {
        let spend = OutPoint {
            txid: Hash256::from_bytes([0x11; 32]),
            vout: 0,
        };
        let mut tx = sample_normal_tx(spend, 0);
        mine_tx_pow(&mut tx);
        tx.pow_nonce += 1; // corrupt the nonce
        assert!(!validate_tx_pow(&tx));
    }
}
