//! Transaction-level anti-spam proof of work (protocol §6.7).
//!
//! Every non-coinbase transaction must carry a `pow_nonce` such that
//! `double_sha256(tx_digest || nonce_le_bytes)`, interpreted as a
//! big-endian 256-bit integer, is strictly less than a 256-bit
//! target.  The minimum target ([`min_tx_pow_target`]) costs the
//! sender roughly two seconds of CPU on a commodity laptop — enough
//! to make flood attacks uneconomical without charging honest users
//! money.
//!
//! Senders who want their transaction to sit higher in the mempool's
//! priority order can mine against a **stricter** target (a smaller
//! number): [`mine_tx_pow_with_target`] accepts an arbitrary target
//! and mines until the hash satisfies it.  The mempool already
//! orders entries by `tx_pow_hash` ascending, so a tx with a lower
//! hash naturally sorts above less-worked txs.  Because validation
//! only checks against the minimum target, harder-mined transactions
//! remain valid — the extra work is voluntary and buys priority,
//! not any consensus advantage.

use bitaiir_crypto::hash::double_sha256;
use bitaiir_types::{Hash256, Transaction, encoding};
use primitive_types::U256;

/// Number of leading zero bits in the minimum anti-spam PoW target.
/// Production: 20 bits (1 in 1.05M, ~1s on a commodity laptop).
/// Tests: 8 bits (1 byte, 1 in 256, instant).
#[cfg(not(test))]
const MIN_TX_POW_LEADING_ZERO_BITS: u32 = 20;

#[cfg(test)]
const MIN_TX_POW_LEADING_ZERO_BITS: u32 = 8;

/// The minimum anti-spam PoW target.  A hash is accepted iff, as a
/// big-endian 256-bit integer, it is **strictly less than** this
/// target.
///
/// Concretely: `target = 2^(256 - MIN_LEADING_ZERO_BITS)`, which is
/// identical to requiring the first `MIN_LEADING_ZERO_BITS / 8`
/// bytes of the hash to be zero — the earlier "leading zero bytes"
/// formulation — but expressed numerically so callers can ask for
/// stricter targets that aren't whole-byte multiples.
pub fn min_tx_pow_target() -> U256 {
    U256::one() << (256 - MIN_TX_POW_LEADING_ZERO_BITS)
}

/// Check whether a 32-byte hash meets the given target: hash <
/// target when both are read as big-endian 256-bit unsigned ints.
fn meets_target(hash: &[u8; 32], target: U256) -> bool {
    U256::from_big_endian(hash) < target
}

/// Compute the tx digest used as input to the PoW:
/// `double_sha256(canonical_encode(tx with pow_nonce = 0 and
/// pow_priority = 0))`.
///
/// Both PoW fields are stripped so the mined hash is a function of
/// the "tx template" only — the same nonce-search run lets the
/// sender stop at different points depending on how hard they want
/// to mine (i.e. which priority they declare).  Validation then
/// reads the declared `pow_priority` from the tx and checks
/// `hash < min_target / declared_priority`.  This cleanly separates
/// "how much work was done" (the nonce relative to the digest) from
/// "what the sender claims" (the pow_priority field).
fn tx_digest(tx: &Transaction) -> [u8; 32] {
    let mut template = tx.clone();
    template.pow_nonce = 0;
    template.pow_priority = 0;
    let bytes = encoding::to_bytes(&template).expect("Transaction encodes");
    double_sha256(&bytes)
}

/// Mine the anti-spam pow_nonce for a transaction against the
/// **minimum** target (priority 1).  This is what honest users
/// call for normal sends — cheapest accepted by the network.
/// Sets both `tx.pow_priority = 1` and `tx.pow_nonce = N` where N
/// is the mined nonce.  Coinbase transactions should NOT call this
/// (they are exempt).
pub fn mine_tx_pow(tx: &mut Transaction) {
    mine_tx_pow_with_priority(tx, 1);
}

/// Mine at a declared priority level — a `u64` multiplier of work
/// relative to the minimum target.  Priority 1 matches the bare
/// [`mine_tx_pow`] call; priority 2 costs ~2× more CPU against a
/// target of `min_target / 2`; priority 10 costs ~10× CPU; etc.
///
/// Sets `tx.pow_priority = priority` and `tx.pow_nonce` to the
/// mined nonce.  Validators read `pow_priority` from the tx and
/// enforce that its hash meets `min_target / pow_priority`, so the
/// declared priority is verifiable — a sender cannot claim priority
/// 10 without actually doing ~10× the work.  Mempool ordering uses
/// the declared priority directly, which gives deterministic
/// sorting (higher priority always beats lower, with arrival order
/// as the tiebreaker on equal priority).
///
/// Priority of 0 is treated as 1.  The caller is responsible for
/// sanity-capping large values — priority 1000 is several hours
/// of CPU.
pub fn mine_tx_pow_with_priority(tx: &mut Transaction, priority: u64) {
    let priority = priority.max(1);
    tx.pow_priority = priority;
    let target = target_for_priority(priority);
    mine_tx_pow_with_target(tx, target);
}

/// Target a transaction must beat given a declared `pow_priority`.
/// Priority 1 returns `min_tx_pow_target`; higher priorities return
/// proportionally smaller (stricter) targets.
fn target_for_priority(priority: u64) -> U256 {
    let p = priority.max(1);
    min_tx_pow_target() / U256::from(p)
}

/// Mine the anti-spam pow_nonce against a **custom** target.  A
/// smaller target means more CPU time.  Used internally by
/// [`mine_tx_pow_with_priority`]; external callers should almost
/// always go through the priority-based API, which keeps
/// `tx.pow_priority` in sync with the target that was actually
/// honoured.
///
/// Callers that pass a target larger than [`min_tx_pow_target`]
/// would produce a nonce the network rejects — this is the caller's
/// responsibility; this function honours exactly the target passed.
pub fn mine_tx_pow_with_target(tx: &mut Transaction, target: U256) {
    let digest = tx_digest(tx);
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(&digest);

    for nonce in 0u64.. {
        data[32..].copy_from_slice(&nonce.to_le_bytes());
        let hash = double_sha256(&data);
        if meets_target(&hash, target) {
            tx.pow_nonce = nonce;
            return;
        }
    }
}

/// Validate that a transaction's pow_nonce satisfies its declared
/// priority's target.  The declared priority must be >= 1, and the
/// hash must beat `min_target / priority`.  Returns `true` for
/// coinbase transactions (they are exempt per protocol §6.5).
///
/// A transaction that declares `pow_priority = 10` but whose hash
/// only meets the minimum target (not `min / 10`) is rejected — so
/// the mempool can safely use the declared priority for ordering
/// without risking an unearned front-of-queue claim.
pub fn validate_tx_pow(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return true;
    }
    if tx.pow_priority == 0 {
        return false;
    }
    let hash = tx_pow_hash(tx);
    meets_target(hash.as_bytes(), target_for_priority(tx.pow_priority))
}

/// Compute the tx-level anti-spam PoW hash as a `Hash256`.
///
/// This is `double_sha256(tx_digest || pow_nonce_le)` — the same
/// hash `validate_tx_pow` checks against the minimum target.  It's
/// exposed publicly so the mempool can use the numeric value as a
/// priority key: a lower hash means more CPU spent mining, which
/// the sender volunteered for priority.
///
/// For coinbase transactions (exempt from tx-PoW) the hash is still
/// well-defined — callers that care about coinbase-vs-non-coinbase
/// semantics must check [`Transaction::is_coinbase`] separately.
pub fn tx_pow_hash(tx: &Transaction) -> Hash256 {
    let digest = tx_digest(tx);
    let mut data = [0u8; 40];
    data[..32].copy_from_slice(&digest);
    data[32..].copy_from_slice(&tx.pow_nonce.to_le_bytes());
    Hash256::from_bytes(double_sha256(&data))
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
            outputs: vec![TxOut::p2pkh(
                Amount::from_atomic(50 * 100_000_000),
                [0x99; 20],
            )],
            locktime: 0,
            pow_nonce: 0,
            pow_priority: 0,
        };
        assert!(!validate_tx_pow(&tx), "zero pow_priority should fail");

        mine_tx_pow(&mut tx);
        assert_eq!(tx.pow_priority, 1, "mine_tx_pow declares priority 1");
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

    #[test]
    fn priority_is_declared_and_enforced() {
        // A tx mined at priority 4 declares `pow_priority = 4` on
        // the tx itself; its hash is strictly below `min / 4`; and
        // validation against that declared priority passes.
        let spend = OutPoint {
            txid: Hash256::from_bytes([0x22; 32]),
            vout: 0,
        };
        let mut tx = sample_normal_tx(spend, 0);
        mine_tx_pow_with_priority(&mut tx, 4);

        assert_eq!(tx.pow_priority, 4);
        let hash = tx_pow_hash(&tx);
        let hash_u = U256::from_big_endian(hash.as_bytes());
        let declared_target = min_tx_pow_target() / U256::from(4u64);
        assert!(hash_u < declared_target);
        assert!(validate_tx_pow(&tx));

        // Over-claim: derive the smallest priority P whose target
        // `min / P` is **stricter** than our actual hash — that P
        // is a claim the sender did NOT earn.  Validation must
        // reject it.  Computing from the hash keeps the assertion
        // deterministic regardless of where in `[0, min/4]` the
        // mined hash happened to land.
        if !hash_u.is_zero() {
            let too_high = (min_tx_pow_target() / hash_u).low_u64().saturating_add(1);
            tx.pow_priority = too_high;
            assert!(
                !validate_tx_pow(&tx),
                "priority {too_high} should be too high for this hash",
            );
        }

        // Under-claim: any priority ≤ the one actually mined is
        // trivially satisfied (looser target).  Senders can always
        // under-report priority, they just can't over-report.
        tx.pow_priority = 1;
        assert!(validate_tx_pow(&tx));
    }

    #[test]
    fn min_target_matches_legacy_leading_zero_bytes() {
        // Sanity: the numeric min target is identical to "the
        // hash's top MIN_LEADING_ZERO_BITS bits are zero".
        // Tests use 8 bits = 1 byte.
        let target = min_tx_pow_target();
        let leading_bytes = (MIN_TX_POW_LEADING_ZERO_BITS / 8) as usize;

        // Build a hash whose first `leading_bytes` are zero and
        // the next byte is 1 — must meet target.
        let mut passing = [0u8; 32];
        passing[leading_bytes] = 1;
        assert!(meets_target(&passing, target));

        // Flip one of the leading bytes to non-zero — must fail.
        let mut failing = [0u8; 32];
        if leading_bytes > 0 {
            failing[leading_bytes - 1] = 1;
            assert!(!meets_target(&failing, target));
        }
    }
}
