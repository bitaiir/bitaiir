//! Basic sanity tests for `bitaiir-types`.
//!
//! These cover the invariants every downstream crate relies on:
//!
//! - `Hash256` parses back from its own `Display` output.
//! - `Amount` arithmetic is checked and never silently wraps.
//! - Every protocol type round-trips through both JSON (`serde_json`) and
//!   canonical binary (`encoding::to_bytes` / `from_bytes`), so the shape
//!   we write is the shape we read back.
//! - `Transaction::txid` and `BlockHeader::block_hash` are stable: the
//!   same input always hashes to the same output.
//! - The merkle root agrees with a hand-computed reference for small
//!   fixed inputs.

use bitaiir_crypto::hash::double_sha256;
use bitaiir_types::{
    Amount, Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut, encoding, merkle_root,
};

// --- Hash256 ------------------------------------------------------------- //

#[test]
fn hash256_display_round_trip() {
    let h = Hash256::from_bytes([0xaa; 32]);
    let printed = h.to_string();
    assert_eq!(
        printed,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let parsed: Hash256 = printed.parse().expect("round trip");
    assert_eq!(parsed, h);
}

#[test]
fn hash256_zero_is_all_zero() {
    assert_eq!(Hash256::ZERO.as_bytes(), &[0u8; 32]);
}

#[test]
fn hash256_from_str_rejects_wrong_length() {
    let too_short = "deadbeef";
    assert!(too_short.parse::<Hash256>().is_err());
}

// --- Amount -------------------------------------------------------------- //

#[test]
fn amount_arithmetic_is_checked() {
    let a = Amount::from_atomic(100);
    let b = Amount::from_atomic(40);

    assert_eq!(a.checked_add(b), Some(Amount::from_atomic(140)));
    assert_eq!(a.checked_sub(b), Some(Amount::from_atomic(60)));

    // Underflow returns None.
    assert_eq!(b.checked_sub(a), None);

    // Overflow returns None.
    let huge = Amount::from_atomic(u64::MAX);
    assert_eq!(huge.checked_add(Amount::from_atomic(1)), None);
}

#[test]
fn amount_display_formats_with_eight_decimals() {
    let one_aiir = Amount::from_atomic(100_000_000);
    assert_eq!(one_aiir.to_string(), "1.00000000 AIIR");

    let half = Amount::from_atomic(50_000_000);
    assert_eq!(half.to_string(), "0.50000000 AIIR");

    let tiny = Amount::from_atomic(1);
    assert_eq!(tiny.to_string(), "0.00000001 AIIR");
}

// --- Round-trip helpers -------------------------------------------------- //

fn sample_transaction() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256::from_bytes([0x11; 32]),
                vout: 3,
            },
            signature: vec![0xaa, 0xbb, 0xcc],
            pubkey: vec![0x02; 33],
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOut {
                amount: Amount::from_atomic(21_000_000),
                recipient_hash: [0x42; 20],
            },
            TxOut {
                amount: Amount::from_atomic(79_000_000),
                recipient_hash: [0x99; 20],
            },
        ],
        locktime: 0,
    }
}

fn sample_block() -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_bytes([0x01; 32]),
            merkle_root: Hash256::from_bytes([0x02; 32]),
            timestamp: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 42,
        },
        transactions: vec![sample_transaction()],
    }
}

// --- JSON round trip ----------------------------------------------------- //

#[test]
fn transaction_json_round_trip() {
    let tx = sample_transaction();
    let json = serde_json::to_string(&tx).expect("serialize");
    let parsed: Transaction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, tx);
}

#[test]
fn block_json_round_trip() {
    let block = sample_block();
    let json = serde_json::to_string(&block).expect("serialize");
    let parsed: Block = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, block);
}

// --- Canonical binary round trip ----------------------------------------- //

#[test]
fn transaction_canonical_round_trip() {
    let tx = sample_transaction();
    let bytes = encoding::to_bytes(&tx).expect("encode");
    let parsed: Transaction = encoding::from_bytes(&bytes).expect("decode");
    assert_eq!(parsed, tx);
}

#[test]
fn block_header_canonical_round_trip() {
    let header = sample_block().header;
    let bytes = encoding::to_bytes(&header).expect("encode");
    let parsed: BlockHeader = encoding::from_bytes(&bytes).expect("decode");
    assert_eq!(parsed, header);
}

// --- txid / block_hash stability ----------------------------------------- //

#[test]
fn txid_is_deterministic() {
    let tx = sample_transaction();
    assert_eq!(tx.txid(), tx.txid());
}

#[test]
fn txid_changes_when_any_field_changes() {
    let tx = sample_transaction();
    let original = tx.txid();

    let mut mutated = tx.clone();
    mutated.locktime += 1;
    assert_ne!(mutated.txid(), original);

    let mut mutated = tx.clone();
    mutated.outputs[0].amount = Amount::from_atomic(99);
    assert_ne!(mutated.txid(), original);
}

#[test]
fn block_hash_is_deterministic() {
    let block = sample_block();
    assert_eq!(block.block_hash(), block.header.block_hash());
    assert_eq!(block.block_hash(), block.block_hash());
}

#[test]
fn coinbase_detection() {
    let mut tx = sample_transaction();
    assert!(!tx.is_coinbase());

    tx.inputs = vec![TxIn {
        prev_out: OutPoint::NULL,
        signature: vec![0xde, 0xad, 0xbe, 0xef],
        pubkey: vec![],
        sequence: u32::MAX,
    }];
    assert!(tx.is_coinbase());
}

// --- Merkle root --------------------------------------------------------- //

#[test]
fn merkle_root_empty_is_zero() {
    assert_eq!(merkle_root(&[]), Hash256::ZERO);
}

#[test]
fn merkle_root_single_is_identity() {
    let h = Hash256::from_bytes([0x7f; 32]);
    assert_eq!(merkle_root(&[h]), h);
}

#[test]
fn merkle_root_two_matches_manual() {
    let a = Hash256::from_bytes([0xaa; 32]);
    let b = Hash256::from_bytes([0xbb; 32]);

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a.as_bytes());
    buf[32..].copy_from_slice(b.as_bytes());
    let expected = Hash256::from_bytes(double_sha256(&buf));

    assert_eq!(merkle_root(&[a, b]), expected);
}

#[test]
fn merkle_root_three_duplicates_last() {
    // With three inputs, Bitcoin-style merkle pads the last one. The
    // first level becomes: hash(a || b), hash(c || c). The root then is:
    // hash(hash(a || b) || hash(c || c)).
    let a = Hash256::from_bytes([0x11; 32]);
    let b = Hash256::from_bytes([0x22; 32]);
    let c = Hash256::from_bytes([0x33; 32]);

    let mut ab_buf = [0u8; 64];
    ab_buf[..32].copy_from_slice(a.as_bytes());
    ab_buf[32..].copy_from_slice(b.as_bytes());
    let ab = double_sha256(&ab_buf);

    let mut cc_buf = [0u8; 64];
    cc_buf[..32].copy_from_slice(c.as_bytes());
    cc_buf[32..].copy_from_slice(c.as_bytes());
    let cc = double_sha256(&cc_buf);

    let mut final_buf = [0u8; 64];
    final_buf[..32].copy_from_slice(&ab);
    final_buf[32..].copy_from_slice(&cc);
    let expected = Hash256::from_bytes(double_sha256(&final_buf));

    assert_eq!(merkle_root(&[a, b, c]), expected);
}

#[test]
fn block_compute_merkle_root_matches_single_tx() {
    let block = sample_block();
    // Single-transaction block: merkle root equals the txid.
    assert_eq!(block.compute_merkle_root(), block.transactions[0].txid());
}
