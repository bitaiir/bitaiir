//! Hardcoded genesis block parameters.
//!
//! Every BitAiir node produces the exact same genesis block because
//! the inputs are fully deterministic: a fixed timestamp, a fixed
//! coinbase message, a burn address, and a linear nonce search from
//! zero. Two nodes that have never communicated will arrive at the
//! same genesis hash and can sync via P2P without needing to share
//! data directories.
//!
//! The genesis coinbase reward (100 AIIR) is paid to a burn address
//! (`[0x00; 20]`) and is unspendable. This ensures a fair launch:
//! no one has a head start from the genesis block. The first
//! spendable coins come from block 1.

use bitaiir_types::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};

use crate::pow::aiir_pow;
use crate::subsidy::subsidy;
use crate::target::CompactTarget;

/// The coinbase message embedded in the genesis block, permanently
/// recorded on-chain.
pub const GENESIS_MESSAGE: &str =
    "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos";

/// Fixed timestamp for the genesis block: 2026-03-29 00:00:00 UTC.
/// Matches the date of the coinbase headline.
pub const GENESIS_TIMESTAMP: u64 = 1743206400;

/// The genesis coinbase pays to a burn address. These 100 AIIR are
/// unspendable — nobody holds the private key for the all-zero hash.
pub const GENESIS_RECIPIENT_HASH: [u8; 20] = [0u8; 20];

/// Build and mine the genesis block. This is called ONCE on the
/// first startup of a node. Because all inputs are deterministic,
/// every node produces the same block with the same hash.
///
/// Mining takes ~5–30 seconds with production Argon2id (64 MiB).
pub fn mine_genesis() -> Block {
    let reward = subsidy(0);
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            signature: GENESIS_MESSAGE.as_bytes().to_vec(),
            pubkey: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount: reward,
            recipient_hash: GENESIS_RECIPIENT_HASH,
        }],
        locktime: 0,
        pow_nonce: 0,
    };

    let merkle_root = coinbase.txid();
    let bits = CompactTarget::INITIAL.to_bits();

    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp: GENESIS_TIMESTAMP,
        bits,
        nonce: 0,
    };

    // Mine: grind nonce until Proof of Aiir meets the target.
    let target = CompactTarget::INITIAL;
    loop {
        let pow_hash = aiir_pow(&header);
        if target.hash_meets_target(pow_hash.as_bytes()) {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    Block {
        header,
        transactions: vec![coinbase],
    }
}
