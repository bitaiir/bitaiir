//! Hardcoded genesis block parameters.
//!
//! Every BitAiir node produces the exact same genesis block because
//! the inputs are fully deterministic: a fixed timestamp, a fixed
//! coinbase message, a burn address, and a linear nonce search from
//! zero. Two nodes that have never communicated will arrive at the
//! same genesis hash and can sync via P2P without needing to share
//! data directories.
//!
//! The genesis coinbase reward (100 AIIR) is paid to a provably
//! unspendable "nothing up my sleeve" burn address derived from
//! `hash160("BitAiir Genesis Burn")` on mainnet (or
//! `hash160("BitAiir Testnet Genesis Burn")` on testnet).  Anyone can
//! verify the derivation; nobody can spend the output because it
//! would require finding a secp256k1 keypair whose public key hashes
//! to the same 20-byte value — computationally infeasible.  This
//! ensures a fair launch: no one has a head start from the genesis
//! block.  The first spendable coins come from block 1.

use bitaiir_crypto::hash::hash160;
use bitaiir_types::{Block, BlockHeader, Hash256, Network, OutPoint, Transaction, TxIn, TxOut};

use crate::pow::aiir_pow;
use crate::subsidy::subsidy;
use crate::target::CompactTarget;

/// The coinbase message embedded in the mainnet genesis block,
/// permanently recorded on-chain.  The testnet genesis uses a
/// different message (see [`Network::genesis_message`]).
pub const GENESIS_MESSAGE: &str =
    "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos";

/// Fixed timestamp for the mainnet genesis block: 2026-03-29
/// 00:00:00 UTC.  Matches the date of the coinbase headline.
pub const GENESIS_TIMESTAMP: u64 = 1743206400;

/// The phrase whose `hash160` produces the mainnet genesis burn
/// address.  Testnet uses a different phrase — see
/// [`Network::genesis_burn_phrase`].
///
/// Verifiable by anyone: `RIPEMD160(SHA256("BitAiir Genesis Burn"))`
/// yields the `recipient_hash` in the genesis coinbase output.  No
/// private key was generated or discarded — the address is derived
/// purely from a public string, so the 100 AIIR are provably burned.
pub const GENESIS_BURN_PHRASE: &str = "BitAiir Genesis Burn";

/// Build and mine the genesis block for the currently-active network.
/// This is called ONCE on the first startup of a node. Because all
/// inputs are deterministic, every node on the same network produces
/// the same block with the same hash.  Mainnet and testnet produce
/// different genesis blocks (different burn phrase, message, and
/// timestamp) so the two chains are cryptographically separated.
///
/// Mining takes ~5–30 seconds with production Argon2id (64 MiB).
pub fn mine_genesis() -> Block {
    let network = Network::active();
    let recipient_hash = hash160(network.genesis_burn_phrase().as_bytes());
    let reward = subsidy(0);
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            signature: network.genesis_message().as_bytes().to_vec(),
            pubkey: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut::p2pkh(reward, recipient_hash)],
        locktime: 0,
        pow_nonce: 0,
        pow_priority: 1,
    };

    let merkle_root = coinbase.txid();
    let bits = CompactTarget::INITIAL.to_bits();

    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp: network.genesis_timestamp(),
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
