//! `bitaiird` — BitAiir Core daemon.
//!
//! Phase C1: a minimal mining daemon that creates a test genesis,
//! mines blocks in a loop, validates each one, and prints progress
//! to stdout. No RPC, no P2P, no persistence — just a live
//! demonstration that the entire consensus pipeline works end-to-end
//! with the real Proof-of-Aiir algorithm (Argon2id).
//!
//! Phase C2 will layer an async runtime (tokio), a JSON-RPC server,
//! and a CLI client on top of this core loop.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitaiir_chain::{
    Chain, Mempool, UtxoSet, create_test_genesis, mine_block, subsidy, validate_block,
};

/// Fixed test miner address (HASH160). In a real daemon this would
/// come from the wallet or from a `--address` CLI flag.
const MINER_RECIPIENT: [u8; 20] = [0x42; 20];

/// The message embedded in the genesis block's coinbase transaction,
/// permanently recorded on-chain. Follows Bitcoin's tradition of
/// embedding a headline or marker string to prove the block's creation
/// date and document the project's intent.
const GENESIS_MESSAGE: &str =
    "BitAiir/10-Apr-2026/The beginning of a new decentralized payment system";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs()
}

fn main() {
    // --- Banner ---------------------------------------------------------- //

    println!();
    println!("  BitAiir Core v0.1.0");
    println!("  Proof of Aiir (SHA-256d + Argon2id)");
    println!("  Target block time: 5s | Retarget every 20 blocks");
    println!();

    // --- Genesis --------------------------------------------------------- //

    println!("  Mining genesis block...");
    let genesis_start = Instant::now();
    let genesis = create_test_genesis(MINER_RECIPIENT, unix_now(), GENESIS_MESSAGE);
    let genesis_elapsed = genesis_start.elapsed();
    let genesis_hash = genesis.block_hash();

    // Extract the coinbase message back from the genesis to display it.
    let embedded_msg = String::from_utf8_lossy(&genesis.transactions[0].inputs[0].signature);

    println!("  Genesis mined in {:.1}s", genesis_elapsed.as_secs_f64());
    println!("  Hash:    {}", short_hash(&genesis_hash.to_string()));
    println!("  Reward:  {}", subsidy(0));
    println!("  Message: \"{}\"", embedded_msg);
    println!();

    // --- Initialize state ------------------------------------------------ //

    let mut chain = Chain::with_genesis(genesis.clone());
    let mut utxo = UtxoSet::new();
    let mut mempool = Mempool::new();

    for tx in &genesis.transactions {
        utxo.apply_transaction(tx).unwrap();
    }

    // --- Mining loop ----------------------------------------------------- //

    println!(
        "  {:<7} | {:<15} | {:<22} | {:>6} | {:>7} | {:>5}",
        "Height", "Hash", "Reward", "Nonce", "Time", "UTXOs",
    );
    println!("  {}", "-".repeat(78));

    loop {
        let height = chain.height() + 1;
        let timestamp = unix_now();

        let start = Instant::now();
        let block = mine_block(&chain, &mut mempool, MINER_RECIPIENT, timestamp);
        let elapsed = start.elapsed();

        // Validate (should always pass for our own mined blocks).
        validate_block(&block, &chain, &utxo, timestamp + 1)
            .expect("self-mined block must be valid");

        // Commit to chain state.
        chain
            .push(block.clone())
            .expect("validated block must push");

        for tx in &block.transactions {
            utxo.apply_transaction(tx).unwrap();
        }

        // Print progress.
        let block_hash = block.block_hash().to_string();
        let reward = subsidy(height);
        println!(
            "  {:<7} | {:<15} | {:<22} | {:>6} | {:>6.1}s | {:>5}",
            height,
            short_hash(&block_hash),
            reward,
            block.header.nonce,
            elapsed.as_secs_f64(),
            utxo.len(),
        );
    }
}

/// Truncate a hex hash to the first and last 6 characters with an
/// ellipsis in the middle, for compact display.
fn short_hash(hex: &str) -> String {
    if hex.len() <= 14 {
        return hex.to_string();
    }
    format!("{}...{}", &hex[..6], &hex[hex.len() - 6..])
}
