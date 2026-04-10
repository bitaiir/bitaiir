//! `bitaiird` — BitAiir Core daemon.
//!
//! Phase C2: an async daemon that mines blocks in a background thread
//! and serves a JSON-RPC interface so `bitaiir-cli` (and any other
//! tooling) can query the chain state.
//!
//! Usage:
//!
//! ```text
//! cargo build --release --bin bitaiird
//! ./target/release/bitaiird
//!
//! # In another terminal:
//! cargo run --release --bin bitaiir-cli -- getblockchaininfo
//! cargo run --release --bin bitaiir-cli -- stop
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bitaiir_chain::{
    Chain, Mempool, UtxoSet, create_test_genesis, mine_block, subsidy, validate_block,
};
use bitaiir_rpc::{BitaiirApiServer, BitaiirRpcImpl, NodeState, SharedState};
use jsonrpsee::server::ServerBuilder;
use tokio::sync::RwLock;
use tracing::{info, warn};

const MINER_RECIPIENT: [u8; 20] = [0x42; 20];
const GENESIS_MESSAGE: &str =
    "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos";
const RPC_ADDR: &str = "127.0.0.1:8443";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs()
}

fn short_hash(hex: &str) -> String {
    if hex.len() <= 14 {
        return hex.to_string();
    }
    format!("{}...{}", &hex[..6], &hex[hex.len() - 6..])
}

#[tokio::main]
async fn main() {
    // --- Logging --------------------------------------------------------- //

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // --- Banner ---------------------------------------------------------- //

    println!();
    println!("  BitAiir Core v0.1.0");
    println!("  Proof of Aiir (SHA-256d + Argon2id)");
    println!("  Target block time: 5s | Retarget every 20 blocks");
    println!("  RPC server: http://{RPC_ADDR}");
    println!();

    // --- Genesis --------------------------------------------------------- //

    println!("  Mining genesis block...");
    let genesis_start = Instant::now();
    let genesis = create_test_genesis(MINER_RECIPIENT, unix_now(), GENESIS_MESSAGE);
    let genesis_elapsed = genesis_start.elapsed();

    let embedded_msg = String::from_utf8_lossy(&genesis.transactions[0].inputs[0].signature);
    println!("  Genesis mined in {:.1}s", genesis_elapsed.as_secs_f64());
    println!(
        "  Hash:    {}",
        short_hash(&genesis.block_hash().to_string())
    );
    println!("  Reward:  {}", subsidy(0));
    println!("  Message: \"{}\"", embedded_msg);
    println!();

    // --- Initialize shared state ----------------------------------------- //

    let mut utxo = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo.apply_transaction(tx).unwrap();
    }

    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain: Chain::with_genesis(genesis),
        utxo,
    }));

    let shutdown = Arc::new(AtomicBool::new(false));

    // --- Start RPC server ------------------------------------------------ //

    let rpc_impl = BitaiirRpcImpl {
        state: state.clone(),
        shutdown: shutdown.clone(),
    };

    let server = ServerBuilder::default()
        .build(RPC_ADDR)
        .await
        .expect("failed to bind RPC server");

    let rpc_handle = server.start(rpc_impl.into_rpc());
    info!("RPC server listening on http://{RPC_ADDR}");

    // --- Mining in background thread ------------------------------------- //

    let mining_state = state.clone();
    let mining_shutdown = shutdown.clone();

    let mining_handle = tokio::task::spawn_blocking(move || {
        // Table header (printed once).
        macro_rules! row_fmt {
            () => {
                "  {:>6} | {:<15} | {:>20} | {:>6} | {:>6} | {:>5}"
            };
        }
        println!(
            row_fmt!(),
            "Height", "Hash", "Reward", "Nonce", "Time", "UTXOs",
        );
        println!("  {}", "-".repeat(74));

        let mut mempool = Mempool::new();

        while !mining_shutdown.load(Ordering::Relaxed) {
            // Read current state to prepare mining.
            let (tip, height, timestamp) = {
                let s = mining_state.blocking_read();
                (s.chain.tip(), s.chain.height() + 1, unix_now())
            };
            let _ = tip; // used implicitly by mine_block reading chain

            // Mine (CPU-heavy, runs in the blocking thread pool).
            let start = Instant::now();
            let block = {
                let s = mining_state.blocking_read();
                mine_block(&s.chain, &mut mempool, MINER_RECIPIENT, timestamp)
            };
            let elapsed = start.elapsed();

            // Validate and commit under write lock.
            {
                let mut s = mining_state.blocking_write();
                if let Err(e) = validate_block(&block, &s.chain, &s.utxo, timestamp + 1) {
                    warn!("self-mined block failed validation: {e}");
                    continue;
                }
                if let Err(e) = s.chain.push(block.clone()) {
                    warn!("self-mined block failed push: {e}");
                    continue;
                }
                for tx in &block.transactions {
                    s.utxo.apply_transaction(tx).unwrap();
                }
            }

            // Print progress (state is unlocked now).
            let block_hash = block.block_hash().to_string();
            let reward = subsidy(height);
            println!(
                row_fmt!(),
                height,
                short_hash(&block_hash),
                format!("{reward}"),
                block.header.nonce,
                format!("{:.1}s", elapsed.as_secs_f64()),
                {
                    let s = mining_state.blocking_read();
                    s.utxo.len()
                },
            );
        }

        info!("Mining stopped.");
    });

    // --- Wait for shutdown ----------------------------------------------- //

    // Poll the shutdown flag. When `stop` RPC is called, the flag is
    // set and we break out.
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }

    info!("Shutting down...");
    rpc_handle.stop().expect("rpc handle stop");
    // The mining thread will observe the shutdown flag and exit.
    let _ = mining_handle.await;
    info!("Goodbye.");
}
