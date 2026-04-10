//! `bitaiird` — BitAiir Core daemon.
//!
//! Mines blocks with Proof of Aiir (Argon2id), serves JSON-RPC, and
//! persists the chain to disk via redb. On restart the chain resumes
//! from where it left off — no re-mining the genesis.
//!
//! Usage:
//! ```text
//! cargo build --release --bin bitaiird --bin bitaiir-cli
//! ./target/release/bitaiird          # mines + serves RPC
//! ./target/release/bitaiir-cli getblockchaininfo
//! ./target/release/bitaiir-cli stop  # graceful shutdown
//! # restart — chain continues from disk
//! ./target/release/bitaiird
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bitaiir_chain::{Chain, Mempool, UtxoSet, create_test_genesis, subsidy, validate_block};
use bitaiir_crypto::hash::hash160;
use bitaiir_net::Peer;
use bitaiir_net::message::NetMessage;
use bitaiir_rpc::{BitaiirApiServer, BitaiirRpcImpl, NodeState, SharedState, Wallet};
use bitaiir_storage::Storage;
use bitaiir_types::OutPoint;
use clap::Parser;
use jsonrpsee::server::ServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

const GENESIS_MESSAGE: &str =
    "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos";

#[derive(Parser)]
#[command(name = "bitaiird", about = "BitAiir Core daemon", version)]
struct Args {
    /// RPC server bind address.
    #[arg(long, default_value = "127.0.0.1:8443")]
    rpc_addr: String,
    /// P2P listener bind address.
    #[arg(long, default_value = "127.0.0.1:8444")]
    p2p_addr: String,
    /// Data directory for chain storage.
    #[arg(long, default_value = "bitaiir_data")]
    data_dir: String,
    /// Disable mining (useful for a node that only syncs and serves RPC).
    #[arg(long, default_value_t = false)]
    no_mine: bool,
    /// Interactive mode: show a command prompt instead of mining table.
    #[arg(short, long, default_value_t = false)]
    interactive: bool,
}

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
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    println!();
    println!("  BitAiir Core v0.1.0");
    println!("  Proof of Aiir (SHA-256d + Argon2id)");
    println!("  Target block time: 5s | Retarget every 20 blocks");
    println!("  RPC server: http://{}", args.rpc_addr);
    println!("  P2P server: {}", args.p2p_addr);
    println!("  Data dir:   {}/", args.data_dir);
    println!();

    // --- Open storage ---------------------------------------------------- //

    let data_path = PathBuf::from(&args.data_dir);
    let storage = Arc::new(Storage::open(&data_path).expect("failed to open storage"));

    // --- Load or create chain -------------------------------------------- //

    let (chain, utxo, wallet, miner_recipient_hash) =
        if storage.has_chain().expect("storage check failed") {
            // Resume from disk.
            println!("  Loading chain from disk...");

            let (tip_height, tip_hash) = storage
                .load_chain_tip()
                .expect("load tip")
                .expect("has_chain was true");

            // Rebuild Chain by replaying blocks in order.
            let genesis = storage
                .load_block_at(0)
                .expect("load genesis")
                .expect("genesis must exist");
            let mut chain = Chain::with_genesis(genesis);

            for h in 1..=tip_height {
                let block = storage
                    .load_block_at(h)
                    .expect("load block")
                    .unwrap_or_else(|| panic!("block at height {h} missing from storage"));
                chain.push(block).expect("push stored block");
            }

            // Load UTXOs directly from storage.
            let utxo_map = storage.load_all_utxos().expect("load utxos");
            let mut utxo = UtxoSet::new();
            for (outpoint, txout) in utxo_map {
                utxo.insert(outpoint, txout);
            }

            // Load wallet keys.
            let wallet_keys = storage.load_wallet_keys().expect("load wallet keys");
            let mut wallet = Wallet::new();
            // Re-populate wallet from stored keys.
            for (addr, (privkey, pubkey)) in &wallet_keys {
                wallet.import_key(addr.clone(), privkey.clone(), *pubkey);
            }

            // Use the first wallet address as the miner address.
            let miner_hash = if let Some(addr) = wallet.addresses().first() {
                let (_, pk) = wallet.get_keys(addr).unwrap();
                hash160(&pk.to_compressed())
            } else {
                // No wallet keys stored — generate a new one.
                let addr = wallet.generate_address();
                let (privkey, pubkey) = wallet.get_keys(&addr).unwrap().clone();
                storage
                    .save_wallet_key(&addr, &privkey, &pubkey)
                    .expect("save wallet key");
                hash160(&pubkey.to_compressed())
            };

            println!(
                "  Loaded: height={tip_height}, tip={}",
                short_hash(&tip_hash.to_string())
            );
            println!("  UTXOs:  {}", utxo.len());
            println!("  Wallet: {} address(es)", wallet.addresses().len());
            println!();

            (chain, utxo, wallet, miner_hash)
        } else {
            // Fresh start: generate miner address + mine genesis.
            let mut wallet = Wallet::new();
            let miner_address = wallet.generate_address();
            let (privkey, pubkey) = wallet.get_keys(&miner_address).unwrap().clone();
            let miner_hash = hash160(&pubkey.to_compressed());

            // Persist the miner key immediately.
            storage
                .save_wallet_key(&miner_address, &privkey, &pubkey)
                .expect("save miner wallet key");

            println!("  Miner address: {miner_address}");
            println!();
            println!("  Mining genesis block...");
            let t = Instant::now();
            let genesis = create_test_genesis(miner_hash, unix_now(), GENESIS_MESSAGE);
            println!("  Genesis mined in {:.1}s", t.elapsed().as_secs_f64());
            println!(
                "  Hash:    {}",
                short_hash(&genesis.block_hash().to_string())
            );
            println!("  Reward:  {}", subsidy(0));
            let msg = String::from_utf8_lossy(&genesis.transactions[0].inputs[0].signature);
            println!("  Message: \"{msg}\"");
            println!();

            let mut utxo = UtxoSet::new();
            for tx in &genesis.transactions {
                utxo.apply_transaction(tx).unwrap();
            }

            // Persist genesis.
            storage
                .apply_block(0, &genesis, &[])
                .expect("persist genesis");

            let chain = Chain::with_genesis(genesis);
            (chain, utxo, wallet, miner_hash)
        };

    // --- Initialize shared state ----------------------------------------- //

    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        utxo,
        mempool: Mempool::new(),
        wallet,
        peer_senders: Vec::new(),
    }));

    let shutdown = Arc::new(AtomicBool::new(false));

    // --- Start RPC server ------------------------------------------------ //

    let rpc_impl = BitaiirRpcImpl {
        state: state.clone(),
        shutdown: shutdown.clone(),
        storage: storage.clone(),
    };

    let server = ServerBuilder::default()
        .build(&args.rpc_addr)
        .await
        .expect("failed to bind RPC server");

    let rpc_handle = server.start(rpc_impl.into_rpc());
    info!("RPC server listening on http://{}", args.rpc_addr);

    // --- Start P2P listener ---------------------------------------------- //

    let p2p_state = state.clone();
    let p2p_addr = args.p2p_addr.clone();
    let p2p_storage = storage.clone();
    tokio::spawn(async move {
        let storage = p2p_storage;
        let listener = match TcpListener::bind(&p2p_addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!("failed to bind P2P listener on {p2p_addr}: {e}");
                return;
            }
        };
        info!("P2P listener on {p2p_addr}");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let state = p2p_state.clone();
                    let _storage = storage.clone();
                    tokio::spawn(async move {
                        let our_height = {
                            let s = state.read().await;
                            s.chain.height()
                        };
                        let mut peer = Peer::new(stream, addr);
                        let version = match peer.handshake_inbound(our_height).await {
                            Ok(v) => {
                                info!(
                                    "inbound peer {} connected: agent={}, height={}",
                                    addr, v.user_agent, v.best_height,
                                );
                                v
                            }
                            Err(e) => {
                                warn!("inbound handshake with {addr} failed: {e}");
                                return;
                            }
                        };
                        let _ = version;

                        // Message loop: serve block requests.
                        loop {
                            match peer.receive().await {
                                Ok(NetMessage::GetBlocks(start_height)) => {
                                    info!("peer {addr} requests blocks from height {start_height}");
                                    let s = state.read().await;
                                    let tip = s.chain.height();
                                    for h in (start_height + 1)..=tip {
                                        if let Some(block) = s.chain.block_at(h) {
                                            let bytes = bitaiir_types::encoding::to_bytes(block)
                                                .expect("block encodes");
                                            if peer
                                                .send(&NetMessage::BlockData(bytes))
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                    }
                                    drop(s); // release lock before sending
                                    let _ = peer.send(&NetMessage::SyncDone).await;
                                    info!(
                                        "sent blocks {} to {} to peer {addr}",
                                        start_height + 1,
                                        tip
                                    );
                                }
                                Ok(NetMessage::TxData(bytes)) => {
                                    if let Ok(tx) = bitaiir_types::encoding::from_bytes::<
                                        bitaiir_types::Transaction,
                                    >(&bytes)
                                    {
                                        let txid = tx.txid();
                                        let mut s = state.write().await;
                                        if !s.mempool.contains(&txid) {
                                            s.mempool.add(tx);
                                            info!("received tx {txid} from inbound peer {addr}");
                                        }
                                    }
                                }
                                Ok(NetMessage::Ping(nonce)) => {
                                    let _ = peer.send(&NetMessage::Pong(nonce)).await;
                                }
                                Ok(_) => { /* ignore other messages */ }
                                Err(_) => {
                                    info!("peer {addr} disconnected");
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("P2P accept error: {e}");
                }
            }
        }
    });

    // --- Mining in background thread ------------------------------------- //

    if args.no_mine {
        info!("Mining disabled (--no-mine). Node will only sync and serve RPC.");
    }

    let mining_state = state.clone();
    let mining_shutdown = shutdown.clone();
    let mining_recipient = miner_recipient_hash;
    let do_mine = !args.no_mine;
    let interactive = args.interactive;
    let mining_storage = storage.clone();

    let mining_handle = tokio::task::spawn_blocking(move || {
        if !do_mine {
            // Just wait for shutdown signal.
            while !mining_shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            return;
        }
        macro_rules! row_fmt {
            () => {
                "  {:>6} | {:<15} | {:>20} | {:>6} | {:>6} | {:>5}"
            };
        }
        if !interactive {
            println!(
                row_fmt!(),
                "Height", "Hash", "Reward", "Nonce", "Time", "UTXOs",
            );
            println!("  {}", "-".repeat(74));
        }

        while !mining_shutdown.load(Ordering::Relaxed) {
            let timestamp = unix_now();

            // Snapshot (short write lock).
            let (prev_hash, next_height, bits, user_txs) = {
                let mut s = mining_state.blocking_write();
                let h = s.chain.height() + 1;
                let tip = s.chain.tip();
                let b = bitaiir_chain::required_bits(&s.chain, h);
                let txs = s.mempool.take_for_block(2000);
                (tip, h, b, txs)
            };

            // Mine (NO lock held).
            let start = Instant::now();
            let block = bitaiir_chain::mine_block_from_params(
                prev_hash,
                next_height,
                bits,
                user_txs,
                mining_recipient,
                timestamp,
            );
            let elapsed = start.elapsed();

            // Validate, commit, and persist (short write lock).
            {
                let mut s = mining_state.blocking_write();
                if let Err(e) = validate_block(&block, &s.chain, &s.utxo, timestamp + 1) {
                    warn!("self-mined block failed validation: {e}");
                    continue;
                }

                // Collect spent outpoints for storage.
                let spent: Vec<OutPoint> = block
                    .transactions
                    .iter()
                    .skip(1)
                    .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
                    .collect();

                if let Err(e) = s.chain.push(block.clone()) {
                    warn!("self-mined block failed push: {e}");
                    continue;
                }
                for tx in &block.transactions {
                    s.utxo.apply_transaction(tx).unwrap();
                }

                // Persist to disk.
                if let Err(e) = mining_storage.apply_block(next_height, &block, &spent) {
                    warn!("failed to persist block {next_height}: {e}");
                }
            }

            if !interactive {
                let reward = subsidy(next_height);
                println!(
                    row_fmt!(),
                    next_height,
                    short_hash(&block.block_hash().to_string()),
                    format!("{reward}"),
                    block.header.nonce,
                    format!("{:.1}s", elapsed.as_secs_f64()),
                    {
                        let s = mining_state.blocking_read();
                        s.utxo.len()
                    },
                );
            }
        }

        info!("Mining stopped.");
    });

    // --- Wait for shutdown / interactive REPL ----------------------------- //

    if args.interactive {
        run_repl(&args.rpc_addr, &shutdown).await;
    } else {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    info!("Shutting down...");
    rpc_handle.stop().expect("rpc handle stop");
    let _ = mining_handle.await;
    info!("Goodbye.");
}

/// Interactive command-line REPL. Reads commands from stdin and
/// dispatches them as RPC calls to the local server.
async fn run_repl(rpc_addr: &str, shutdown: &AtomicBool) {
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use std::io::Write;

    // Give the RPC server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let url = format!("http://{rpc_addr}");
    let client = match HttpClientBuilder::default().build(&url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to local RPC: {e}");
            return;
        }
    };

    println!();
    println!("  Type 'help' for available commands, 'exit' to quit.");
    println!();

    loop {
        print!("bitaiir> ");
        let _ = std::io::stdout().flush();

        let line = match read_stdin_line().await {
            Some(l) => l,
            None => break, // EOF / Ctrl+D
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "exit" || line == "quit" {
            break;
        }

        if line == "help" {
            println!("  Available commands:");
            println!("    getblockchaininfo              Show chain status");
            println!("    getblock <height>              Show block details");
            println!("    getnewaddress                  Generate a new address");
            println!("    getbalance <address>           Show address balance");
            println!("    sendtoaddress <address> <amt>  Send AIIR");
            println!("    getmempoolinfo                 Show mempool status");
            println!("    addpeer <ip:port>              Connect to a peer");
            println!("    stop                           Stop the daemon");
            println!("    help                           Show this help");
            println!("    exit / quit                    Exit interactive mode");
            println!();
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let cmd = parts[0];

        let result: Result<serde_json::Value, _> = match cmd {
            "getblockchaininfo" => client.request("getblockchaininfo", rpc_params![]).await,
            "getblock" => {
                let h: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                client.request("getblock", rpc_params![h]).await
            }
            "getnewaddress" => client.request("getnewaddress", rpc_params![]).await,
            "getbalance" => {
                let addr = parts.get(1).copied().unwrap_or("");
                client
                    .request("getbalance", rpc_params![addr.to_string()])
                    .await
            }
            "sendtoaddress" => {
                let addr = parts.get(1).copied().unwrap_or("");
                let amt: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                client
                    .request("sendtoaddress", rpc_params![addr.to_string(), amt])
                    .await
            }
            "getmempoolinfo" => client.request("getmempoolinfo", rpc_params![]).await,
            "addpeer" => {
                let addr = parts.get(1).copied().unwrap_or("");
                client
                    .request("addpeer", rpc_params![addr.to_string()])
                    .await
            }
            "stop" => {
                let _: std::result::Result<serde_json::Value, _> =
                    client.request("stop", rpc_params![]).await;
                println!("  Daemon stopping...");
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
            _ => {
                println!("  Unknown command: '{cmd}'. Type 'help' for available commands.");
                continue;
            }
        };

        match result {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            Err(e) => println!("  Error: {e}"),
        }
    }
}

/// Read one line from stdin inside an async context (uses a blocking
/// thread to avoid stalling the tokio runtime on Windows).
async fn read_stdin_line() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => Some(buf),
            Err(_) => None,
        }
    })
    .await
    .ok()
    .flatten()
}
