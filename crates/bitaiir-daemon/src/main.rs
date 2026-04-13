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

use bitaiir_chain::{Chain, Mempool, UtxoSet, mine_genesis, subsidy, validate_block};
use bitaiir_crypto::hash::hash160;
use bitaiir_net::Peer;
use bitaiir_rpc::{BitaiirApiServer, BitaiirRpcImpl, NodeState, SharedState, Wallet};
use bitaiir_storage::Storage;
use bitaiir_types::OutPoint;
use clap::Parser;
use jsonrpsee::server::ServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

mod peer_manager;
mod tui;

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
    /// Enable mining on startup. Without this flag the node only
    /// syncs, serves RPC, and relays transactions — like bitcoind.
    #[arg(long, default_value_t = false)]
    mine: bool,
    /// Interactive mode: show a command prompt where you can type
    /// commands directly, including `mine start` / `mine stop`.
    #[arg(short, long, default_value_t = false)]
    interactive: bool,
    /// Connect to a peer on startup. Repeatable:
    /// `--connect 1.2.3.4:8444 --connect 5.6.7.8:8444`
    #[arg(long = "connect", value_name = "HOST:PORT")]
    connect: Vec<String>,
    /// Number of parallel mining threads (default: half the CPU cores).
    /// Each thread allocates ~64 MiB for Argon2id, so 4 threads use
    /// ~256 MiB of RAM during mining.
    #[arg(long, default_value_t = 0)]
    mining_threads: usize,
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

    // In TUI mode, skip the tracing subscriber: raw mode means stdout
    // output would corrupt the terminal. System events go through the
    // log channel instead.
    if !args.interactive {
        tracing_subscriber::fmt()
            .with_target(false)
            .with_level(true)
            .init();
    }

    if !args.interactive {
        println!();
        println!("  BitAiir Core v0.1.0");
        println!("  Proof of Aiir (SHA-256d + Argon2id)");
        println!("  Target block time: 5s | Retarget every 20 blocks");
        println!("  RPC server: http://{}", args.rpc_addr);
        println!("  P2P server: {}", args.p2p_addr);
        println!("  Data dir:   {}/", args.data_dir);
        println!();
    }

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

            // Check if the wallet is encrypted before trying to
            // import plaintext keys.
            let is_encrypted = storage
                .get_metadata("wallet_encrypted")
                .ok()
                .flatten()
                .map(|v| v == [1])
                .unwrap_or(false);

            if is_encrypted {
                // Wallet is encrypted: load raw entries to register
                // addresses and extract pubkeys (unencrypted tail).
                // The private keys stay encrypted until the user
                // calls /walletpassphrase.
                let raw_keys = storage.load_wallet_keys_raw().expect("load wallet keys");
                for (addr, bytes) in &raw_keys {
                    wallet.register_address(addr.clone());
                    // Encrypted: nonce(12) + ciphertext(48) + pubkey(33) = 93
                    // We can still read the pubkey from the tail.
                    if bytes.len() >= 93 {
                        // pubkey is at bytes[60..93] — NOT encrypted.
                        // We'll use it for the miner address if needed.
                    }
                }
                println!("  Wallet is encrypted ({} address(es)).", raw_keys.len());
                println!("  Use /walletpassphrase <pass> <timeout> to unlock.");
            } else {
                // Unencrypted: import all keys normally.
                for (addr, (privkey, pubkey)) in &wallet_keys {
                    wallet.import_key(addr.clone(), privkey.clone(), *pubkey);
                }
            }

            // Use the first wallet address as the miner address.
            let miner_hash = if let Some(addr) = wallet.addresses().first() {
                if let Some((_, pk)) = wallet.get_keys(addr) {
                    hash160(&pk.to_compressed())
                } else if is_encrypted {
                    // Wallet is locked — try to extract the pubkey
                    // from the encrypted raw entry.
                    let raw = storage.load_wallet_keys_raw().unwrap_or_default();
                    if let Some((_, bytes)) = raw.first() {
                        if bytes.len() >= 93 {
                            let mut pk_bytes = [0u8; 33];
                            pk_bytes.copy_from_slice(&bytes[60..93]);
                            hash160(&pk_bytes)
                        } else {
                            [0u8; 20] // fallback — won't mine correctly
                        }
                    } else {
                        [0u8; 20]
                    }
                } else {
                    [0u8; 20]
                }
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
            // Fresh start: mine the deterministic genesis block.
            // All nodes produce the exact same genesis (fixed timestamp,
            // fixed message, burn address) so P2P sync works between
            // nodes that never shared data.
            if !args.interactive {
                println!("  Mining genesis block (first start)...");
            }
            let t = Instant::now();
            let genesis = mine_genesis();
            if !args.interactive {
                println!("  Genesis mined in {:.1}s", t.elapsed().as_secs_f64());
                println!(
                    "  Hash:    {}",
                    short_hash(&genesis.block_hash().to_string())
                );
                println!("  Reward:  {} (burn address, unspendable)", subsidy(0));
                let msg = String::from_utf8_lossy(&genesis.transactions[0].inputs[0].signature);
                println!("  Message: \"{msg}\"");
                println!();
            }

            let mut utxo = UtxoSet::new();
            for tx in &genesis.transactions {
                utxo.apply_transaction(tx, 0).unwrap();
            }

            // Persist genesis.
            storage
                .apply_block(0, &genesis, &[])
                .expect("persist genesis");

            // Generate a miner address in the wallet for block 1+.
            let mut wallet = Wallet::new();
            let miner_address = wallet.generate_address();
            let (privkey, pubkey) = wallet.get_keys(&miner_address).unwrap().clone();
            let miner_hash = hash160(&pubkey.to_compressed());
            storage
                .save_wallet_key(&miner_address, &privkey, &pubkey)
                .expect("save miner wallet key");

            if !args.interactive {
                println!("  Miner address: {miner_address}");
                println!();
            }

            let chain = Chain::with_genesis(genesis);
            (chain, utxo, wallet, miner_hash)
        };

    // --- Initialize shared state ----------------------------------------- //

    // Load known peers from storage and merge with --connect and seeds.
    let mut known_peers = std::collections::HashMap::new();
    if let Ok(stored) = storage.load_known_peers() {
        for (addr, last_seen, failures, banned_until, source) in stored {
            known_peers.insert(
                addr.clone(),
                bitaiir_rpc::KnownPeer {
                    addr,
                    last_seen,
                    consecutive_failures: failures,
                    banned_until,
                    source: bitaiir_rpc::KnownPeer::source_from_byte(source),
                },
            );
        }
    }
    // --connect peers.
    for addr in &args.connect {
        known_peers
            .entry(addr.clone())
            .or_insert_with(|| bitaiir_rpc::KnownPeer {
                addr: addr.clone(),
                last_seen: 0,
                consecutive_failures: 0,
                banned_until: 0,
                source: bitaiir_rpc::PeerSource::Manual,
            });
    }
    // Seed nodes (fallback).
    for &addr in peer_manager::SEED_NODES {
        known_peers
            .entry(addr.to_string())
            .or_insert_with(|| bitaiir_rpc::KnownPeer {
                addr: addr.to_string(),
                last_seen: 0,
                consecutive_failures: 0,
                banned_until: 0,
                source: bitaiir_rpc::PeerSource::Seed,
            });
    }

    // Check if the wallet on disk is encrypted.
    let wallet_encrypted = storage
        .get_metadata("wallet_encrypted")
        .ok()
        .flatten()
        .map(|v| v == [1])
        .unwrap_or(false);

    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        utxo,
        mempool: Mempool::new(),
        wallet,
        peers: Vec::new(),
        known_peers,
        wallet_encrypted,
        // Unencrypted wallets start unlocked; encrypted wallets start
        // locked — the user must call /walletpassphrase to unlock.
        wallet_unlocked: !wallet_encrypted,
        wallet_lock_at: 0,
    }));

    let shutdown = Arc::new(AtomicBool::new(false));

    // Mining is controlled by this atomic flag.
    let mining_active = Arc::new(AtomicBool::new(args.mine));

    // Channel for routing mining + P2P + system events to the TUI.
    let (log_tx, log_rx) = std::sync::mpsc::channel::<String>();
    let events_sender = if args.interactive {
        Some(log_tx.clone())
    } else {
        None
    };

    // --- Start RPC server ------------------------------------------------ //

    let rpc_impl = BitaiirRpcImpl {
        state: state.clone(),
        shutdown: shutdown.clone(),
        mining_active: mining_active.clone(),
        storage: storage.clone(),
        events: events_sender.clone(),
    };

    let server = ServerBuilder::default()
        .build(&args.rpc_addr)
        .await
        .expect("failed to bind RPC server");

    let rpc_handle = server.start(rpc_impl.into_rpc());
    info!("RPC server listening on http://{}", args.rpc_addr);

    // --- Start P2P listener ---------------------------------------------- //
    //
    // Inbound connections: accept → handshake → register → delegate to
    // the shared `run_gossip_loop` (which also handles `GetAddr`/`Addr`
    // peer discovery messages).

    let p2p_state = state.clone();
    let p2p_addr = args.p2p_addr.clone();
    let p2p_storage = storage.clone();
    let p2p_events = events_sender.clone();
    tokio::spawn(async move {
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
                    let storage = p2p_storage.clone();
                    let events = p2p_events.clone();
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
                                if let Some(ev) = &events {
                                    let _ = ev.send(format!(
                                        "  inbound handshake with {addr} failed: {e}"
                                    ));
                                }
                                return;
                            }
                        };

                        let addr_key = addr.to_string();
                        let (tx_send, tx_recv) =
                            tokio::sync::mpsc::channel::<bitaiir_net::NetMessage>(100);
                        {
                            let mut s = state.write().await;
                            s.peers.push(bitaiir_rpc::ConnectedPeer {
                                addr: addr_key.clone(),
                                user_agent: version.user_agent.clone(),
                                best_height: version.best_height,
                                direction: bitaiir_rpc::PeerDirection::Inbound,
                                connected_at: std::time::Instant::now(),
                                sender: tx_send,
                            });
                        }
                        if let Some(ev) = &events {
                            let _ = ev.send(format!(
                                "  peer connected: {addr_key} (inbound, {}, height {})",
                                version.user_agent, version.best_height,
                            ));
                        }

                        // Delegate to the shared gossip loop which
                        // handles blocks, txs, pings, AND addr gossip.
                        let (reader, writer, _) = peer.into_parts();
                        peer_manager::run_gossip_loop(
                            reader, writer, tx_recv, state, storage, events, addr_key,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    warn!("P2P accept error: {e}");
                }
            }
        }
    });

    // --- Start PeerManager ----------------------------------------------- //
    //
    // The PeerManager periodically checks the outbound connection count
    // and tries to connect to known peers that are below the target.
    // It also handles `--connect` peers and auto-reconnects.

    let pm = peer_manager::PeerManager::new(
        state.clone(),
        storage.clone(),
        events_sender.clone(),
        shutdown.clone(),
        args.p2p_addr.clone(),
    );
    let _pm_handle = pm.spawn();

    // --- Mining in background thread ------------------------------------- //

    if !args.mine && !args.interactive {
        info!("Mining disabled. Use --mine flag to enable.");
    }

    let mining_state = state.clone();
    let mining_shutdown = shutdown.clone();
    let mining_active_ref = mining_active.clone();
    let mining_recipient = miner_recipient_hash;
    let is_interactive = args.interactive;
    let mining_storage = storage.clone();
    // Resolve mining thread count: 0 = auto (half of CPU cores, min 1).
    // Default: min(4, cores/2) — beyond 4 threads Argon2id saturates
    // the memory bus and adding threads hurts more than it helps.
    let mining_threads = if args.mining_threads > 0 {
        args.mining_threads
    } else {
        std::thread::available_parallelism()
            .map(|n| (n.get() / 2).clamp(1, 4))
            .unwrap_or(1)
    };

    if args.mine {
        info!("Mining enabled (--mine), {mining_threads} thread(s).");
    }

    // Clone so the TUI (spawned below) can still use `log_tx` after
    // the mining task takes ownership of its own clone.
    let mining_log_tx = log_tx.clone();

    let mining_handle = tokio::task::spawn_blocking(move || {
        let log_tx = mining_log_tx;
        let mut header_printed = false;

        macro_rules! row_fmt {
            () => {
                "  {:>6} | {:<15} | {:>20} | {:>6} | {:>6} | {:>5}"
            };
        }

        while !mining_shutdown.load(Ordering::Relaxed) {
            // If mining is not active, sleep briefly and recheck.
            if !mining_active_ref.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }

            // Print table header once when mining starts.
            if !header_printed {
                let h1 = format!(
                    row_fmt!(),
                    "Height", "Hash", "Reward", "Nonce", "Time", "UTXOs",
                );
                let h2 = format!("  {}", "-".repeat(74));
                if is_interactive {
                    let _ = log_tx.send(String::new());
                    let _ = log_tx.send(format!(
                        "  Mining started ({mining_threads} thread{}).",
                        if mining_threads == 1 { "" } else { "s" }
                    ));
                    let _ = log_tx.send(h1);
                    let _ = log_tx.send(h2);
                } else {
                    println!();
                    println!(
                        "  Mining started ({mining_threads} thread{}).",
                        if mining_threads == 1 { "" } else { "s" }
                    );
                    println!("{h1}");
                    println!("{h2}");
                }
                header_printed = true;
            }

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

            // Mine with N parallel threads (NO lock held).
            let start = Instant::now();
            let Some(block) = bitaiir_chain::mine_block_parallel(
                prev_hash,
                next_height,
                bits,
                user_txs,
                mining_recipient,
                timestamp,
                mining_threads,
                &mining_shutdown,
            ) else {
                // Mining was cancelled (daemon shutting down).
                break;
            };
            let elapsed = start.elapsed();

            // Validate, commit, and persist (short write lock).
            {
                let mut s = mining_state.blocking_write();
                if let Err(e) = validate_block(&block, &s.chain, &s.utxo, timestamp + 1) {
                    warn!("self-mined block failed validation: {e}");
                    continue;
                }

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
                    s.utxo.apply_transaction(tx, next_height).unwrap();
                }

                if let Err(e) = mining_storage.apply_block(next_height, &block, &spent) {
                    warn!("failed to persist block {next_height}: {e}");
                }

                // Broadcast the new block to all connected peers, and
                // optimistically bump their recorded `best_height` —
                // we don't get an ack but in the common case they
                // accept what we broadcast.
                let block_bytes = bitaiir_types::encoding::to_bytes(&block).expect("block encodes");
                for peer in &mut s.peers {
                    let _ = peer
                        .sender
                        .try_send(bitaiir_net::message::NetMessage::BlockData(
                            block_bytes.clone(),
                        ));
                    peer.best_height = peer.best_height.max(next_height);
                }
            }

            // Report the mined block.
            let reward = subsidy(next_height);
            let utxo_count = {
                let s = mining_state.blocking_read();
                s.utxo.len()
            };
            let line = format!(
                row_fmt!(),
                next_height,
                short_hash(&block.block_hash().to_string()),
                format!("{reward}"),
                block.header.nonce,
                format!("{:.1}s", elapsed.as_secs_f64()),
                utxo_count,
            );

            if is_interactive {
                let _ = log_tx.send(line);
            } else {
                println!("{line}");
            }

            // If mining was turned off while we were grinding this
            // block, emit the "stopped" message AFTER the block log
            // so the order in the TUI makes sense.
            if !mining_active_ref.load(Ordering::Relaxed) {
                if is_interactive {
                    let _ = log_tx.send("  Mining stopped.".into());
                    let _ = log_tx.send(String::new());
                }
                header_printed = false;
            }
        }

        info!("Mining thread exiting.");
    });

    // --- Wait for shutdown / interactive REPL ----------------------------- //

    if args.interactive {
        let repl_rpc_addr = args.rpc_addr.clone();
        let repl_shutdown = shutdown.clone();
        let repl_log_tx = log_tx.clone();
        let _ = tokio::task::spawn_blocking(move || {
            // Wait for RPC server to be ready.
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Err(e) = tui::run_repl(&repl_rpc_addr, repl_log_tx, log_rx, repl_shutdown) {
                eprintln!("REPL error: {e}");
            }
        })
        .await;
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

// The old REPL code has been replaced by the TUI in tui.rs.
