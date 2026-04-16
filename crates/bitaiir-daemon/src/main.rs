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
use clap::Parser;
use jsonrpsee::server::ServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

mod config;
mod log;
mod peer_manager;
mod rpc_auth;
mod tui;

#[derive(Parser)]
#[command(name = "bitaiird", about = "BitAiir Core daemon", version)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "bitaiir.toml")]
    config: String,
    /// Run on the testnet network instead of mainnet.  Testnet uses
    /// different magic bytes, a different genesis block, faster
    /// coinbase maturity (10 blocks), and separate default ports
    /// (18443/18444) and data directory (`bitaiir_testnet_data`).
    #[arg(long)]
    testnet: bool,
    /// RPC server bind address.
    #[arg(long)]
    rpc_addr: Option<String>,
    /// P2P listener bind address.
    #[arg(long)]
    p2p_addr: Option<String>,
    /// Data directory for chain storage.
    #[arg(long)]
    data_dir: Option<String>,
    /// Enable mining on startup.
    #[arg(long)]
    mine: bool,
    /// Interactive mode.
    #[arg(short, long)]
    interactive: bool,
    /// Connect to a peer on startup (repeatable).
    #[arg(long = "connect", value_name = "HOST:PORT")]
    connect: Vec<String>,
    /// Number of parallel mining threads. [default: min(4, cores/2)]
    #[arg(long)]
    mining_threads: Option<usize>,
}

/// Resolved settings after merging CLI > config > defaults.
struct Settings {
    rpc_addr: String,
    p2p_addr: String,
    data_dir: String,
    mine: bool,
    interactive: bool,
    connect: Vec<String>,
    mining_threads: usize,
    max_mempool_bytes: usize,
}

impl Settings {
    /// Build resolved settings.  MUST be called *after*
    /// `Network::set_active` so that the network-dependent defaults
    /// (ports, data dir) pick up the correct values.
    fn from_args_and_config(args: &Args, cfg: &config::Config) -> Self {
        let rpc_addr = args
            .rpc_addr
            .clone()
            .or_else(|| cfg.network.rpc_addr.clone())
            .unwrap_or_else(config::default_rpc_addr);

        let p2p_addr = args
            .p2p_addr
            .clone()
            .or_else(|| cfg.network.p2p_addr.clone())
            .unwrap_or_else(config::default_p2p_addr);

        let data_dir = args
            .data_dir
            .clone()
            .or_else(|| cfg.storage.data_dir.clone())
            .unwrap_or_else(config::default_data_dir);

        let mine = args.mine || cfg.mining.enabled.unwrap_or(false);

        let interactive = args.interactive;

        let mut connect = args.connect.clone();
        if connect.is_empty() {
            if let Some(cfg_connect) = &cfg.network.connect {
                connect = cfg_connect.clone();
            }
        }

        let mining_threads = args.mining_threads.or(cfg.mining.threads).unwrap_or(0);

        let max_mempool_bytes = cfg
            .mempool
            .max_bytes
            .unwrap_or_else(config::default_max_mempool_bytes);

        Self {
            rpc_addr,
            p2p_addr,
            data_dir,
            mine,
            interactive,
            connect,
            mining_threads,
            max_mempool_bytes,
        }
    }
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

    // Load config file and merge with CLI flags.
    let config_path = std::path::Path::new(&args.config);
    config::write_default_config(config_path);
    let cfg = config::load_config(config_path);

    // Decide the active network *before* anything else reads
    // network-dependent constants (magic bytes, genesis parameters,
    // coinbase maturity, default ports, default data dir).  Network
    // is locked in for the lifetime of the process.
    let network = if args.testnet || cfg.network.testnet.unwrap_or(false) {
        bitaiir_types::Network::Testnet
    } else {
        bitaiir_types::Network::Mainnet
    };
    network.set_active();

    let args = Settings::from_args_and_config(&args, &cfg);

    // In TUI mode, skip the tracing subscriber: raw mode means stdout
    // output would corrupt the terminal. System events go through the
    // unified log module instead.
    if !args.interactive {
        tracing_subscriber::fmt()
            .with_target(false)
            .with_level(true)
            .init();
    }

    // Create the TUI events channel early so the unified log module
    // can send to the TUI from the very first banner line.
    let (log_tx, log_rx) = std::sync::mpsc::channel::<String>();
    let events_sender: Option<std::sync::mpsc::Sender<String>> = if args.interactive {
        Some(log_tx.clone())
    } else {
        None
    };

    // --- Startup banner ------------------------------------------------- //
    let ev = &events_sender;
    log::print_line("", ev);
    log::print_line("  BitAiir Core v0.1.0", ev);
    log::print_line(&format!("  Network:    {}", network.name()), ev);
    log::print_line("  Proof of Aiir (SHA-256d + Argon2id)", ev);
    log::print_line("  Target block time: 5s | Retarget every 20 blocks", ev);
    log::print_line(&format!("  P2P server: {}", args.p2p_addr), ev);
    log::print_line(&format!("  Data dir:   {}/", args.data_dir), ev);

    // --- Open storage ---------------------------------------------------- //

    let data_path = PathBuf::from(&args.data_dir);
    let storage = Arc::new(Storage::open(&data_path).expect("failed to open storage"));

    // --- Load or create chain -------------------------------------------- //

    let (chain, utxo, wallet, miner_recipient_hash) =
        if storage.has_chain().expect("storage check failed") {
            // Resume from disk.
            log::print_line("  Loading chain from disk...", ev);

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
                log::print_line(
                    &format!("  Wallet is encrypted ({} address(es)).", raw_keys.len()),
                    ev,
                );
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

            log::print_line(
                &format!(
                    "  Loaded: height={tip_height}, tip={}",
                    short_hash(&tip_hash.to_string())
                ),
                ev,
            );
            log::print_line(&format!("  UTXOs:  {}", utxo.len()), ev);
            log::print_line(
                &format!("  Wallet: {} address(es)", wallet.addresses().len()),
                ev,
            );
            log::print_line("", ev);

            (chain, utxo, wallet, miner_hash)
        } else {
            // Fresh start: mine the deterministic genesis block.
            // All nodes produce the exact same genesis (fixed timestamp,
            // fixed message, burn address) so P2P sync works between
            // nodes that never shared data.
            log::print_line("  Mining genesis block (first start)...", ev);
            let t = Instant::now();
            let genesis = mine_genesis();
            log::print_line(
                &format!("  Genesis mined in {:.1}s", t.elapsed().as_secs_f64()),
                ev,
            );
            log::print_line(
                &format!(
                    "  Hash:    {}",
                    short_hash(&genesis.block_hash().to_string())
                ),
                ev,
            );
            log::print_line(
                &format!("  Reward:  {} (burn address, unspendable)", subsidy(0)),
                ev,
            );
            let msg = String::from_utf8_lossy(&genesis.transactions[0].inputs[0].signature);
            log::print_line(&format!("  Message: \"{msg}\""), ev);
            log::print_line("", ev);

            let mut utxo = UtxoSet::new();
            let genesis_undo = utxo
                .apply_block_with_undo(&genesis, 0)
                .expect("genesis applies cleanly");

            // Persist genesis.  The undo record is empty (the genesis
            // coinbase has no previous input to restore) but we still
            // write a BlockUndo entry so `load_block_undo` works
            // uniformly for every stored block.
            storage
                .apply_block(0, &genesis, &genesis_undo)
                .expect("persist genesis");

            // Generate a miner address in the wallet for block 1+.
            let mut wallet = Wallet::new();
            let miner_address = wallet.generate_address();
            let (privkey, pubkey) = wallet.get_keys(&miner_address).unwrap().clone();
            let miner_hash = hash160(&pubkey.to_compressed());
            storage
                .save_wallet_key(&miner_address, &privkey, &pubkey)
                .expect("save miner wallet key");

            log::print_line(&format!("  Miner address: {miner_address}"), ev);
            log::print_line("", ev);

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
        mempool: Mempool::new(args.max_mempool_bytes),
        wallet,
        peers: Vec::new(),
        known_peers,
        wallet_encrypted,
        // Unencrypted wallets start unlocked; encrypted wallets start
        // locked — the user must call /walletpassphrase to unlock.
        wallet_unlocked: !wallet_encrypted,
        wallet_lock_at: 0,
        pending_spends: std::collections::HashSet::new(),
    }));

    let shutdown = Arc::new(AtomicBool::new(false));

    // Mining is controlled by this atomic flag.
    let mining_active = Arc::new(AtomicBool::new(args.mine));

    // --- Resolve RPC credentials ----------------------------------------- //
    //
    // Cookie file at `<data_dir>/.cookie` unless the operator put
    // explicit `user`/`password` in `bitaiir.toml`.  Either way,
    // every RPC call must carry an `Authorization: Basic <b64>`
    // header matching these credentials.
    let rpc_creds = rpc_auth::resolve_credentials(
        std::path::Path::new(&args.data_dir),
        cfg.rpc.user.as_deref(),
        cfg.rpc.password.as_deref(),
    )
    .expect("failed to prepare RPC credentials");
    match &rpc_creds.cookie_path {
        Some(path) => {
            log::log_info(&format!("RPC auth: cookie ({})", path.display()), ev);
        }
        None => {
            log::log_info("RPC auth: config credentials (rpc.user)", ev);
        }
    }

    // --- Start RPC server ------------------------------------------------ //

    let rpc_impl = BitaiirRpcImpl {
        state: state.clone(),
        shutdown: shutdown.clone(),
        mining_active: mining_active.clone(),
        storage: storage.clone(),
        events: events_sender.clone(),
    };

    // HTTP Basic auth middleware: every request must carry the
    // resolved credentials; anything else is rejected with 401.
    let auth_layer = tower_http::validate_request::ValidateRequestHeaderLayer::basic(
        &rpc_creds.user,
        &rpc_creds.password,
    );
    let http_middleware = tower::ServiceBuilder::new().layer(auth_layer);

    // If `rpc.allow_ip` is set, jsonrpsee binds on a random
    // loopback port and a filtering TCP proxy binds on the
    // configured public address.
    let allow_nets: Option<Vec<ipnet::IpNet>> = cfg.rpc.allow_ip.as_ref().map(|list| {
        list.iter()
            .filter_map(|s| {
                s.parse::<ipnet::IpNet>()
                    .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|e| {
                        log::log_warn(&format!("ignoring invalid allow_ip entry '{s}': {e}"), ev);
                        e
                    })
                    .ok()
            })
            .collect()
    });

    let rpc_bind_addr = if allow_nets.is_some() {
        "127.0.0.1:0".to_string()
    } else {
        args.rpc_addr.clone()
    };

    let server = ServerBuilder::default()
        .set_http_middleware(http_middleware)
        .build(&rpc_bind_addr)
        .await
        .expect("failed to bind RPC server");

    let rpc_local_addr = server.local_addr().expect("server has a local addr");
    let rpc_handle = server.start(rpc_impl.into_rpc());

    if let Some(nets) = allow_nets {
        let public_addr = args.rpc_addr.clone();
        let internal = rpc_local_addr;
        let net_strs: Vec<String> = nets.iter().map(ToString::to_string).collect();
        log::log_info(
            &format!(
                "RPC allow_ip: {} rule(s) [{}]",
                nets.len(),
                net_strs.join(", ")
            ),
            ev,
        );
        let proxy_events = events_sender.clone();
        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(&public_addr).await {
                Ok(l) => l,
                Err(e) => {
                    log::log_warn(
                        &format!("RPC allow_ip proxy: failed to bind {public_addr}: {e}"),
                        &proxy_events,
                    );
                    return;
                }
            };
            loop {
                match listener.accept().await {
                    Ok((mut client, addr)) => {
                        if !nets.iter().any(|net| net.contains(&addr.ip())) {
                            log::log_warn(
                                &format!("RPC: rejected connection from {addr} (not in allow_ip)"),
                                &proxy_events,
                            );
                            continue;
                        }
                        tokio::spawn(async move {
                            if let Ok(mut upstream) = tokio::net::TcpStream::connect(internal).await
                            {
                                let _ =
                                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                            }
                        });
                    }
                    Err(e) => {
                        log::log_warn(&format!("RPC proxy accept error: {e}"), &proxy_events);
                    }
                }
            }
        });
        log::log_info(
            &format!(
                "RPC server listening on http://{} (IP-filtered)",
                args.rpc_addr
            ),
            ev,
        );
    } else {
        log::log_info(
            &format!("RPC server listening on http://{}", args.rpc_addr),
            ev,
        );
    }

    log::log_info(&format!("P2P listener on {}", args.p2p_addr), ev);
    log::print_line("", ev);

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
                        // handles headers, blocks, txs, pings, AND
                        // addr gossip.
                        let (reader, writer, _) = peer.into_parts();
                        let peer_best_height = version.best_height;
                        peer_manager::run_gossip_loop(
                            reader,
                            writer,
                            tx_recv,
                            state,
                            storage,
                            events,
                            addr_key,
                            peer_best_height,
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

    if !args.mine {
        let hint = if args.interactive {
            "/mine-start"
        } else {
            "--mine"
        };
        log::log_info(&format!("Mining disabled (use {hint} to enable)"), ev);
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
        log::log_info(&format!("Mining enabled ({mining_threads} thread(s))"), ev);
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

                if let Err(e) = s.chain.push(block.clone()) {
                    warn!("self-mined block failed push: {e}");
                    continue;
                }
                // Apply the block's transactions to the UTXO set and
                // capture the undo record in a single pass.  The
                // undo record is then persisted atomically with the
                // block so a future reorg can reverse this block.
                let undo = match s.utxo.apply_block_with_undo(&block, next_height) {
                    Ok(u) => u,
                    Err(e) => {
                        warn!("self-mined block UTXO apply failed: {e}");
                        continue;
                    }
                };

                if let Err(e) = mining_storage.apply_block(next_height, &block, &undo) {
                    warn!("failed to persist block {next_height}: {e}");
                }

                // Broadcast the new block to all connected peers in
                // **compact** form (BIP 152 style).  Peers reconstruct
                // the full block from their mempool using the short
                // IDs; any tx they're missing they'll request via
                // `GetBlockTxn`.  Only the coinbase is prefilled — no
                // peer has it in mempool.  On a warm mempool this
                // shrinks new-block traffic from ~1 MB to tens of KiB.
                let nonce_salt: u64 = rand::random();
                let sip_key = bitaiir_net::compact::derive_sip_key(&block.header, nonce_salt);
                let short_ids: Vec<bitaiir_net::ShortId> = block
                    .transactions
                    .iter()
                    .skip(1) // coinbase is prefilled
                    .map(|tx| bitaiir_net::compact::short_id_for(&tx.txid(), &sip_key))
                    .collect();
                let prefilled = vec![(0u16, block.transactions[0].clone())];
                let compact_msg = bitaiir_net::message::NetMessage::CompactBlock(
                    bitaiir_net::compact::CompactBlockMsg {
                        header: block.header,
                        nonce_salt,
                        short_ids,
                        prefilled,
                    },
                );
                for peer in &mut s.peers {
                    let _ = peer.sender.try_send(compact_msg.clone());
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
        let repl_basic_token = rpc_creds.basic_token();
        let _ = tokio::task::spawn_blocking(move || {
            // Wait for RPC server to be ready.
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Err(e) = tui::run_repl(
                &repl_rpc_addr,
                &repl_basic_token,
                repl_log_tx,
                log_rx,
                repl_shutdown,
            ) {
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

    // Best-effort: remove the cookie file we wrote at startup so
    // stale credentials don't linger.  On crash the next daemon
    // startup just overwrites.
    if let Some(cookie_path) = &rpc_creds.cookie_path {
        if let Err(e) = rpc_auth::clear_cookie(cookie_path) {
            warn!(
                "failed to remove cookie file {}: {e}",
                cookie_path.display()
            );
        }
    }

    info!("Goodbye.");
}

// The old REPL code has been replaced by the TUI in tui.rs.
