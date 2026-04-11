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
use bitaiir_net::message::NetMessage;
use bitaiir_rpc::{BitaiirApiServer, BitaiirRpcImpl, NodeState, SharedState, Wallet};
use bitaiir_storage::Storage;
use bitaiir_types::OutPoint;
use clap::Parser;
use jsonrpsee::server::ServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

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

    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        utxo,
        mempool: Mempool::new(),
        wallet,
        peers: Vec::new(),
    }));

    let shutdown = Arc::new(AtomicBool::new(false));

    // Mining is controlled by this atomic flag.
    let mining_active = Arc::new(AtomicBool::new(args.mine));

    // Channel for routing mining + P2P + system events to the TUI.
    // Created here so both the RPC layer and the P2P listener can
    // share clones of the sender.
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
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

                        // Register the inbound peer.  We keep the
                        // RECEIVER half of the broadcast channel below
                        // so newly-mined blocks and user transactions
                        // actually reach this connection.
                        let addr_key = addr.to_string();
                        let (tx_send, mut tx_recv) =
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

                        // Split peer into reader/writer so we can
                        // multiplex incoming frames with outgoing
                        // broadcasts via `tokio::select!`.
                        let (mut reader, mut writer, _peer_addr) = peer.into_parts();

                        loop {
                            tokio::select! {
                                // Outgoing: relay mined blocks / mempool txs to this peer.
                                msg = tx_recv.recv() => {
                                    let Some(m) = msg else { break };
                                    let payload = m.to_payload();
                                    let frame = bitaiir_net::protocol::frame_message(
                                        m.command(),
                                        &payload,
                                    );
                                    if writer.write_all(&frame).await.is_err() {
                                        break;
                                    }
                                    if writer.flush().await.is_err() {
                                        break;
                                    }
                                }

                                // Incoming: read one framed message.
                                result = async {
                                    let mut header_buf =
                                        [0u8; bitaiir_net::protocol::HEADER_SIZE];
                                    reader.read_exact(&mut header_buf).await?;
                                    let header =
                                        bitaiir_net::protocol::parse_header(&header_buf)
                                            .ok_or_else(|| std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                "bad magic",
                                            ))?;
                                    let mut payload = vec![0u8; header.payload_len as usize];
                                    if !payload.is_empty() {
                                        reader.read_exact(&mut payload).await?;
                                    }
                                    Ok::<_, std::io::Error>(
                                        bitaiir_net::NetMessage::from_payload(
                                            &header.command,
                                            &payload,
                                        ),
                                    )
                                } => {
                                    match result {
                                        Ok(Some(NetMessage::GetBlocks(start_height))) => {
                                            info!("peer {addr} requests blocks from height {start_height}");
                                            // Snapshot blocks under the lock,
                                            // then write them out without holding it.
                                            let to_send: Vec<Vec<u8>> = {
                                                let s = state.read().await;
                                                let tip = s.chain.height();
                                                (start_height + 1..=tip)
                                                    .filter_map(|h| {
                                                        s.chain.block_at(h).map(|b| {
                                                            bitaiir_types::encoding::to_bytes(b)
                                                                .expect("block encodes")
                                                        })
                                                    })
                                                    .collect()
                                            };
                                            let count = to_send.len();
                                            let mut ok = true;
                                            for bytes in to_send {
                                                let m = NetMessage::BlockData(bytes);
                                                let payload = m.to_payload();
                                                let frame = bitaiir_net::protocol::frame_message(
                                                    m.command(),
                                                    &payload,
                                                );
                                                if writer.write_all(&frame).await.is_err() {
                                                    ok = false;
                                                    break;
                                                }
                                                if writer.flush().await.is_err() {
                                                    ok = false;
                                                    break;
                                                }
                                            }
                                            if ok {
                                                let done = NetMessage::SyncDone;
                                                let payload = done.to_payload();
                                                let frame = bitaiir_net::protocol::frame_message(
                                                    done.command(),
                                                    &payload,
                                                );
                                                let _ = writer.write_all(&frame).await;
                                                let _ = writer.flush().await;
                                            }
                                            info!("sent {count} blocks to peer {addr} (from {start_height}+)");
                                        }
                                        Ok(Some(NetMessage::BlockData(bytes))) => {
                                            if let Ok(block) = bitaiir_types::encoding::from_bytes::<
                                                bitaiir_types::Block,
                                            >(&bytes) {
                                                let mut s = state.write().await;
                                                let height = s.chain.height() + 1;
                                                let now = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_secs();
                                                if bitaiir_chain::validate_block(
                                                    &block,
                                                    &s.chain,
                                                    &s.utxo,
                                                    now + 7200,
                                                )
                                                .is_ok()
                                                {
                                                    let spent: Vec<OutPoint> = block
                                                        .transactions
                                                        .iter()
                                                        .skip(1)
                                                        .flat_map(|tx| {
                                                            tx.inputs.iter().map(|i| i.prev_out)
                                                        })
                                                        .collect();
                                                    if s.chain.push(block.clone()).is_ok() {
                                                        for tx in &block.transactions {
                                                            let _ = s.utxo.apply_transaction(tx, height);
                                                        }
                                                        let _ = storage.apply_block(
                                                            height, &block, &spent,
                                                        );
                                                        // Bump this peer's height
                                                        // estimate — they just sent
                                                        // us a block at this height.
                                                        for p in &mut s.peers {
                                                            if p.addr == addr_key {
                                                                p.best_height =
                                                                    p.best_height.max(height);
                                                                break;
                                                            }
                                                        }
                                                        info!("received block {height} from inbound peer {addr}");
                                                    }
                                                }
                                            }
                                        }
                                        Ok(Some(NetMessage::TxData(bytes))) => {
                                            if let Ok(tx) = bitaiir_types::encoding::from_bytes::<
                                                bitaiir_types::Transaction,
                                            >(&bytes) {
                                                let txid = tx.txid();
                                                let mut s = state.write().await;
                                                if !s.mempool.contains(&txid) {
                                                    s.mempool.add(tx);
                                                    info!("received tx {txid} from inbound peer {addr}");
                                                }
                                            }
                                        }
                                        Ok(Some(NetMessage::Ping(nonce))) => {
                                            let pong = NetMessage::Pong(nonce);
                                            let payload = pong.to_payload();
                                            let frame = bitaiir_net::protocol::frame_message(
                                                pong.command(),
                                                &payload,
                                            );
                                            let _ = writer.write_all(&frame).await;
                                            let _ = writer.flush().await;
                                        }
                                        Ok(_) => { /* ignore other messages */ }
                                        Err(_) => {
                                            info!("peer {addr} disconnected");
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        // Peer gone — unregister and emit.
                        {
                            let mut s = state.write().await;
                            s.peers.retain(|p| p.addr != addr_key);
                        }
                        if let Some(ev) = &events {
                            let _ = ev.send(format!("  peer disconnected: {addr_key}"));
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

    if args.mine {
        info!("Mining enabled (--mine).");
    } else if !args.interactive {
        info!("Mining disabled. Use --mine flag to enable.");
    }

    let mining_state = state.clone();
    let mining_shutdown = shutdown.clone();
    let mining_active_ref = mining_active.clone();
    let mining_recipient = miner_recipient_hash;
    let is_interactive = args.interactive;
    let mining_storage = storage.clone();
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
                    let _ = log_tx.send("  Mining started.".into());
                    let _ = log_tx.send(h1);
                    let _ = log_tx.send(h2);
                } else {
                    println!();
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
