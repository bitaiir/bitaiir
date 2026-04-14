//! Background peer connection manager.
//!
//! The `PeerManager` runs as a long-lived Tokio task and is responsible
//! for:
//!
//!   - Maintaining a target number of outbound connections (default 8).
//!   - Reconnecting to known peers with exponential backoff when they
//!     disconnect.
//!   - Handling `--connect` peers and seed nodes on startup.
//!   - Exchanging known-peer addresses via `GetAddr`/`Addr` gossip so
//!     the network can discover new nodes organically.
//!   - Persisting the known-peer database to `bitaiir-storage` so it
//!     survives restarts.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitaiir_net::Peer;
use bitaiir_net::message::NetMessage;
use bitaiir_net::protocol;
use bitaiir_rpc::{ConnectedPeer, KnownPeer, PeerDirection, PeerSource, SharedState};
use bitaiir_storage::Storage;
use bitaiir_types::OutPoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// How often the manager wakes up to check connections and retry.
const TICK_INTERVAL: Duration = Duration::from_secs(10);

/// Default target number of outbound connections.
const TARGET_OUTBOUND: usize = 8;

/// Hardcoded seed node IPs — last resort when the known-peer database
/// is empty and no `--connect` was given.  Add entries as the network
/// grows (public nodes with static IPs).
pub const SEED_NODES: &[&str] = &[
    // "203.0.113.10:8444",   // example — replace with real IPs
];

/// DNS seed hostnames.  Resolved on startup and periodically (~1 h)
/// to discover fresh node IPs.  Each hostname should return A/AAAA
/// records pointing to active BitAiir nodes on the default P2P port.
///
/// Running a DNS seed is simple: set up a small crawler that probes
/// known nodes and updates the DNS zone for the hostname.  Bitcoin's
/// `bitcoin-seeder` is the reference implementation of this pattern.
pub const DNS_SEEDS: &[&str] = &[
    // "seed.bitaiir.org",
    // "dnsseed.bitaiir.network",
];

/// Default P2P port used when DNS resolution returns bare IPs.
/// Reads from the active network (mainnet = 8444, testnet = 18444).
fn default_p2p_port() -> u16 {
    bitaiir_types::Network::active().default_p2p_port()
}

/// How often to re-resolve DNS seeds (1 hour).
const DNS_RESOLVE_INTERVAL: Duration = Duration::from_secs(3600);

// --------------------------------------------------------------------- //
// PeerManager
// --------------------------------------------------------------------- //

/// Manages outbound peer connections in the background.
pub struct PeerManager {
    state: SharedState,
    storage: Arc<Storage>,
    events: Option<std::sync::mpsc::Sender<String>>,
    shutdown: Arc<AtomicBool>,
    our_p2p_addr: String,
    /// Last time DNS seeds were resolved (0 = never).
    last_dns_resolve: std::sync::atomic::AtomicU64,
}

impl PeerManager {
    pub fn new(
        state: SharedState,
        storage: Arc<Storage>,
        events: Option<std::sync::mpsc::Sender<String>>,
        shutdown: Arc<AtomicBool>,
        our_p2p_addr: String,
    ) -> Self {
        Self {
            state,
            storage,
            events,
            shutdown,
            our_p2p_addr,
            last_dns_resolve: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Spawn the background task.  Returns a `JoinHandle` the caller
    /// can await at shutdown.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(&self) {
        // Resolve DNS seeds on first tick.
        self.maybe_resolve_dns_seeds().await;

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(TICK_INTERVAL).await;
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            self.tick().await;
        }
        info!("PeerManager exiting.");
    }

    /// One iteration: check outbound count and try to connect if below
    /// target.
    async fn tick(&self) {
        // Periodically re-resolve DNS seeds to discover new peers.
        self.maybe_resolve_dns_seeds().await;

        let now = unix_now();

        // Snapshot what we need.
        let (outbound_count, candidates) = {
            let state = self.state.read().await;
            let outbound = state
                .peers
                .iter()
                .filter(|p| p.direction == PeerDirection::Outbound)
                .count();

            // Find connectable known peers: not currently connected,
            // not banned, and past their backoff window.
            let connected_addrs: std::collections::HashSet<&str> =
                state.peers.iter().map(|p| p.addr.as_str()).collect();

            let mut cands: Vec<(String, u64)> = state
                .known_peers
                .values()
                .filter(|kp| {
                    !connected_addrs.contains(kp.addr.as_str())
                        && !kp.is_banned()
                        && kp.addr != self.our_p2p_addr
                })
                .map(|kp| {
                    let ready_at = kp.last_seen + kp.backoff_secs();
                    (kp.addr.clone(), ready_at)
                })
                .filter(|(_, ready_at)| *ready_at <= now)
                .collect();

            // Sort: manual first, then most-recently-seen.
            cands.sort_by(|a, b| a.1.cmp(&b.1));
            (outbound, cands)
        };

        if outbound_count >= TARGET_OUTBOUND {
            return;
        }

        let slots = TARGET_OUTBOUND - outbound_count;
        for (addr, _) in candidates.into_iter().take(slots) {
            self.try_connect(&addr).await;
        }
    }

    /// Attempt a single outbound connection: TCP → handshake → sync →
    /// spawn gossip loop.
    async fn try_connect(&self, addr: &str) {
        info!("PeerManager: connecting to {addr}...");
        self.emit(format!("  reconnecting to {addr}..."));

        let stream = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("PeerManager: failed to connect to {addr}: {e}");
                self.record_failure(addr).await;
                return;
            }
            Err(_) => {
                warn!("PeerManager: connection to {addr} timed out");
                self.record_failure(addr).await;
                return;
            }
        };

        let peer_addr = match stream.peer_addr() {
            Ok(a) => a,
            Err(_) => {
                self.record_failure(addr).await;
                return;
            }
        };
        let mut peer = Peer::new(stream, peer_addr);

        // Handshake.
        let our_height = {
            let s = self.state.read().await;
            s.chain.height()
        };
        let their_version = match tokio::time::timeout(
            Duration::from_secs(10),
            peer.handshake_outbound(our_height),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                warn!("PeerManager: handshake with {addr} failed: {e}");
                // Bad handshake → longer ban.
                let mut s = self.state.write().await;
                if let Some(kp) = s.known_peers.get_mut(addr) {
                    kp.ban(3600); // 1 hour
                }
                return;
            }
            Err(_) => {
                warn!("PeerManager: handshake with {addr} timed out");
                self.record_failure(addr).await;
                return;
            }
        };

        info!(
            "PeerManager: connected to {addr} (agent={}, height={})",
            their_version.user_agent, their_version.best_height
        );

        // Sync if the peer is ahead.
        let (reader, writer, _peer_addr) = peer.into_parts();
        let (tx_send, tx_recv) = mpsc::channel::<NetMessage>(100);

        // Register the connection.
        let peer_addr_key = addr.to_string();
        {
            let mut s = self.state.write().await;
            s.peers.push(ConnectedPeer {
                addr: peer_addr_key.clone(),
                user_agent: their_version.user_agent.clone(),
                best_height: their_version.best_height,
                direction: PeerDirection::Outbound,
                connected_at: std::time::Instant::now(),
                sender: tx_send,
            });
            if let Some(kp) = s.known_peers.get_mut(addr) {
                kp.record_success();
            }
        }
        // Persist updated known-peer record.
        self.persist_known_peer(addr).await;

        self.emit(format!(
            "  peer connected: {peer_addr_key} (outbound, {}, height {})",
            their_version.user_agent, their_version.best_height,
        ));

        // Spawn the gossip loop.
        let state = self.state.clone();
        let storage = self.storage.clone();
        let events = self.events.clone();
        let addr_owned = addr.to_string();
        tokio::spawn(async move {
            run_gossip_loop(reader, writer, tx_recv, state, storage, events, addr_owned).await;
        });
    }

    async fn record_failure(&self, addr: &str) {
        let mut s = self.state.write().await;
        if let Some(kp) = s.known_peers.get_mut(addr) {
            kp.record_failure();
            self.emit(format!(
                "  peer {addr}: connection failed ({} failures)",
                kp.consecutive_failures
            ));
        }
        drop(s);
        self.persist_known_peer(addr).await;
    }

    async fn persist_known_peer(&self, addr: &str) {
        let s = self.state.read().await;
        if let Some(kp) = s.known_peers.get(addr) {
            let _ = self.storage.save_known_peer(
                addr,
                kp.last_seen,
                kp.consecutive_failures,
                kp.banned_until,
                kp.source_byte(),
            );
        }
    }

    // --- DNS seed resolution -------------------------------------------- //

    /// Resolve DNS seed hostnames if enough time has passed since the
    /// last resolution (or if this is the first run).  Each hostname
    /// is resolved to A/AAAA records and the resulting IPs are added
    /// to `known_peers` with `PeerSource::Seed`.
    async fn maybe_resolve_dns_seeds(&self) {
        if DNS_SEEDS.is_empty() {
            return;
        }
        let last = self.last_dns_resolve.load(Ordering::Relaxed);
        let now = unix_now();
        if last != 0 && now - last < DNS_RESOLVE_INTERVAL.as_secs() {
            return;
        }
        self.last_dns_resolve.store(now, Ordering::Relaxed);
        self.resolve_dns_seeds().await;
    }

    /// Perform the actual DNS resolution.  Uses `tokio::net::lookup_host`
    /// which does async A/AAAA lookups.  Each resolved IP gets the
    /// default P2P port appended and is inserted into `known_peers`.
    async fn resolve_dns_seeds(&self) {
        let mut total_discovered = 0usize;

        for &hostname in DNS_SEEDS {
            // lookup_host wants "host:port" — the port is needed for
            // the resolver API but we use our own DEFAULT_P2P_PORT.
            let lookup = format!("{hostname}:{}", default_p2p_port());
            match tokio::net::lookup_host(&lookup).await {
                Ok(addrs) => {
                    let mut s = self.state.write().await;
                    for addr in addrs {
                        let key = addr.to_string();
                        if key == self.our_p2p_addr {
                            continue; // don't add ourselves
                        }
                        if !s.known_peers.contains_key(&key) {
                            s.known_peers.insert(
                                key.clone(),
                                KnownPeer {
                                    addr: key,
                                    last_seen: 0,
                                    consecutive_failures: 0,
                                    banned_until: 0,
                                    source: PeerSource::Seed,
                                },
                            );
                            total_discovered += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("DNS seed resolve failed for {hostname}: {e}");
                }
            }
        }

        if total_discovered > 0 {
            info!("DNS seeds: discovered {total_discovered} new peer(s)");
            self.emit(format!(
                "  DNS seeds: discovered {total_discovered} new peer(s)"
            ));
        }
    }

    fn emit(&self, msg: String) {
        if let Some(tx) = &self.events {
            let _ = tx.send(msg);
        }
    }
}

// --------------------------------------------------------------------- //
// Shared gossip loop
// --------------------------------------------------------------------- //

/// The gossip loop multiplexes incoming P2P messages with outgoing
/// broadcasts (mined blocks, relayed transactions).  Used by both the
/// PeerManager (outbound) and the inbound listener in `main.rs`.
///
/// Handles: BlockData, TxData, GetBlocks, GetAddr, Addr, Ping/Pong.
pub async fn run_gossip_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut tx_recv: mpsc::Receiver<NetMessage>,
    state: SharedState,
    storage: Arc<Storage>,
    events: Option<std::sync::mpsc::Sender<String>>,
    peer_key: String,
) {
    // After connection, request known addresses from the peer.
    let getaddr_msg = NetMessage::GetAddr;
    let payload = getaddr_msg.to_payload();
    let frame = protocol::frame_message(getaddr_msg.command(), &payload);
    let _ = writer.write_all(&frame).await;
    let _ = writer.flush().await;

    loop {
        tokio::select! {
            // Outgoing broadcasts.
            msg = tx_recv.recv() => {
                let Some(m) = msg else { break };
                let payload = m.to_payload();
                let frame = protocol::frame_message(m.command(), &payload);
                if writer.write_all(&frame).await.is_err() { break; }
                if writer.flush().await.is_err() { break; }
            }

            // Incoming messages.
            result = async {
                let mut header_buf = [0u8; protocol::HEADER_SIZE];
                reader.read_exact(&mut header_buf).await?;
                let header = protocol::parse_header(&header_buf)
                    .ok_or_else(|| std::io::Error::new(
                        std::io::ErrorKind::InvalidData, "bad magic",
                    ))?;
                let mut payload = vec![0u8; header.payload_len as usize];
                if !payload.is_empty() {
                    reader.read_exact(&mut payload).await?;
                }
                Ok::<_, std::io::Error>(
                    NetMessage::from_payload(&header.command, &payload),
                )
            } => {
                match result {
                    Ok(Some(NetMessage::GetBlocks(start_height))) => {
                        // Serve requested blocks.
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
                        for bytes in &to_send {
                            let m = NetMessage::BlockData(bytes.clone());
                            let p = m.to_payload();
                            let f = protocol::frame_message(m.command(), &p);
                            if writer.write_all(&f).await.is_err() { break; }
                            let _ = writer.flush().await;
                        }
                        let done = NetMessage::SyncDone;
                        let p = done.to_payload();
                        let f = protocol::frame_message(done.command(), &p);
                        let _ = writer.write_all(&f).await;
                        let _ = writer.flush().await;
                    }
                    Ok(Some(NetMessage::BlockData(bytes))) => {
                        if let Ok(block) = bitaiir_types::encoding::from_bytes::<
                            bitaiir_types::Block,
                        >(&bytes) {
                            let mut s = state.write().await;
                            let height = s.chain.height() + 1;
                            let now = unix_now();
                            if bitaiir_chain::validate_block(
                                &block, &s.chain, &s.utxo, now + 7200,
                            )
                            .is_ok()
                            {
                                let spent: Vec<OutPoint> = block
                                    .transactions.iter().skip(1)
                                    .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
                                    .collect();
                                if s.chain.push(block.clone()).is_ok() {
                                    for tx in &block.transactions {
                                        let _ = s.utxo.apply_transaction(tx, height);
                                    }
                                    let _ = storage.apply_block(height, &block, &spent);
                                    for tx in block.transactions.iter().skip(1) {
                                        s.mempool.remove(&tx.txid());
                                    }
                                    for p in &mut s.peers {
                                        if p.addr == peer_key {
                                            p.best_height = p.best_height.max(height);
                                            break;
                                        }
                                    }
                                    info!("received block {height} from peer {peer_key}");
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
                                info!("received tx {txid} from peer {peer_key}");
                            }
                        }
                    }
                    Ok(Some(NetMessage::GetAddr)) => {
                        // Reply with known peers.
                        let addrs: Vec<bitaiir_net::PeerAddr> = {
                            let s = state.read().await;
                            s.known_peers.values()
                                .filter(|kp| !kp.is_banned())
                                .take(1000)
                                .map(|kp| bitaiir_net::PeerAddr {
                                    addr: kp.addr.clone(),
                                    services: 1,
                                    timestamp: kp.last_seen,
                                })
                                .collect()
                        };
                        if !addrs.is_empty() {
                            let msg = NetMessage::Addr(addrs);
                            let p = msg.to_payload();
                            let f = protocol::frame_message(msg.command(), &p);
                            let _ = writer.write_all(&f).await;
                            let _ = writer.flush().await;
                        }
                    }
                    Ok(Some(NetMessage::Addr(peers))) => {
                        // Learn new peer addresses.
                        let mut s = state.write().await;
                        for pa in peers {
                            if s.known_peers.contains_key(&pa.addr) {
                                // Update last_seen if newer.
                                if let Some(kp) = s.known_peers.get_mut(&pa.addr) {
                                    if pa.timestamp > kp.last_seen {
                                        kp.last_seen = pa.timestamp;
                                    }
                                }
                            } else {
                                s.known_peers.insert(pa.addr.clone(), KnownPeer {
                                    addr: pa.addr,
                                    last_seen: pa.timestamp,
                                    consecutive_failures: 0,
                                    banned_until: 0,
                                    source: PeerSource::Addr,
                                });
                            }
                        }
                    }
                    Ok(Some(NetMessage::Ping(nonce))) => {
                        let pong = NetMessage::Pong(nonce);
                        let p = pong.to_payload();
                        let f = protocol::frame_message(pong.command(), &p);
                        let _ = writer.write_all(&f).await;
                        let _ = writer.flush().await;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        info!("peer {peer_key} disconnected");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: remove from connected peers.
    {
        let mut s = state.write().await;
        s.peers.retain(|p| p.addr != peer_key);
    }
    if let Some(ev) = &events {
        let _ = ev.send(format!("  peer disconnected: {peer_key}"));
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}
