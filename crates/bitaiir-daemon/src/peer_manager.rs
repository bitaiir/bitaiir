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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitaiir_net::Peer;
use bitaiir_net::compact::{self, BlockTxnMsg, CompactBlockMsg, GetBlockTxnMsg, ShortId};
use bitaiir_net::message::NetMessage;
use bitaiir_net::protocol;
use bitaiir_rpc::{ConnectedPeer, KnownPeer, PeerDirection, PeerSource, SharedState};
use bitaiir_storage::Storage;
use bitaiir_types::{BlockHeader, Hash256, Transaction};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

// --------------------------------------------------------------------- //
// Compact-block reconstruction state
// --------------------------------------------------------------------- //

/// A compact block we've received but haven't yet fully reconstructed
/// because some of its transactions weren't in our mempool.  We keep
/// the header, the partially-filled slot array, and the absolute
/// indexes we've asked the peer for via `GetBlockTxn`.
struct PendingCompactBlock {
    header: BlockHeader,
    slots: Vec<Option<Transaction>>,
    missing_indexes: Vec<u16>,
}

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
        let peer_best_height = their_version.best_height;
        tokio::spawn(async move {
            run_gossip_loop(
                reader,
                writer,
                tx_recv,
                state,
                storage,
                events,
                addr_owned,
                peer_best_height,
            )
            .await;
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
/// Handles: GetHeaders/Headers, GetBlocks/BlockData, TxData,
/// GetAddr/Addr, Ping/Pong, SyncDone.
///
/// On startup the loop sends `GetAddr` (peer discovery) and, if the
/// peer's advertised `best_height` is ahead of ours, `GetHeaders` to
/// kick off a header-first sync.
#[allow(clippy::too_many_arguments)]
pub async fn run_gossip_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut tx_recv: mpsc::Receiver<NetMessage>,
    state: SharedState,
    storage: Arc<Storage>,
    events: Option<std::sync::mpsc::Sender<String>>,
    peer_key: String,
    peer_best_height: u64,
) {
    // After connection, request known addresses from the peer.
    let getaddr_msg = NetMessage::GetAddr;
    let payload = getaddr_msg.to_payload();
    let frame = protocol::frame_message(getaddr_msg.command(), &payload);
    let _ = writer.write_all(&frame).await;
    let _ = writer.flush().await;

    // Header-first sync kickoff.  If the peer claims a taller chain,
    // ask for their headers starting right after our current tip.  We
    // validate PoW on each incoming header before committing bandwidth
    // to downloading the corresponding block bodies.
    let our_height = state.read().await.chain.height();
    if peer_best_height > our_height {
        let m = NetMessage::GetHeaders(our_height);
        let p = m.to_payload();
        let f = protocol::frame_message(m.command(), &p);
        let _ = writer.write_all(&f).await;
        let _ = writer.flush().await;
        if let Some(ev) = &events {
            let _ = ev.send(format!(
                "  requesting headers from {peer_key} ({our_height} → {peer_best_height})",
            ));
        }
    }

    // Compact blocks we've received but not yet been able to fully
    // reconstruct from our mempool.  Keyed by the compact block's
    // header hash; lifetime is bounded by the peer connection.
    let mut pending_compact: HashMap<Hash256, PendingCompactBlock> = HashMap::new();

    // Whether we've already retried `GetHeaders(0)` on this
    // connection after an initial header-chain validation failure.
    // A peer whose main chain diverged before our current tip can't
    // answer `GetHeaders(our_height)` with a chain we can validate,
    // so on first failure we ask again from genesis.  One retry per
    // connection is enough; persistent invalidity means a bad peer.
    let mut headers_retried_from_genesis: bool = false;

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
                    Ok(Some(NetMessage::GetHeaders(start_height))) => {
                        // Serve a contiguous batch of headers starting
                        // right after `start_height`, capped at
                        // `MAX_HEADERS_PER_MESSAGE`.
                        let headers: Vec<bitaiir_types::BlockHeader> = {
                            let s = state.read().await;
                            let tip = s.chain.height();
                            let last = tip.min(
                                start_height
                                    + bitaiir_net::message::MAX_HEADERS_PER_MESSAGE as u64,
                            );
                            (start_height + 1..=last)
                                .filter_map(|h| s.chain.header_at(h).copied())
                                .collect()
                        };
                        let m = NetMessage::Headers(headers);
                        let p = m.to_payload();
                        let f = protocol::frame_message(m.command(), &p);
                        if writer.write_all(&f).await.is_err() { break; }
                        let _ = writer.flush().await;
                    }
                    Ok(Some(NetMessage::Headers(headers))) => {
                        // Validate the header chain cheaply:
                        //   (1) the first header's `prev_block_hash`
                        //       is a block we already know (either
                        //       our current tip, or an earlier block
                        //       we have in the index),
                        //   (2) every subsequent header chains from
                        //       its predecessor in the batch, and
                        //   (3) every header's PoW meets its own
                        //       `bits` target.
                        // Full consensus (merkle root, tx validity,
                        // difficulty retarget) is re-run when the
                        // bodies arrive, so a malicious peer can at
                        // worst waste our time — not corrupt state.
                        //
                        // If the first header's parent is unknown,
                        // the peer's main chain likely diverged
                        // before our current tip.  We retry once with
                        // `GetHeaders(0)` to pull from genesis so we
                        // can reconstruct the common ancestor's
                        // side of the fork.
                        let first_prev_known = if let Some(h) = headers.first() {
                            let s = state.read().await;
                            s.chain.contains(&h.prev_block_hash)
                        } else {
                            false
                        };

                        let mut all_ok = !headers.is_empty() && first_prev_known;
                        if all_ok {
                            let mut expected_prev = headers[0].prev_block_hash;
                            for h in &headers {
                                if h.prev_block_hash != expected_prev {
                                    all_ok = false;
                                    break;
                                }
                                let pow_hash = bitaiir_chain::aiir_pow(h);
                                let target = bitaiir_chain::CompactTarget::from_bits(h.bits);
                                if !target.hash_meets_target(pow_hash.as_bytes()) {
                                    all_ok = false;
                                    break;
                                }
                                expected_prev = h.block_hash();
                            }
                        }

                        if all_ok {
                            // Determine a sensible start height for
                            // the follow-up `GetBlocks`: the height
                            // of the common ancestor on our main
                            // chain (if any), otherwise 0.  Asking
                            // from an earlier height than strictly
                            // necessary is harmless — every block
                            // we already have short-circuits as
                            // `Duplicate` inside `accept_block`.
                            let request_from = {
                                let s = state.read().await;
                                s.chain
                                    .height_of(&headers[0].prev_block_hash)
                                    .unwrap_or(0)
                            };
                            let m = NetMessage::GetBlocks(request_from);
                            let p = m.to_payload();
                            let f = protocol::frame_message(m.command(), &p);
                            if writer.write_all(&f).await.is_err() { break; }
                            let _ = writer.flush().await;
                            if let Some(ev) = &events {
                                let _ = ev.send(format!(
                                    "  {} headers validated from {peer_key}, fetching bodies from height {request_from}",
                                    headers.len(),
                                ));
                            }
                        } else if !headers.is_empty() && !headers_retried_from_genesis {
                            // First-parent unknown or chain broken.
                            // Retry from genesis once — the peer may
                            // have diverged earlier than our tip.
                            headers_retried_from_genesis = true;
                            let m = NetMessage::GetHeaders(0);
                            let p = m.to_payload();
                            let f = protocol::frame_message(m.command(), &p);
                            if writer.write_all(&f).await.is_err() { break; }
                            let _ = writer.flush().await;
                            if let Some(ev) = &events {
                                let _ = ev.send(format!(
                                    "  peer {peer_key}: retrying header sync from genesis",
                                ));
                            }
                        } else if !headers.is_empty() {
                            warn!(
                                "peer {peer_key}: {} header(s) failed PoW/chain validation",
                                headers.len(),
                            );
                            if let Some(ev) = &events {
                                let _ = ev.send(format!(
                                    "  peer {peer_key}: invalid header chain, ignoring",
                                ));
                            }
                        }
                    }
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
                            try_accept_and_apply_block(
                                block, &state, &storage, &peer_key, &events,
                            )
                            .await;
                        }
                    }
                    Ok(Some(NetMessage::CompactBlock(cb))) => {
                        handle_compact_block(
                            cb,
                            &mut pending_compact,
                            &state,
                            &storage,
                            &peer_key,
                            &mut writer,
                            &events,
                        ).await;
                    }
                    Ok(Some(NetMessage::GetBlockTxn(req))) => {
                        // Serve the requested transactions from our
                        // copy of the block (chain lookup by hash).
                        let txs: Vec<Transaction> = {
                            let s = state.read().await;
                            match s.chain.block(&req.block_hash) {
                                Some(b) => req
                                    .indexes
                                    .iter()
                                    .filter_map(|i| b.transactions.get(*i as usize).cloned())
                                    .collect(),
                                None => Vec::new(),
                            }
                        };
                        if !txs.is_empty() {
                            let m = NetMessage::BlockTxn(BlockTxnMsg {
                                block_hash: req.block_hash,
                                txs,
                            });
                            let p = m.to_payload();
                            let f = protocol::frame_message(m.command(), &p);
                            if writer.write_all(&f).await.is_err() { break; }
                            let _ = writer.flush().await;
                        }
                    }
                    Ok(Some(NetMessage::BlockTxn(resp))) => {
                        if let Some(mut pending) = pending_compact.remove(&resp.block_hash) {
                            let asked = pending.missing_indexes.len();
                            // Fill the missing slots using the txs in
                            // the order we asked for them.
                            for (idx, tx) in pending.missing_indexes.iter().zip(resp.txs.into_iter())
                            {
                                if let Some(slot) = pending.slots.get_mut(*idx as usize) {
                                    *slot = Some(tx);
                                }
                            }
                            // If every slot is now filled, reconstruct
                            // and apply.
                            if pending.slots.iter().all(Option::is_some) {
                                let txs: Vec<Transaction> =
                                    pending.slots.into_iter().flatten().collect();
                                let block = bitaiir_types::Block {
                                    header: pending.header,
                                    transactions: txs,
                                };
                                let ok = try_accept_and_apply_block(
                                    block, &state, &storage, &peer_key, &events,
                                )
                                .await;
                                if ok {
                                    if let Some(ev) = &events {
                                        let _ = ev.send(format!(
                                            "  compact block from {peer_key} reconstructed ({asked} tx via GetBlockTxn)",
                                        ));
                                    }
                                }
                            } else {
                                warn!(
                                    "peer {peer_key}: BlockTxn did not fill all missing slots",
                                );
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

// --------------------------------------------------------------------- //
// Block acceptance + reorg orchestration
// --------------------------------------------------------------------- //

/// Accept a block from a peer, performing a reorg when its branch
/// carries more cumulative work than the current main chain.
///
/// Flow:
///
/// 1. **Standalone validation** — cheap, block-only checks (PoW,
///    size, merkle, coinbase structure, duplicate txs).  Rejects
///    garbage before it can pollute the block index.
/// 2. **Fork-choice decision** via [`bitaiir_chain::Chain::accept_block`],
///    which returns one of four outcomes:
///    - `Connected`: block extends the current tip.  Runs full
///      stateful validation, applies to UTXO, persists.
///    - `Reorg`: branch overtakes the main chain.  Undoes the
///      old chain's UTXO state (re-inserting its txs into the
///      mempool), rolls back `Chain.main_chain`, then validates
///      and applies each block on the new branch one at a time.
///    - `SideChain`: branch stored in the index but still has
///      less-or-equal work — nothing else to do.
///    - `Duplicate`: already-known block, no-op.
///
/// Returns `true` if the block (or the reorg it triggered) was
/// successfully applied, `false` if it was rejected.
async fn try_accept_and_apply_block(
    block: bitaiir_types::Block,
    state: &SharedState,
    storage: &Arc<Storage>,
    peer_key: &str,
    events: &Option<std::sync::mpsc::Sender<String>>,
) -> bool {
    // 1. Cheap standalone validation.
    if let Err(e) = bitaiir_chain::validate_block_standalone(&block) {
        warn!("peer {peer_key}: block failed standalone validation: {e}");
        return false;
    }

    // 2. Branch on whether this block extends the tip: the
    //    tip-extending case can run full stateful validation BEFORE
    //    touching chain state, which lets us bail cleanly if the
    //    block fails consensus.  Side-chain cases go through the
    //    reorg orchestrator below.
    let mut s = state.write().await;
    let now = unix_now();
    let current_tip = s.chain.tip();

    if block.header.prev_block_hash == current_tip {
        // Tip-extending path.  Validate fully first — cheaper to
        // reject now than to unwind chain state later.
        if let Err(e) = bitaiir_chain::validate_block(&block, &s.chain, &s.utxo, now + 7200) {
            warn!("peer {peer_key}: tip-extending block failed validation: {e}");
            return false;
        }
        let height = s.chain.height() + 1;
        match s.chain.accept_block(block.clone()) {
            Ok(bitaiir_chain::AcceptOutcome::Connected) => {}
            Ok(other) => {
                warn!("peer {peer_key}: unexpected outcome {other:?} for tip-extending block");
                return false;
            }
            Err(e) => {
                warn!("peer {peer_key}: chain rejected tip-extending block: {e}");
                return false;
            }
        }
        let undo = match s.utxo.apply_block_with_undo(&block, height) {
            Ok(u) => u,
            Err(e) => {
                warn!("peer {peer_key}: UTXO apply failed: {e}");
                return false;
            }
        };
        let _ = storage.apply_block(height, &block, &undo);
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
        return true;
    }

    // Not tip-extending.  Feed the block to the chain and see if
    // it causes a reorg.
    let outcome = match s.chain.accept_block(block.clone()) {
        Ok(o) => o,
        Err(e) => {
            warn!("peer {peer_key}: chain rejected side-chain block: {e}");
            return false;
        }
    };

    match outcome {
        bitaiir_chain::AcceptOutcome::Duplicate => true,
        bitaiir_chain::AcceptOutcome::SideChain => {
            if let Some(ev) = events {
                let _ = ev.send(format!(
                    "  side-chain block from {peer_key} stored (no reorg)",
                ));
            }
            true
        }
        bitaiir_chain::AcceptOutcome::Connected => {
            // accept_block does not report Connected for
            // non-tip-extending blocks, so this path is unreachable
            // — but we handle it defensively rather than panicking.
            warn!("peer {peer_key}: unexpected Connected outcome off-tip");
            false
        }
        bitaiir_chain::AcceptOutcome::Reorg {
            common_ancestor,
            undone,
            applied,
        } => {
            let ok = perform_reorg(
                &mut s,
                storage,
                peer_key,
                common_ancestor,
                &undone,
                &applied,
            )
            .await;
            if ok {
                if let Some(ev) = events {
                    let _ = ev.send(format!(
                        "  reorg from {peer_key}: undone {} block(s), applied {} block(s)",
                        undone.len(),
                        applied.len(),
                    ));
                }
            }
            ok
        }
    }
}

/// Drive a reorg through the stateful layers: undo the old chain's
/// UTXO effect, re-insert its txs into the mempool, roll back
/// `Chain.main_chain`, then validate + apply + persist each block on
/// the new branch.
///
/// On any failure mid-reorg the in-memory state is **not** currently
/// rolled back to a consistent prior snapshot — this is a known
/// limitation.  A well-behaved peer sending a valid branch will
/// succeed; a peer sending a branch that fails validation at apply
/// time will leave the node in a partial state that the next restart
/// can recover from by reloading from storage.
async fn perform_reorg(
    s: &mut tokio::sync::RwLockWriteGuard<'_, bitaiir_rpc::NodeState>,
    storage: &Arc<Storage>,
    peer_key: &str,
    common_ancestor: Hash256,
    undone: &[Hash256],
    applied: &[Hash256],
) -> bool {
    // 1. Undo each block on the old chain, in tip-first order.
    for hash in undone {
        let block = match s.chain.block(hash) {
            Some(b) => b.clone(),
            None => {
                warn!("reorg: cannot load block {hash} to undo (peer {peer_key})");
                return false;
            }
        };
        let undo = match storage.load_block_undo(hash) {
            Ok(Some(u)) => u,
            Ok(None) => {
                warn!("reorg: no undo record for block {hash} (peer {peer_key})");
                return false;
            }
            Err(e) => {
                warn!("reorg: load_block_undo({hash}) failed: {e}");
                return false;
            }
        };
        if let Err(e) = s.utxo.undo_block(&block, &undo) {
            warn!("reorg: utxo.undo_block({hash}) failed: {e}");
            return false;
        }
        // Non-coinbase txs go back to the mempool — they were valid
        // at their original inclusion time and may still be valid
        // against the post-reorg UTXO state.  If they turn out to
        // be invalid (e.g. double-spent by a new-chain tx), mining
        // will skip them at block-assembly time.
        for tx in block.transactions.iter().skip(1) {
            if !s.mempool.contains(&tx.txid()) {
                s.mempool.add(tx.clone());
            }
        }
    }

    // 2. Walk `Chain.main_chain` back to the common ancestor.  From
    //    here on, `chain.tip()` matches the parent expected by the
    //    first block we're about to apply.
    s.chain.rollback_main_chain_to(common_ancestor);

    // 3. Apply each block on the new branch in order.
    let now = unix_now();
    for hash in applied {
        let block = match s.chain.block(hash) {
            Some(b) => b.clone(),
            None => {
                warn!("reorg: cannot load new-chain block {hash} (peer {peer_key})");
                return false;
            }
        };
        if let Err(e) = bitaiir_chain::validate_block(&block, &s.chain, &s.utxo, now + 7200) {
            warn!("reorg: new-chain block {hash} failed validation: {e}");
            return false;
        }
        let height = s.chain.height() + 1;
        let undo = match s.utxo.apply_block_with_undo(&block, height) {
            Ok(u) => u,
            Err(e) => {
                warn!("reorg: UTXO apply of {hash} failed: {e}");
                return false;
            }
        };
        if let Err(e) = s.chain.extend_main_chain(*hash) {
            warn!("reorg: extend_main_chain({hash}) failed: {e}");
            return false;
        }
        let _ = storage.apply_block(height, &block, &undo);
        for tx in block.transactions.iter().skip(1) {
            s.mempool.remove(&tx.txid());
        }
    }

    // 4. Bump the peer's best_height to the new tip height.
    let new_height = s.chain.height();
    for p in &mut s.peers {
        if p.addr == peer_key {
            p.best_height = p.best_height.max(new_height);
            break;
        }
    }
    info!("reorg complete: new tip height {new_height} (peer {peer_key})");
    true
}

// --------------------------------------------------------------------- //
// Compact block reception
// --------------------------------------------------------------------- //

/// Handle an incoming `CompactBlock`:
///
///   1. Validate the header's PoW and parent-hash linkage.
///   2. Build a slot array of the block's total tx count.
///   3. Prefill the slots listed in `cb.prefilled` (always includes
///      the coinbase, which no peer has in its mempool).
///   4. Compute SipHash short IDs for every mempool tx and fill any
///      matching slots.
///   5. If every slot is filled, reconstruct and apply the block.
///   6. Otherwise, stash the partial block under `pending_compact`
///      and request the missing txs via `GetBlockTxn`.
#[allow(clippy::too_many_arguments)]
async fn handle_compact_block(
    cb: CompactBlockMsg,
    pending_compact: &mut HashMap<Hash256, PendingCompactBlock>,
    state: &SharedState,
    storage: &Arc<Storage>,
    peer_key: &str,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    events: &Option<std::sync::mpsc::Sender<String>>,
) {
    let block_hash = cb.header.block_hash();

    // 1. Cheap header checks: PoW + parent linkage.
    let pow_hash = bitaiir_chain::aiir_pow(&cb.header);
    let target = bitaiir_chain::CompactTarget::from_bits(cb.header.bits);
    if !target.hash_meets_target(pow_hash.as_bytes()) {
        warn!("peer {peer_key}: compact block failed PoW");
        return;
    }
    let our_tip = {
        let s = state.read().await;
        s.chain.tip()
    };
    if cb.header.prev_block_hash != our_tip {
        // Not a direct extension of our tip — could be a block we
        // already have, or a header ahead of us.  Either way, the
        // header-first sync path will catch up via `GetHeaders`.
        return;
    }

    // 2. Prepare the slot array.
    let total_txs = cb.short_ids.len() + cb.prefilled.len();
    if total_txs == 0 {
        return;
    }
    let mut slots: Vec<Option<Transaction>> = (0..total_txs).map(|_| None).collect();
    for (idx, tx) in &cb.prefilled {
        if let Some(slot) = slots.get_mut(*idx as usize) {
            *slot = Some(tx.clone());
        }
    }

    // 3. Build a short-id → Transaction map from the mempool so we
    //    can fill the non-prefilled slots in O(1) per lookup.
    let sip_key = compact::derive_sip_key(&cb.header, cb.nonce_salt);
    let mempool_by_sid: HashMap<ShortId, Transaction> = {
        let s = state.read().await;
        s.mempool
            .iter()
            .map(|(txid, tx)| (compact::short_id_for(txid, &sip_key), tx.clone()))
            .collect()
    };

    // 4. Walk the short-ID list in block order, filling the remaining
    //    slots from the mempool and collecting the indexes we can't
    //    resolve locally.
    let mut sid_iter = cb.short_ids.into_iter();
    let mut missing_indexes: Vec<u16> = Vec::new();
    for (i, slot) in slots.iter_mut().enumerate() {
        if slot.is_some() {
            continue;
        }
        let sid = match sid_iter.next() {
            Some(s) => s,
            None => break,
        };
        if let Some(tx) = mempool_by_sid.get(&sid) {
            *slot = Some(tx.clone());
        } else {
            missing_indexes.push(i as u16);
        }
    }

    // 5. If complete, reconstruct and apply right away.
    if missing_indexes.is_empty() {
        let txs: Vec<Transaction> = slots.into_iter().flatten().collect();
        let block = bitaiir_types::Block {
            header: cb.header,
            transactions: txs,
        };
        let ok = try_accept_and_apply_block(block, state, storage, peer_key, events).await;
        if ok {
            if let Some(ev) = events {
                let _ = ev.send(format!(
                    "  compact block from {peer_key} reconstructed fully from mempool",
                ));
            }
        }
        return;
    }

    // 6. Still missing some txs — ask the peer and stash the partial.
    if let Some(ev) = events {
        let _ = ev.send(format!(
            "  compact block from {peer_key}: {} tx(s) missing, requesting",
            missing_indexes.len(),
        ));
    }
    let req = NetMessage::GetBlockTxn(GetBlockTxnMsg {
        block_hash,
        indexes: missing_indexes.clone(),
    });
    let p = req.to_payload();
    let f = protocol::frame_message(req.command(), &p);
    let _ = writer.write_all(&f).await;
    let _ = writer.flush().await;

    pending_compact.insert(
        block_hash,
        PendingCompactBlock {
            header: cb.header,
            slots,
            missing_indexes,
        },
    );
}
