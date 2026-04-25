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

// --------------------------------------------------------------------- //
// Per-peer rate limit
// --------------------------------------------------------------------- //

/// Rate-limit parameters applied to every incoming P2P message.  A
/// peer that exceeds the bucket is disconnected and banned for
/// `ban_secs`.  Resolved at daemon startup from `[network]` config
/// and reused for every gossip loop (one `TokenBucket` instance per
/// peer).
#[derive(Debug, Clone, Copy)]
pub struct PeerRateLimit {
    /// Token refill rate (messages per second).
    pub rate_per_sec: f64,
    /// Bucket capacity — the maximum burst before throttling kicks in.
    pub burst: f64,
    /// How long to ban the peer after a violation, in seconds.
    pub ban_secs: u64,
}

impl Default for PeerRateLimit {
    fn default() -> Self {
        Self {
            rate_per_sec: 100.0,
            burst: 200.0,
            ban_secs: 600,
        }
    }
}

/// Standard token bucket: fractional tokens accumulate at
/// `rate_per_sec` up to `capacity`, each incoming message consumes
/// one token.  Refill is computed lazily from elapsed wall time, so
/// there's no background timer.
pub struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, rate_per_sec: f64) -> Self {
        Self {
            capacity,
            rate_per_sec,
            tokens: capacity,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Take one token if available.  Returns `false` when the
    /// bucket is empty — the caller should treat that as a rate
    /// violation.
    pub fn try_take(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// --------------------------------------------------------------------- //
// Seed discovery
// --------------------------------------------------------------------- //
//
// A node with no `known_peers` on disk and no `--connect` flag has to
// bootstrap somehow.  Two fallbacks are consulted, in order:
//
//   1. **DNS seeds** — hostnames whose A/AAAA records are maintained
//      by an operator running a crawler (see
//      <https://github.com/sipa/bitcoin-seeder> for the reference
//      implementation).  The crawler probes currently-alive nodes,
//      keeps a ranked list, and updates the DNS zone.  New nodes
//      resolve the hostname, learn ~a dozen IPs, and connect.
//      Re-resolved every hour so stale IPs are pruned.
//   2. **Hardcoded seed nodes** — a last-resort list compiled into
//      the binary.  Used when DNS is blocked or the seeds are down.
//      Should be a small set of long-lived static-IP nodes run by
//      trusted operators.
//
// The arrays below are network-specific — mainnet and testnet have
// separate bootstrap fleets so a testnet node never tries to peer
// with mainnet and vice versa.  All four are currently empty; the
// network is still in development and has no public nodes.  Populate
// them as infrastructure lands.

/// Hardcoded mainnet seed nodes.  `"ip:port"` strings; port defaults
/// to 8444 when using the standard mainnet port.
pub const SEED_NODES_MAINNET: &[&str] = &[
    // TODO: populate with static-IP mainnet nodes.
    // Example: "203.0.113.10:8444",
];

/// Hardcoded testnet seed nodes.  `"ip:port"` strings; port defaults
/// to 18444 when using the standard testnet port.
pub const SEED_NODES_TESTNET: &[&str] = &[
    // TODO: populate with static-IP testnet nodes.
    // Example: "203.0.113.11:18444",
];

/// Mainnet DNS seed hostnames.  Each hostname's A/AAAA records
/// should point at healthy mainnet P2P peers.
pub const DNS_SEEDS_MAINNET: &[&str] = &[
    // TODO: register and run a seeder for the mainnet.
    // Example: "seed.bitaiir.org",
];

/// Testnet DNS seed hostnames.  Kept separate from mainnet so
/// crossed-network connection attempts are impossible.
pub const DNS_SEEDS_TESTNET: &[&str] = &[
    // TODO: register and run a seeder for the testnet.
    // Example: "testnet-seed.bitaiir.org",
];

/// Hardcoded seed nodes for the currently-active network.  Operators
/// can extend this list at runtime via `--seed` / `[network]
/// seed_nodes`; the merged list is what the daemon actually uses.
pub fn hardcoded_seed_nodes() -> &'static [&'static str] {
    match bitaiir_types::Network::active() {
        bitaiir_types::Network::Mainnet => SEED_NODES_MAINNET,
        bitaiir_types::Network::Testnet => SEED_NODES_TESTNET,
    }
}

/// Hardcoded DNS seed hostnames for the currently-active network.
/// Extend at runtime via `--dns-seed` / `[network] dns_seeds`; skip
/// entirely with `--no-dns-seeds` / `disable_dns_seeds = true`.
pub fn hardcoded_dns_seeds() -> &'static [&'static str] {
    match bitaiir_types::Network::active() {
        bitaiir_types::Network::Mainnet => DNS_SEEDS_MAINNET,
        bitaiir_types::Network::Testnet => DNS_SEEDS_TESTNET,
    }
}

/// Combine the hardcoded list with operator-provided additions,
/// preserving order (hardcoded first) and de-duplicating exact
/// string matches.
pub fn resolve_seed_nodes(extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = hardcoded_seed_nodes()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for s in extra {
        if !out.iter().any(|existing| existing == s) {
            out.push(s.clone());
        }
    }
    out
}

/// Combine hardcoded DNS seeds with operator-provided additions.
/// When `disabled` is `true`, returns an empty list — both hardcoded
/// and configured seeds are skipped.
pub fn resolve_dns_seeds(extra: &[String], disabled: bool) -> Vec<String> {
    if disabled {
        return Vec::new();
    }
    let mut out: Vec<String> = hardcoded_dns_seeds()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for s in extra {
        if !out.iter().any(|existing| existing == s) {
            out.push(s.clone());
        }
    }
    out
}

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
    rate_limit: PeerRateLimit,
    /// Resolved DNS seed hostnames (hardcoded + operator-provided).
    /// Empty when DNS seeding is disabled by configuration.
    dns_seeds: Vec<String>,
    /// Last time DNS seeds were resolved (0 = never).
    last_dns_resolve: std::sync::atomic::AtomicU64,
}

impl PeerManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: SharedState,
        storage: Arc<Storage>,
        events: Option<std::sync::mpsc::Sender<String>>,
        shutdown: Arc<AtomicBool>,
        our_p2p_addr: String,
        rate_limit: PeerRateLimit,
        dns_seeds: Vec<String>,
    ) -> Self {
        Self {
            state,
            storage,
            events,
            shutdown,
            our_p2p_addr,
            rate_limit,
            dns_seeds,
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
        self.emit_info("PeerManager exiting.");
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
            cands.sort_by_key(|a| a.1);
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
        self.emit_info(&format!("reconnecting to {addr}..."));

        let stream = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.emit_warn(&format!("failed to connect to {addr}: {e}"));
                self.record_failure(addr).await;
                return;
            }
            Err(_) => {
                self.emit_warn(&format!("connection to {addr} timed out"));
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
                self.emit_warn(&format!("handshake with {addr} failed: {e}"));
                // Bad handshake → longer ban.
                let mut s = self.state.write().await;
                if let Some(kp) = s.known_peers.get_mut(addr) {
                    kp.ban(3600); // 1 hour
                }
                return;
            }
            Err(_) => {
                self.emit_warn(&format!("handshake with {addr} timed out"));
                self.record_failure(addr).await;
                return;
            }
        };

        self.emit_info(&format!(
            "connected to {addr} (agent={}, height={})",
            their_version.user_agent, their_version.best_height,
        ));

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

        self.emit_info(&format!(
            "peer connected: {peer_addr_key} (outbound, {}, height {})",
            their_version.user_agent, their_version.best_height,
        ));

        // Spawn the gossip loop.
        let state = self.state.clone();
        let storage = self.storage.clone();
        let events = self.events.clone();
        let addr_owned = addr.to_string();
        let peer_best_height = their_version.best_height;
        let rate_limit = self.rate_limit;
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
                rate_limit,
            )
            .await;
        });
    }

    async fn record_failure(&self, addr: &str) {
        let mut s = self.state.write().await;
        if let Some(kp) = s.known_peers.get_mut(addr) {
            kp.record_failure();
            self.emit_warn(&format!(
                "peer {addr}: connection failed ({} failures)",
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
        if self.dns_seeds.is_empty() {
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

        for hostname in &self.dns_seeds {
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
                    self.emit_warn(&format!("DNS seed resolve failed for {hostname}: {e}"));
                }
            }
        }

        if total_discovered > 0 {
            self.emit_info(&format!(
                "DNS seeds: discovered {total_discovered} new peer(s)"
            ));
        }
    }

    /// Emit a timestamped INFO event.
    fn emit_info(&self, msg: &str) {
        crate::log::log_info(msg, &self.events);
    }

    /// Emit a timestamped WARN event.
    fn emit_warn(&self, msg: &str) {
        crate::log::log_warn(msg, &self.events);
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
    rate_limit: PeerRateLimit,
) {
    let mut bucket = TokenBucket::new(rate_limit.burst, rate_limit.rate_per_sec);
    // After connection, request known addresses from the peer.
    let getaddr_msg = NetMessage::GetAddr;
    let payload = getaddr_msg.to_payload();
    let frame = protocol::frame_message(getaddr_msg.command(), &payload);
    let _ = writer.write_all(&frame).await;
    let _ = writer.flush().await;

    // Header-first sync kickoff.  If the peer claims a taller chain,
    // send a block locator (newest-first list of hashes, exponentially
    // spaced, terminating at genesis) so the peer can find the
    // deepest common ancestor on our chain in one round trip — no
    // retry needed even when the two chains share only the genesis.
    let (our_height, locator) = {
        let s = state.read().await;
        (s.chain.height(), s.chain.build_locator())
    };
    if peer_best_height > our_height {
        let m = NetMessage::GetHeaders(locator);
        let p = m.to_payload();
        let f = protocol::frame_message(m.command(), &p);
        let _ = writer.write_all(&f).await;
        let _ = writer.flush().await;
        crate::log::log_info(
            &format!("requesting headers from {peer_key} ({our_height} → {peer_best_height})"),
            &events,
        );
    }

    // Compact blocks we've received but not yet been able to fully
    // reconstruct from our mempool.  Keyed by the compact block's
    // header hash; lifetime is bounded by the peer connection.
    let mut pending_compact: HashMap<Hash256, PendingCompactBlock> = HashMap::new();

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
                // Rate-limit gate: one token per parsed message.  On
                // violation we disconnect and ban the peer — both
                // via `KnownPeer::ban` (persisted) if we have an
                // entry for this addr, and via the in-memory
                // `banned_ips` map so the IP can't reconnect until
                // the ban expires.
                if matches!(&result, Ok(Some(_))) && !bucket.try_take() {
                    let peer_ip: Option<std::net::IpAddr> = peer_key
                        .rsplit_once(':')
                        .and_then(|(host, _)| host.trim_matches(['[', ']']).parse().ok());

                    // Exponential backoff on repeat offenders: each
                    // additional violation doubles the ban, capped at
                    // 64× to keep bans finite (~10h at default 600s).
                    let mut s = state.write().await;
                    let prev = peer_ip.and_then(|ip| s.banned_ips.get(&ip).copied());
                    let offenses = prev.map(|b| b.offenses.saturating_add(1)).unwrap_or(1);
                    let mult: u64 = 1u64 << (offenses - 1).min(6);
                    let ban_secs = rate_limit.ban_secs.saturating_mul(mult);
                    let deadline = unix_now() + ban_secs;

                    crate::log::log_warn(
                        &format!(
                            "peer {peer_key} exceeded rate limit ({} msgs/s, burst {}) — disconnecting, banning for {}s (offense #{})",
                            rate_limit.rate_per_sec, rate_limit.burst, ban_secs, offenses,
                        ),
                        &events,
                    );

                    if let Some(kp) = s.known_peers.get_mut(&peer_key) {
                        kp.banned_until = deadline;
                        let _ = storage.save_known_peer(
                            &peer_key,
                            kp.last_seen,
                            kp.consecutive_failures,
                            kp.banned_until,
                            kp.source_byte(),
                        );
                    }
                    if let Some(ip) = peer_ip {
                        s.banned_ips.insert(
                            ip,
                            bitaiir_rpc::BannedIp {
                                deadline,
                                offenses,
                            },
                        );
                        drop(s);
                        let _ = storage.save_banned_ip(&ip.to_string(), deadline, offenses);
                    } else {
                        drop(s);
                    }
                    break;
                }
                match result {
                    Ok(Some(NetMessage::GetHeaders(locator))) => {
                        // Walk the locator newest-first looking for
                        // the first hash that lives on our main
                        // chain — that's the deepest common
                        // ancestor.  If nothing in the locator is
                        // on our chain (e.g. peer started from a
                        // different genesis), fall back to sending
                        // headers from height 1 so the peer at
                        // least gets a chance to reject or retry.
                        let headers: Vec<bitaiir_types::BlockHeader> = {
                            let s = state.read().await;
                            let start_height = locator
                                .iter()
                                .find_map(|h| s.chain.height_of(h))
                                .unwrap_or(0);
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
                        //       is a block we already know (the
                        //       common ancestor the sender picked
                        //       from our locator);
                        //   (2) every subsequent header chains from
                        //       its predecessor in the batch;
                        //   (3) every header's PoW meets its own
                        //       `bits` target.
                        // Full consensus (merkle root, tx validity,
                        // difficulty retarget) is re-run when the
                        // bodies arrive, so a malicious peer can at
                        // worst waste our time — not corrupt state.
                        //
                        // Because we sent a block locator rather
                        // than a bare start height, a peer that
                        // speaks the protocol correctly will always
                        // anchor its response at a block we know.
                        // Anchors we don't recognise are now a hard
                        // error, no retry — that path was the old
                        // `GetHeaders(u64)` workaround.
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
                            // chain (guaranteed to exist — it's the
                            // locator hit the sender anchored on).
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
                            crate::log::log_info(
                                &format!(
                                    "{} headers validated from {peer_key}, fetching bodies from height {request_from}",
                                    headers.len(),
                                ),
                                &events,
                            );
                        } else if !headers.is_empty() {
                            crate::log::log_warn(
                                &format!(
                                    "peer {peer_key}: {} header(s) failed PoW/chain validation — ignoring",
                                    headers.len(),
                                ),
                                &events,
                            );
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
                                    crate::log::log_info(
                                        &format!(
                                            "compact block from {peer_key} reconstructed ({asked} tx via GetBlockTxn)",
                                        ),
                                        &events,
                                    );
                                }
                            } else {
                                crate::log::log_warn(
                                    &format!(
                                        "peer {peer_key}: BlockTxn did not fill all missing slots",
                                    ),
                                    &events,
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
                            if s.mempool.contains(&txid) {
                                // Already in pool — peers often
                                // re-broadcast a tx before a miner
                                // picks it up.  Silent no-op.
                            } else {
                                // Validate before accepting: rejects
                                // txs with invalid signatures, bad
                                // tx-PoW nonce, missing inputs, or
                                // attempted overspend.  Without this
                                // guard any peer could fill our
                                // mempool with arbitrary bytes.
                                let next_height = s.chain.height() + 1;
                                if let Err(e) = bitaiir_chain::validate_transaction(
                                    &tx,
                                    &s.utxo,
                                    next_height,
                                ) {
                                    crate::log::log_warn(
                                        &format!(
                                            "peer {peer_key}: rejected tx {txid}: {e}",
                                        ),
                                        &events,
                                    );
                                } else if let Err(e) = s.mempool.add(tx) {
                                    crate::log::log_warn(
                                        &format!(
                                            "peer {peer_key}: mempool rejected tx {txid}: {e}",
                                        ),
                                        &events,
                                    );
                                } else {
                                    crate::log::log_info(
                                        &format!("received tx {txid} from peer {peer_key}"),
                                        &events,
                                    );
                                }
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
    crate::log::log_info(&format!("peer disconnected: {peer_key}"), &events);
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
        crate::log::log_warn(
            &format!("peer {peer_key}: block failed standalone validation: {e}"),
            events,
        );
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
            crate::log::log_warn(
                &format!("peer {peer_key}: tip-extending block failed validation: {e}"),
                events,
            );
            return false;
        }
        let height = s.chain.height() + 1;
        match s.chain.accept_block(block.clone()) {
            Ok(bitaiir_chain::AcceptOutcome::Connected) => {}
            Ok(other) => {
                crate::log::log_warn(
                    &format!(
                        "peer {peer_key}: unexpected outcome {other:?} for tip-extending block"
                    ),
                    events,
                );
                return false;
            }
            Err(e) => {
                crate::log::log_warn(
                    &format!("peer {peer_key}: chain rejected tip-extending block: {e}"),
                    events,
                );
                return false;
            }
        }
        let undo = match s.utxo.apply_block_with_undo(&block, height) {
            Ok(u) => u,
            Err(e) => {
                crate::log::log_warn(&format!("peer {peer_key}: UTXO apply failed: {e}"), events);
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
        crate::log::log_info(
            &format!("received block {height} from peer {peer_key}"),
            events,
        );
        return true;
    }

    // Not tip-extending.  Feed the block to the chain and see if
    // it causes a reorg.
    let outcome = match s.chain.accept_block(block.clone()) {
        Ok(o) => o,
        Err(e) => {
            crate::log::log_warn(
                &format!("peer {peer_key}: chain rejected side-chain block: {e}"),
                events,
            );
            return false;
        }
    };

    match outcome {
        bitaiir_chain::AcceptOutcome::Duplicate => true,
        bitaiir_chain::AcceptOutcome::SideChain => {
            crate::log::log_info(
                &format!("side-chain block from {peer_key} stored (no reorg)"),
                events,
            );
            true
        }
        bitaiir_chain::AcceptOutcome::Connected => {
            // accept_block does not report Connected for
            // non-tip-extending blocks, so this path is unreachable
            // — but we handle it defensively rather than panicking.
            crate::log::log_warn(
                &format!("peer {peer_key}: unexpected Connected outcome off-tip"),
                events,
            );
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
                events,
            )
            .await;
            if ok {
                crate::log::log_info(
                    &format!(
                        "reorg from {peer_key}: undone {} block(s), applied {} block(s)",
                        undone.len(),
                        applied.len(),
                    ),
                    events,
                );
            }
            ok
        }
    }
}

/// Drive a reorg through the stateful layers, atomically.
///
/// Before touching anything the orchestrator snapshots the pieces
/// of in-memory state that the reorg mutates — the UTXO set, the
/// chain's main-chain pointer, and the mempool.  It then runs the
/// full reorg **in memory only**: undo old blocks (returning their
/// non-coinbase txs to the mempool), roll back `main_chain`, and
/// validate + apply each block on the new branch.  If any step
/// fails — a missing undo record, a block that fails validation,
/// a UTXO apply error — the snapshots are dropped back in and the
/// node returns to exactly its pre-reorg state.
///
/// Storage persistence only happens **after** every in-memory step
/// has succeeded, and is itself a single atomic redb write
/// transaction via [`Storage::apply_reorg`].  End-to-end the reorg
/// either fully commits (memory + disk both post-reorg) or fully
/// rolls back (memory restored from snapshot, disk untouched).
async fn perform_reorg(
    s: &mut tokio::sync::RwLockWriteGuard<'_, bitaiir_rpc::NodeState>,
    storage: &Arc<Storage>,
    peer_key: &str,
    common_ancestor: Hash256,
    undone: &[Hash256],
    applied: &[Hash256],
    events: &Option<std::sync::mpsc::Sender<String>>,
) -> bool {
    // Snapshot the mutable in-memory state.  Rollback on failure is
    // just three assignments — cheap, and keeps the failure path
    // trivially correct regardless of which step failed.
    let utxo_snapshot = s.utxo.clone();
    let main_chain_snapshot = s.chain.main_chain_snapshot();
    let mempool_snapshot = s.mempool.clone();
    let old_tip_height = s.chain.height();

    // Run the whole reorg in memory first.  Each step returns
    // `Err(msg)` on failure; the outer match restores state from
    // snapshots before returning.  We also collect the paired
    // `(block, undo)` records for both the undone and the applied
    // chains so the single-transaction `Storage::apply_reorg` call
    // at the end has everything it needs.
    type UndonePersist = Vec<(bitaiir_types::Block, bitaiir_chain::BlockUndo)>;
    type AppliedPersist = Vec<(u64, bitaiir_types::Block, bitaiir_chain::BlockUndo)>;
    let persist: Result<(UndonePersist, AppliedPersist), String> = (|| {
        let mut undone_persist: UndonePersist = Vec::with_capacity(undone.len());
        let mut applied_persist: AppliedPersist = Vec::with_capacity(applied.len());

        // 1. Undo each block on the old chain, in tip-first order.
        for hash in undone {
            let block = s
                .chain
                .block(hash)
                .ok_or_else(|| format!("cannot load block {hash} to undo"))?
                .clone();
            let undo = storage
                .load_block_undo(hash)
                .map_err(|e| format!("load_block_undo({hash}) failed: {e}"))?
                .ok_or_else(|| format!("no undo record for block {hash}"))?;
            s.utxo
                .undo_block(&block, &undo)
                .map_err(|e| format!("utxo.undo_block({hash}) failed: {e}"))?;
            // Non-coinbase txs go back to the mempool — they were
            // valid at their original inclusion time and may still
            // be valid against the post-reorg UTXO state.  If they
            // turn out to be invalid (e.g. double-spent by a new-
            // chain tx), mining will skip them at block assembly.
            // Mempool rejection here (size cap, etc.) is tolerated
            // silently: re-inserting reorg txs is best-effort.
            for tx in block.transactions.iter().skip(1) {
                if !s.mempool.contains(&tx.txid()) {
                    let _ = s.mempool.add(tx.clone());
                }
            }
            undone_persist.push((block, undo));
        }

        // 2. Walk `Chain.main_chain` back to the common ancestor.
        //    From here on, `chain.tip()` matches the parent expected
        //    by the first block we're about to apply.
        s.chain.rollback_main_chain_to(common_ancestor);

        // 3. Apply each block on the new branch in order.
        let now = unix_now();
        for hash in applied {
            let block = s
                .chain
                .block(hash)
                .ok_or_else(|| format!("cannot load new-chain block {hash}"))?
                .clone();
            bitaiir_chain::validate_block(&block, &s.chain, &s.utxo, now + 7200)
                .map_err(|e| format!("new-chain block {hash} failed validation: {e}"))?;
            let height = s.chain.height() + 1;
            let undo = s
                .utxo
                .apply_block_with_undo(&block, height)
                .map_err(|e| format!("UTXO apply of {hash} failed: {e}"))?;
            s.chain
                .extend_main_chain(*hash)
                .map_err(|e| format!("extend_main_chain({hash}) failed: {e}"))?;
            for tx in block.transactions.iter().skip(1) {
                s.mempool.remove(&tx.txid());
            }
            applied_persist.push((height, block, undo));
        }

        Ok((undone_persist, applied_persist))
    })();

    let (undone_persist, applied_persist) = match persist {
        Ok(v) => v,
        Err(msg) => {
            crate::log::log_warn(
                &format!("reorg aborted ({peer_key}): {msg} — restoring pre-reorg state"),
                events,
            );
            s.utxo = utxo_snapshot;
            s.chain.restore_main_chain(main_chain_snapshot);
            s.mempool = mempool_snapshot;
            return false;
        }
    };

    // 4. In-memory reorg succeeded.  Commit the whole transition to
    //    disk in a single atomic redb write transaction via
    //    `Storage::apply_reorg`: either disk is fully post-reorg or
    //    fully pre-reorg, never partially either way.  If this
    //    commit fails (disk error, out of space) the in-memory
    //    state we've already mutated is ahead of disk — which is
    //    recovered on next restart by reloading from disk and
    //    re-syncing via P2P.
    let new_tip_height = s.chain.height();
    let new_tip_hash = s.chain.tip();
    if let Err(e) = storage.apply_reorg(
        old_tip_height,
        new_tip_height,
        new_tip_hash,
        &undone_persist,
        &applied_persist,
    ) {
        crate::log::log_warn(
            &format!("reorg persist: storage.apply_reorg failed: {e}"),
            events,
        );
    }

    // 5. Bump the peer's best_height to the new tip height.
    for p in &mut s.peers {
        if p.addr == peer_key {
            p.best_height = p.best_height.max(new_tip_height);
            break;
        }
    }
    crate::log::log_info(
        &format!("reorg complete: new tip height {new_tip_height} (peer {peer_key})"),
        events,
    );
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
        crate::log::log_warn(
            &format!("peer {peer_key}: compact block failed PoW"),
            events,
        );
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
            crate::log::log_info(
                &format!("compact block from {peer_key} reconstructed fully from mempool"),
                events,
            );
        }
        return;
    }

    // 6. Still missing some txs — ask the peer and stash the partial.
    crate::log::log_info(
        &format!(
            "compact block from {peer_key}: {} tx(s) missing, requesting",
            missing_indexes.len(),
        ),
        events,
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_up_to_capacity_immediately() {
        let mut b = TokenBucket::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(b.try_take());
        }
        assert!(!b.try_take());
    }

    #[test]
    fn token_bucket_refills_at_configured_rate() {
        let mut b = TokenBucket::new(2.0, 1000.0);
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(!b.try_take());
        // 2ms at 1000 tok/s = 2 tokens refilled → capped at capacity.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(b.try_take());
        assert!(b.try_take());
    }

    #[test]
    fn token_bucket_never_exceeds_capacity() {
        let mut b = TokenBucket::new(3.0, 1000.0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        // 50ms at 1000 tok/s would imply 50 tokens, but capacity is 3.
        for _ in 0..3 {
            assert!(b.try_take());
        }
        assert!(!b.try_take());
    }

    #[test]
    fn resolve_seed_nodes_is_additive_and_dedups() {
        // The hardcoded list is empty pre-launch, so the result is
        // exactly the operator-provided extras with duplicates
        // collapsed.  When the list is later populated this same
        // test still proves the ordering invariant: hardcoded first,
        // extras appended, no duplicates.
        let extra = vec![
            "203.0.113.10:8444".to_string(),
            "203.0.113.11:8444".to_string(),
            "203.0.113.10:8444".to_string(), // duplicate
        ];
        let resolved = resolve_seed_nodes(&extra);
        for s in hardcoded_seed_nodes() {
            assert!(resolved.iter().any(|r| r == s));
        }
        assert!(resolved.contains(&"203.0.113.10:8444".to_string()));
        assert!(resolved.contains(&"203.0.113.11:8444".to_string()));
        let count = resolved
            .iter()
            .filter(|r| *r == "203.0.113.10:8444")
            .count();
        assert_eq!(count, 1, "duplicates must be collapsed");
    }

    #[test]
    fn resolve_dns_seeds_returns_empty_when_disabled() {
        let extra = vec!["seed.example.org".to_string()];
        let resolved = resolve_dns_seeds(&extra, true);
        assert!(
            resolved.is_empty(),
            "disabled flag must drop both hardcoded and configured seeds",
        );
    }

    #[test]
    fn resolve_dns_seeds_merges_when_enabled() {
        let extra = vec!["seed.example.org".to_string()];
        let resolved = resolve_dns_seeds(&extra, false);
        assert!(resolved.contains(&"seed.example.org".to_string()));
    }
}
