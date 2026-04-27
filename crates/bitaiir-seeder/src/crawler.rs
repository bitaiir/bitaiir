//! Background crawler.
//!
//! In a loop:
//!   1. Pull up to `CRAWL_BATCH` candidates from the DB (never-tried
//!      first, then oldest-attempted).
//!   2. For each, try a TCP connect → handshake → `getaddr` →
//!      collect the returned `addr` list, with a wall-clock timeout.
//!   3. Record success / failure in the DB.  Newly-learnt addrs are
//!      `ensure_known`-inserted so the next round picks them up.
//!
//! Concurrency is bounded by `CRAWL_PARALLELISM`; each task spawns
//! one TCP connection and lives for at most `CONNECT_TIMEOUT` +
//! `HANDSHAKE_TIMEOUT` + `GETADDR_TIMEOUT`.  After each round we
//! sleep `ROUND_INTERVAL` so we don't hammer peers — the seeder is
//! a slow scout, not a load test.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitaiir_net::Peer;
use bitaiir_net::message::NetMessage;
use bitaiir_net::protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::db::Db;

const CRAWL_BATCH: usize = 64;
const CRAWL_PARALLELISM: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const GETADDR_TIMEOUT: Duration = Duration::from_secs(8);
const ROUND_INTERVAL: Duration = Duration::from_secs(20);
const CRAWL_COOLDOWN_SECS: u64 = 5 * 60; // skip peers tried within 5 min

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Top-level crawler loop.  Runs until `shutdown` flips to true.
pub async fn run(db: Arc<Db>, shutdown: Arc<AtomicBool>) {
    info!(target: "seeder.crawler", "crawler starting");
    while !shutdown.load(Ordering::Relaxed) {
        if let Err(e) = crawl_round(&db).await {
            warn!(target: "seeder.crawler", error = %e, "crawl round failed");
        }
        // Sleep in 1 s slices so a Ctrl-C is responsive.
        for _ in 0..(ROUND_INTERVAL.as_secs()) {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    info!(target: "seeder.crawler", "crawler stopped");
}

async fn crawl_round(db: &Arc<Db>) -> Result<(), String> {
    let now = unix_now();
    let candidates = db
        .candidates_to_crawl(CRAWL_BATCH, now, CRAWL_COOLDOWN_SECS)
        .map_err(|e| format!("db: {e}"))?;
    if candidates.is_empty() {
        return Ok(());
    }
    let total_db = db.count().unwrap_or(0);
    info!(
        target: "seeder.crawler",
        attempts = candidates.len(),
        known = total_db,
        "crawling round"
    );

    let mut handles = Vec::with_capacity(candidates.len());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(CRAWL_PARALLELISM));

    for addr in candidates {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed
        };
        let db = db.clone();
        let handles_ref = &mut handles;
        handles_ref.push(tokio::spawn(async move {
            // Stamp `last_attempt` before we even start — keeps the
            // cooldown ticking on tarpitting peers whose connect
            // never returns.
            let _ = db.record_attempt(&addr, unix_now());
            let outcome = crawl_one(&addr).await;
            let now = unix_now();
            match outcome {
                Ok(CrawlOk {
                    user_agent,
                    height,
                    learned,
                }) => {
                    let _ = db.record_success(&addr, now, height, &user_agent);
                    for new_addr in learned {
                        let _ = db.ensure_known(&new_addr, now);
                    }
                }
                Err(_) => {
                    let _ = db.record_failure(&addr, now);
                }
            }
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

struct CrawlOk {
    user_agent: String,
    height: u64,
    learned: Vec<String>,
}

/// Connect, handshake, run getaddr, return what we learnt.  Bounded
/// by all three timeouts so a tarpitting peer can't stall the loop.
async fn crawl_one(addr: &str) -> Result<CrawlOk, String> {
    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect {addr}: {e}")),
        Err(_) => return Err(format!("connect {addr}: timeout")),
    };
    let peer_addr = stream
        .peer_addr()
        .map_err(|e| format!("peer_addr {addr}: {e}"))?;
    let mut peer = Peer::new(stream, peer_addr);

    // Use 0 as our advertised height — we're a seeder, not a sync
    // candidate.  The remote can still tell us its own height.
    let version = match tokio::time::timeout(HANDSHAKE_TIMEOUT, peer.handshake_outbound(0)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("handshake {addr}: {e}")),
        Err(_) => return Err(format!("handshake {addr}: timeout")),
    };

    let (mut reader, mut writer, _addr) = peer.into_parts();

    // Send GetAddr.
    let getaddr = NetMessage::GetAddr;
    let payload = getaddr.to_payload();
    let frame = protocol::frame_message(getaddr.command(), &payload);
    if writer.write_all(&frame).await.is_err() {
        return Ok(CrawlOk {
            user_agent: version.user_agent,
            height: version.best_height,
            learned: Vec::new(),
        });
    }
    let _ = writer.flush().await;

    // Read messages until we see the Addr response or time out.
    let mut learned = Vec::new();
    let read_loop = async {
        loop {
            let mut header_buf = [0u8; protocol::HEADER_SIZE];
            reader.read_exact(&mut header_buf).await?;
            let header = protocol::parse_header(&header_buf)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad magic"))?;
            let mut payload = vec![0u8; header.payload_len as usize];
            if !payload.is_empty() {
                reader.read_exact(&mut payload).await?;
            }
            if let Some(NetMessage::Addr(peers)) =
                NetMessage::from_payload(&header.command, &payload)
            {
                let collected: Vec<String> = peers.into_iter().map(|p| p.addr).collect();
                return Ok::<Vec<String>, std::io::Error>(collected);
            }
            // Ignore anything else; some peers send pings before we
            // get the addr reply.
        }
    };
    if let Ok(Ok(addrs)) = tokio::time::timeout(GETADDR_TIMEOUT, read_loop).await {
        learned = addrs;
    }

    Ok(CrawlOk {
        user_agent: version.user_agent,
        height: version.best_height,
        learned,
    })
}
