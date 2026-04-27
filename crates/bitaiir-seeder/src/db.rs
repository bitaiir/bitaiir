//! Persistent peer-history store backed by redb.
//!
//! One single-file ACID database keeps everything the crawler and
//! the DNS handler need to share: discovery time, last attempt, last
//! success, success / failure counters, and the most recent
//! `best_height` we got back from the peer.
//!
//! The schema is **one table** keyed by string `"ip:port"`.  Values
//! are a tiny hand-rolled binary format (fixed 40-byte header + a
//! length-prefixed user-agent string).  It's small enough that
//! adding `bincode` or `serde` for it would be more dependency than
//! it's worth.

use std::net::SocketAddr;
use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");

/// One peer's running stats.  `addr` is implicit (it's the row key).
#[derive(Debug, Clone, Default)]
pub struct PeerRecord {
    pub discovered_at: u64,
    pub last_attempt: u64,
    pub last_success: u64,
    pub success_count: u32,
    pub failure_count: u32,
    pub last_height: u64,
    pub last_user_agent: String,
}

impl PeerRecord {
    fn encode(&self) -> Vec<u8> {
        let ua = self.last_user_agent.as_bytes();
        let mut out = Vec::with_capacity(44 + ua.len());
        out.extend_from_slice(&self.discovered_at.to_le_bytes());
        out.extend_from_slice(&self.last_attempt.to_le_bytes());
        out.extend_from_slice(&self.last_success.to_le_bytes());
        out.extend_from_slice(&self.success_count.to_le_bytes());
        out.extend_from_slice(&self.failure_count.to_le_bytes());
        out.extend_from_slice(&self.last_height.to_le_bytes());
        out.extend_from_slice(&(ua.len() as u32).to_le_bytes());
        out.extend_from_slice(ua);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 44 {
            return None;
        }
        let discovered_at = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let last_attempt = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let last_success = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let success_count = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
        let failure_count = u32::from_le_bytes(bytes[28..32].try_into().ok()?);
        let last_height = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let ua_len = u32::from_le_bytes(bytes[40..44].try_into().ok()?) as usize;
        if bytes.len() < 44 + ua_len {
            return None;
        }
        let last_user_agent = String::from_utf8(bytes[44..44 + ua_len].to_vec()).ok()?;
        Some(Self {
            discovered_at,
            last_attempt,
            last_success,
            success_count,
            failure_count,
            last_height,
            last_user_agent,
        })
    }

    /// Has this peer responded successfully recently enough to be a
    /// good DNS answer?  `recent_secs` controls the window.
    pub fn is_healthy(&self, now: u64, recent_secs: u64) -> bool {
        if self.last_success == 0 {
            return false;
        }
        if now.saturating_sub(self.last_success) > recent_secs {
            return false;
        }
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return false;
        }
        // Require >= 50 % success rate, smoothed by adding 1 to both
        // numerator and denominator so a single early failure doesn't
        // permanently disqualify a fresh peer.
        let num = self.success_count as u64 + 1;
        let den = total as u64 + 1;
        num * 2 >= den
    }
}

pub struct Db {
    inner: Database,
}

/// Result alias used across the DB API.  We stringify redb errors at
/// the boundary so callers don't have to depend on the redb error type
/// (callers stringify or discard, never introspect).
pub type DbResult<T> = Result<T, String>;

fn stringify<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

impl Db {
    /// Open (or create) the seeder database file at `path`.
    pub fn open(path: &Path) -> DbResult<Self> {
        let inner = Database::create(path).map_err(stringify)?;
        // Create the table on first run so subsequent reads don't
        // fail with TableDoesNotExist.
        let txn = inner.begin_write().map_err(stringify)?;
        {
            let _t = txn.open_table(PEERS).map_err(stringify)?;
        }
        txn.commit().map_err(stringify)?;
        Ok(Self { inner })
    }

    fn read(&self, addr: &str) -> DbResult<PeerRecord> {
        let txn = self.inner.begin_read().map_err(stringify)?;
        let table = txn.open_table(PEERS).map_err(stringify)?;
        let value = table
            .get(addr)
            .map_err(stringify)?
            .and_then(|v| PeerRecord::decode(v.value()))
            .unwrap_or_default();
        Ok(value)
    }

    fn write(&self, addr: &str, rec: &PeerRecord) -> DbResult<()> {
        let txn = self.inner.begin_write().map_err(stringify)?;
        {
            let mut table = txn.open_table(PEERS).map_err(stringify)?;
            let bytes = rec.encode();
            table.insert(addr, bytes.as_slice()).map_err(stringify)?;
        }
        txn.commit().map_err(stringify)?;
        Ok(())
    }

    /// Insert a peer if absent, marking it as freshly discovered.
    pub fn ensure_known(&self, addr: &str, now: u64) -> DbResult<()> {
        let mut rec = self.read(addr)?;
        if rec.discovered_at == 0 {
            rec.discovered_at = now;
            self.write(addr, &rec)?;
        }
        Ok(())
    }

    /// Bump `last_attempt` (called right before we try to connect) so
    /// a flapping peer's cooldown still ticks even when the connect
    /// itself never returns.
    pub fn record_attempt(&self, addr: &str, now: u64) -> DbResult<()> {
        let mut rec = self.read(addr)?;
        if rec.discovered_at == 0 {
            rec.discovered_at = now;
        }
        rec.last_attempt = now;
        self.write(addr, &rec)
    }

    pub fn record_success(
        &self,
        addr: &str,
        now: u64,
        height: u64,
        user_agent: &str,
    ) -> DbResult<()> {
        let mut rec = self.read(addr)?;
        if rec.discovered_at == 0 {
            rec.discovered_at = now;
        }
        rec.last_attempt = now;
        rec.last_success = now;
        rec.success_count = rec.success_count.saturating_add(1);
        rec.last_height = height;
        rec.last_user_agent = user_agent.to_string();
        self.write(addr, &rec)
    }

    pub fn record_failure(&self, addr: &str, now: u64) -> DbResult<()> {
        let mut rec = self.read(addr)?;
        if rec.discovered_at == 0 {
            rec.discovered_at = now;
        }
        rec.last_attempt = now;
        rec.failure_count = rec.failure_count.saturating_add(1);
        self.write(addr, &rec)
    }

    /// Pick up to `max` peers that haven't been tried in the last
    /// `cooldown_secs` seconds.  Order: never-tried first, then the
    /// peers we last tried longest ago.
    pub fn candidates_to_crawl(
        &self,
        max: usize,
        now: u64,
        cooldown_secs: u64,
    ) -> DbResult<Vec<String>> {
        let txn = self.inner.begin_read().map_err(stringify)?;
        let table = txn.open_table(PEERS).map_err(stringify)?;
        let mut rows: Vec<(String, u64)> = Vec::new();
        for entry in table.iter().map_err(stringify)? {
            let (k, v) = entry.map_err(stringify)?;
            let Some(rec) = PeerRecord::decode(v.value()) else {
                continue;
            };
            if now.saturating_sub(rec.last_attempt) < cooldown_secs && rec.last_attempt != 0 {
                continue;
            }
            rows.push((k.value().to_string(), rec.last_attempt));
        }
        rows.sort_by_key(|r| r.1); // smallest last_attempt = oldest = first
        rows.truncate(max);
        Ok(rows.into_iter().map(|(a, _)| a).collect())
    }

    /// Up to `max` peers fit to serve as DNS A records: healthy in
    /// the last `recent_secs`, parseable as `SocketAddr`.  Sorted
    /// most-recent-success first.
    pub fn top_for_dns(&self, max: usize, now: u64, recent_secs: u64) -> DbResult<Vec<SocketAddr>> {
        let txn = self.inner.begin_read().map_err(stringify)?;
        let table = txn.open_table(PEERS).map_err(stringify)?;
        let mut rows: Vec<(SocketAddr, u64)> = Vec::new();
        for entry in table.iter().map_err(stringify)? {
            let (k, v) = entry.map_err(stringify)?;
            let Some(rec) = PeerRecord::decode(v.value()) else {
                continue;
            };
            if !rec.is_healthy(now, recent_secs) {
                continue;
            }
            let Ok(sa) = k.value().parse::<SocketAddr>() else {
                continue;
            };
            rows.push((sa, rec.last_success));
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        rows.truncate(max);
        Ok(rows.into_iter().map(|(a, _)| a).collect())
    }

    /// Total rows in the peer table — used by `/stats` and the
    /// startup banner.
    pub fn count(&self) -> DbResult<usize> {
        let txn = self.inner.begin_read().map_err(stringify)?;
        let table = txn.open_table(PEERS).map_err(stringify)?;
        Ok(table.len().map_err(stringify)? as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_db() -> (tempfile::TempDir, Db) {
        let dir = tempdir().unwrap();
        let db = Db::open(&dir.path().join("seeder.redb")).unwrap();
        (dir, db)
    }

    #[test]
    fn record_round_trip() {
        let original = PeerRecord {
            discovered_at: 1,
            last_attempt: 2,
            last_success: 3,
            success_count: 4,
            failure_count: 5,
            last_height: 6,
            last_user_agent: "BitAiir Core/0.1.0".into(),
        };
        let bytes = original.encode();
        let decoded = PeerRecord::decode(&bytes).unwrap();
        assert_eq!(decoded.discovered_at, 1);
        assert_eq!(decoded.last_user_agent, "BitAiir Core/0.1.0");
        assert_eq!(decoded.last_height, 6);
    }

    #[test]
    fn ensure_known_then_record_success() {
        let (_d, db) = fresh_db();
        db.ensure_known("1.2.3.4:18444", 100).unwrap();
        assert_eq!(db.count().unwrap(), 1);

        db.record_success("1.2.3.4:18444", 200, 42, "BitAiir/0.1")
            .unwrap();

        // After one success and zero failures it should be healthy.
        let dns = db.top_for_dns(10, 250, 60).unwrap();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].to_string(), "1.2.3.4:18444");
    }

    #[test]
    fn unhealthy_peers_are_excluded_from_dns() {
        let (_d, db) = fresh_db();
        // 9.9.9.9: 1 success, 0 failures, recent → healthy.
        db.record_success("9.9.9.9:18444", 100, 1, "ua").unwrap();
        // 8.8.8.8: 1 success, 5 failures → below the 50 % bar.
        db.record_success("8.8.8.8:18444", 100, 1, "ua").unwrap();
        for _ in 0..5 {
            db.record_failure("8.8.8.8:18444", 100).unwrap();
        }
        // 7.7.7.7: success was a long time ago → stale.
        db.record_success("7.7.7.7:18444", 1, 1, "ua").unwrap();

        // now=120, recent_secs=60: 9.9.9.9 (success 20 s ago) and
        // 8.8.8.8 (also 20 s ago) are within the freshness window;
        // 7.7.7.7 (success 119 s ago) is stale.  Health filter drops
        // 8.8.8.8 on success rate, 7.7.7.7 on staleness.
        let dns = db.top_for_dns(10, 120, 60).unwrap();
        let addrs: Vec<String> = dns.iter().map(|a| a.to_string()).collect();
        assert!(addrs.contains(&"9.9.9.9:18444".to_string()));
        assert!(!addrs.contains(&"8.8.8.8:18444".to_string()));
        assert!(!addrs.contains(&"7.7.7.7:18444".to_string()));
    }

    #[test]
    fn candidates_skip_recently_attempted() {
        let (_d, db) = fresh_db();
        db.record_attempt("a:1", 100).unwrap();
        db.record_attempt("b:1", 50).unwrap();
        db.ensure_known("c:1", 100).unwrap();

        // Now=110, cooldown=30 → "a" attempted 10s ago is skipped,
        // "b" attempted 60s ago is fine, "c" never attempted is fine.
        let cands = db.candidates_to_crawl(10, 110, 30).unwrap();
        assert!(!cands.contains(&"a:1".to_string()));
        assert!(cands.contains(&"b:1".to_string()));
        assert!(cands.contains(&"c:1".to_string()));
        // Order: never-tried first, then oldest attempted.
        assert_eq!(cands[0], "c:1");
        assert_eq!(cands[1], "b:1");
    }
}
