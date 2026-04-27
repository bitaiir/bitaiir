//! Prometheus-style metrics endpoint.
//!
//! When `--metrics-addr <ip:port>` is set (or `[metrics] addr` in
//! `bitaiir.toml`), the daemon spawns a tiny HTTP server on that
//! address that serves a single `GET /metrics` endpoint in the
//! Prometheus exposition format.  Operators scrape it from
//! Prometheus / Grafana / VictoriaMetrics and alert on anomalies
//! (height stalled, peer count zero, mempool exploding, etc.).
//!
//! The endpoint is **off by default**: enabling it requires an
//! explicit address.  Bind to `127.0.0.1:<port>` for local-only
//! scraping; expose externally via a reverse proxy with HTTP Basic
//! auth or IP allowlisting (the metrics server itself has neither).
//!
//! Privacy: no wallet balances, addresses, or transaction details
//! are emitted — only chain / network / mempool / mining counters.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{Router, extract::State, response::IntoResponse, routing::get};
use bitaiir_rpc::{PeerDirection, SharedState};

/// Shared snapshot of everything the `/metrics` handler needs.
struct MetricsState {
    node: SharedState,
    mining_active: Arc<AtomicBool>,
    mining_threads: usize,
}

/// Spawn the metrics HTTP server as a background task.
///
/// Returns the JoinHandle so the daemon can await it at shutdown.
/// Returns `None` if `addr` failed to parse — the caller logs and
/// continues without metrics rather than crashing the daemon.
pub fn spawn(
    addr: &str,
    node: SharedState,
    mining_active: Arc<AtomicBool>,
    mining_threads: usize,
    events: Option<std::sync::mpsc::Sender<String>>,
) -> Option<tokio::task::JoinHandle<()>> {
    let bind: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            crate::log::log_warn(
                &format!("Metrics: --metrics-addr {addr} parse failed: {e} (metrics disabled)"),
                &events,
            );
            return None;
        }
    };

    let state = Arc::new(MetricsState {
        node,
        mining_active,
        mining_threads,
    });

    let app = Router::new()
        .route("/", get(root))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    Some(tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                crate::log::log_warn(
                    &format!("Metrics: cannot bind {bind}: {e} (metrics disabled)"),
                    &events,
                );
                return;
            }
        };
        crate::log::log_info(
            &format!("Metrics server listening on http://{bind}/metrics"),
            &events,
        );
        if let Err(e) = axum::serve(listener, app).await {
            crate::log::log_warn(&format!("Metrics server crashed: {e}"), &events);
        }
    }))
}

async fn root() -> &'static str {
    "BitAiir metrics endpoint.  See /metrics for Prometheus exposition."
}

async fn metrics_handler(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    // Snapshot under the read lock; release it before formatting so
    // we're not holding the chain locked during string concatenation.
    let snapshot = {
        let s = state.node.read().await;
        let mut outbound = 0usize;
        let mut inbound = 0usize;
        for p in &s.peers {
            match p.direction {
                PeerDirection::Outbound => outbound += 1,
                PeerDirection::Inbound => inbound += 1,
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let banned_active = s.banned_ips.values().filter(|b| b.deadline > now).count();
        Snapshot {
            height: s.chain.height(),
            mempool_count: s.mempool.iter().count(),
            mempool_bytes: s.mempool.total_bytes(),
            peers_outbound: outbound,
            peers_inbound: inbound,
            known_peers: s.known_peers.len(),
            banned_ips: banned_active,
            pending_spends: s.pending_spends.len(),
            wallet_unlocked: s.wallet_unlocked,
            wallet_encrypted: s.wallet_encrypted,
        }
    };

    let mining_active = state.mining_active.load(Ordering::Relaxed);
    let mining_threads = state.mining_threads;

    let body = render_prometheus(&snapshot, mining_active, mining_threads);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

struct Snapshot {
    height: u64,
    mempool_count: usize,
    mempool_bytes: usize,
    peers_outbound: usize,
    peers_inbound: usize,
    known_peers: usize,
    banned_ips: usize,
    pending_spends: usize,
    wallet_unlocked: bool,
    wallet_encrypted: bool,
}

fn render_prometheus(s: &Snapshot, mining_active: bool, mining_threads: usize) -> String {
    let network = bitaiir_types::Network::active().name();
    let mut out = String::new();

    out.push_str("# HELP bitaiir_chain_height Current chain tip height.\n");
    out.push_str("# TYPE bitaiir_chain_height gauge\n");
    out.push_str(&format!(
        "bitaiir_chain_height{{network=\"{network}\"}} {}\n",
        s.height
    ));

    out.push_str("\n# HELP bitaiir_peers Currently connected peers, by direction.\n");
    out.push_str("# TYPE bitaiir_peers gauge\n");
    out.push_str(&format!(
        "bitaiir_peers{{network=\"{network}\",direction=\"outbound\"}} {}\n",
        s.peers_outbound
    ));
    out.push_str(&format!(
        "bitaiir_peers{{network=\"{network}\",direction=\"inbound\"}} {}\n",
        s.peers_inbound
    ));

    out.push_str(
        "\n# HELP bitaiir_known_peers Total peers in the address book (connected or not).\n",
    );
    out.push_str("# TYPE bitaiir_known_peers gauge\n");
    out.push_str(&format!(
        "bitaiir_known_peers{{network=\"{network}\"}} {}\n",
        s.known_peers
    ));

    out.push_str("\n# HELP bitaiir_banned_ips IPs currently banned for misbehavior.\n");
    out.push_str("# TYPE bitaiir_banned_ips gauge\n");
    out.push_str(&format!(
        "bitaiir_banned_ips{{network=\"{network}\"}} {}\n",
        s.banned_ips
    ));

    out.push_str("\n# HELP bitaiir_mempool_transactions Transactions currently in the mempool.\n");
    out.push_str("# TYPE bitaiir_mempool_transactions gauge\n");
    out.push_str(&format!(
        "bitaiir_mempool_transactions{{network=\"{network}\"}} {}\n",
        s.mempool_count
    ));

    out.push_str("\n# HELP bitaiir_mempool_bytes Mempool size in serialized bytes.\n");
    out.push_str("# TYPE bitaiir_mempool_bytes gauge\n");
    out.push_str(&format!(
        "bitaiir_mempool_bytes{{network=\"{network}\"}} {}\n",
        s.mempool_bytes
    ));

    out.push_str(
        "\n# HELP bitaiir_pending_spends UTXOs reserved by in-flight sendtoaddress calls.\n",
    );
    out.push_str("# TYPE bitaiir_pending_spends gauge\n");
    out.push_str(&format!(
        "bitaiir_pending_spends{{network=\"{network}\"}} {}\n",
        s.pending_spends
    ));

    out.push_str("\n# HELP bitaiir_mining_active 1 if mining is currently running.\n");
    out.push_str("# TYPE bitaiir_mining_active gauge\n");
    out.push_str(&format!(
        "bitaiir_mining_active{{network=\"{network}\"}} {}\n",
        if mining_active { 1 } else { 0 }
    ));

    out.push_str("\n# HELP bitaiir_mining_threads Configured mining thread count.\n");
    out.push_str("# TYPE bitaiir_mining_threads gauge\n");
    out.push_str(&format!(
        "bitaiir_mining_threads{{network=\"{network}\"}} {mining_threads}\n",
    ));

    out.push_str("\n# HELP bitaiir_wallet_encrypted 1 if the wallet on disk is encrypted.\n");
    out.push_str("# TYPE bitaiir_wallet_encrypted gauge\n");
    out.push_str(&format!(
        "bitaiir_wallet_encrypted{{network=\"{network}\"}} {}\n",
        if s.wallet_encrypted { 1 } else { 0 }
    ));

    out.push_str(
        "\n# HELP bitaiir_wallet_unlocked 1 if the wallet is currently unlocked (can sign).\n",
    );
    out.push_str("# TYPE bitaiir_wallet_unlocked gauge\n");
    out.push_str(&format!(
        "bitaiir_wallet_unlocked{{network=\"{network}\"}} {}\n",
        if s.wallet_unlocked { 1 } else { 0 }
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            height: 42,
            mempool_count: 3,
            mempool_bytes: 1234,
            peers_outbound: 5,
            peers_inbound: 2,
            known_peers: 50,
            banned_ips: 1,
            pending_spends: 0,
            wallet_unlocked: true,
            wallet_encrypted: false,
        }
    }

    #[test]
    fn render_includes_every_metric() {
        let s = sample_snapshot();
        let body = render_prometheus(&s, true, 4);
        for needle in [
            "bitaiir_chain_height",
            "bitaiir_peers",
            "bitaiir_known_peers",
            "bitaiir_banned_ips",
            "bitaiir_mempool_transactions",
            "bitaiir_mempool_bytes",
            "bitaiir_pending_spends",
            "bitaiir_mining_active",
            "bitaiir_mining_threads",
            "bitaiir_wallet_encrypted",
            "bitaiir_wallet_unlocked",
        ] {
            assert!(body.contains(needle), "missing metric {needle}");
        }
    }

    #[test]
    fn render_emits_help_and_type_per_metric() {
        let s = sample_snapshot();
        let body = render_prometheus(&s, false, 0);
        // Prometheus exposition spec: each metric needs `# HELP` and
        // `# TYPE` lines before its samples.
        let help_lines = body.lines().filter(|l| l.starts_with("# HELP")).count();
        let type_lines = body.lines().filter(|l| l.starts_with("# TYPE")).count();
        assert_eq!(help_lines, type_lines);
        assert!(
            help_lines >= 11,
            "expected at least 11 metrics, got {help_lines}"
        );
    }

    #[test]
    fn render_uses_network_label() {
        let s = sample_snapshot();
        let body = render_prometheus(&s, true, 4);
        // Whichever network is active in the test runner, the label
        // must appear consistently.
        let network = bitaiir_types::Network::active().name();
        let needle = format!("network=\"{network}\"");
        assert!(body.contains(&needle));
    }
}
