//! Configuration file support.
//!
//! The daemon reads `bitaiir.toml` (or a path given via `--config`)
//! on startup.  Settings follow a three-level priority cascade:
//!
//!     CLI flag  >  config file  >  compiled default
//!
//! On first run, if no config file exists, a commented-out template is
//! written so the user can see every available knob.

use serde::Deserialize;
use std::path::Path;

// -------------------------------------------------------------------------
// Config struct (mirrors every CLI-configurable field)
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub mining: MiningConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub mempool: MempoolConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct NetworkConfig {
    /// Run on the testnet network instead of mainnet.
    pub testnet: Option<bool>,
    pub rpc_addr: Option<String>,
    pub p2p_addr: Option<String>,
    pub connect: Option<Vec<String>>,
    /// Token-bucket refill rate per peer, in messages per second.
    /// Defaults to 100 when unset.  Normal block/tx relay sits well
    /// under this; values lower than ~20 risk starving legitimate
    /// peers during catch-up.
    pub rate_limit_msgs_per_sec: Option<u32>,
    /// Token-bucket capacity per peer (maximum burst).  Defaults to
    /// 200.  Must be `>= rate_limit_msgs_per_sec` or bursts will be
    /// dropped even at the configured steady-state rate.
    pub rate_limit_burst: Option<u32>,
    /// Duration (seconds) for which a peer is banned after violating
    /// the rate limit.  Defaults to 600 (10 minutes).  The ban is
    /// persisted to the `known_peers` table if the peer has an
    /// outbound history; in-memory only for inbound-only peers.
    pub rate_limit_ban_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MiningConfig {
    pub enabled: Option<bool>,
    pub threads: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct StorageConfig {
    pub data_dir: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MempoolConfig {
    /// Upper bound on total serialized bytes held in the mempool.
    /// When reached, the lowest-priority transactions (highest
    /// tx-PoW hash, newest arrival on ties) are evicted to make
    /// room for incoming ones.  Defaults to
    /// [`bitaiir_chain::consensus::DEFAULT_MAX_MEMPOOL_BYTES`]
    /// (50 MB) when unset.
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RpcConfig {
    /// Explicit RPC user name.  If both `user` and `password` are
    /// set, the daemon authenticates clients with HTTP Basic auth
    /// against these credentials and does NOT generate a cookie
    /// file.  Useful when the RPC port is exposed on a LAN or
    /// behind a reverse proxy — the same credentials must be
    /// reachable by the client (e.g. passed to `bitaiir-cli` via
    /// `--rpc-user` and `--rpc-password`).
    pub user: Option<String>,
    /// Explicit RPC password.  Paired with `user`; see above.
    pub password: Option<String>,
    /// IP allowlist for incoming RPC connections.  Each entry is a
    /// single IP or a CIDR block (e.g. `"127.0.0.1"`,
    /// `"192.168.1.0/24"`).  When set, only connections from
    /// matching IPs are proxied to the JSON-RPC server; all others
    /// are silently dropped at the TCP level.  When unset, any IP
    /// can reach the RPC server (auth is still enforced).
    pub allow_ip: Option<Vec<String>>,
    /// Serve the RPC endpoint over HTTPS instead of plain HTTP.  When
    /// `true` and neither `tls_cert_path` nor `tls_key_path` is set,
    /// the daemon generates a self-signed cert pair (`rpc.cert` +
    /// `rpc.key`) in the data directory on first startup and reuses
    /// it on subsequent runs.  When paths are provided, the daemon
    /// loads them as-is — use this to plug in a cert signed by a real
    /// CA (Let's Encrypt, internal PKI, etc.) for LAN / production.
    pub tls: Option<bool>,
    /// Path to a PEM-encoded TLS certificate (chain).  Only read when
    /// `tls = true`.  When unset, defaults to
    /// `<data_dir>/rpc.cert` (auto-generated on first run).
    pub tls_cert_path: Option<String>,
    /// Path to a PEM-encoded TLS private key.  Only read when
    /// `tls = true`.  When unset, defaults to `<data_dir>/rpc.key`.
    pub tls_key_path: Option<String>,
}

// -------------------------------------------------------------------------
// Defaults (network-dependent — resolved at runtime)
// -------------------------------------------------------------------------

/// Default RPC address for the currently-active network.
pub fn default_rpc_addr() -> String {
    format!(
        "127.0.0.1:{}",
        bitaiir_types::Network::active().default_rpc_port()
    )
}

/// Default P2P address for the currently-active network.
pub fn default_p2p_addr() -> String {
    format!(
        "127.0.0.1:{}",
        bitaiir_types::Network::active().default_p2p_port()
    )
}

/// Default data directory for the currently-active network.
pub fn default_data_dir() -> String {
    bitaiir_types::Network::active()
        .default_data_dir()
        .to_string()
}

/// Default mempool capacity in bytes — sourced from the chain
/// crate so consensus and daemon agree on the same compile-time
/// constant.
pub fn default_max_mempool_bytes() -> usize {
    bitaiir_chain::consensus::DEFAULT_MAX_MEMPOOL_BYTES
}

// -------------------------------------------------------------------------
// Load / create
// -------------------------------------------------------------------------

/// Load a config file, returning `Config::default()` if the file
/// doesn't exist or can't be parsed.
pub fn load_config(path: &Path) -> Config {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse {}: {e}", path.display());
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

/// Write a commented-out template config file if none exists.
pub fn write_default_config(path: &Path) {
    if path.exists() {
        return;
    }
    let template = r#"# BitAiir Core configuration file.
#
# Settings here are overridden by CLI flags.
# Uncomment and edit to customize.

[network]
# testnet = false                    # true runs the testnet network
                                     # (different magic bytes, genesis,
                                     # ports, and data dir)
# rpc_addr = "127.0.0.1:8443"        # mainnet default; testnet is 18443
# p2p_addr = "127.0.0.1:8444"        # mainnet default; testnet is 18444
# connect = ["127.0.0.1:8544"]

# Per-peer message rate limit (token bucket).  A peer that sustains
# more than `rate_limit_msgs_per_sec` messages/second — or bursts
# past `rate_limit_burst` in aggregate — is disconnected and banned
# for `rate_limit_ban_secs` seconds.  Defaults: 100 msgs/s, burst
# 200, ban 600s.
# rate_limit_msgs_per_sec = 100
# rate_limit_burst        = 200
# rate_limit_ban_secs     = 600

[mining]
# enabled = false
# threads = 0        # 0 = auto (min(4, cores/2))

[storage]
# data_dir = "bitaiir_data"          # mainnet default;
                                     # testnet is "bitaiir_testnet_data"

[mempool]
# max_bytes = 50000000               # 50 MB default.  Lower-priority
                                     # txs (higher tx-PoW hash, later
                                     # arrival) are evicted first when
                                     # the pool is full.

[rpc]
# By default the daemon writes a random cookie to
# `<data_dir>/.cookie` on startup.  `bitaiir-cli` on the same
# machine reads that cookie automatically — no config needed.
# Set explicit credentials here to expose RPC on a LAN; the
# cookie file is then NOT generated and clients must pass
# `--rpc-user` / `--rpc-password`.
# user = "bitaiir"
# password = "change-me"

# IP allowlist — if set, only connections from these IPs or CIDR
# ranges reach the RPC server.  All other IPs are dropped at the
# TCP level before authentication is even attempted.  Leave unset
# (or empty) to accept any IP (auth is still enforced).
# allow_ip = ["127.0.0.1", "192.168.1.0/24"]

# Serve RPC over HTTPS instead of plain HTTP.  When true and no
# cert/key paths are set, the daemon generates a self-signed cert
# (10-year validity) in `<data_dir>/rpc.cert` + `<data_dir>/rpc.key`
# on first startup and reuses it on subsequent runs.  Point
# `bitaiir-cli` at `https://host:port`; it auto-trusts the local
# `rpc.cert` file.
# tls = false
# tls_cert_path = "/etc/letsencrypt/live/node.example.com/fullchain.pem"
# tls_key_path  = "/etc/letsencrypt/live/node.example.com/privkey.pem"
"#;
    let _ = std::fs::write(path, template);
}
