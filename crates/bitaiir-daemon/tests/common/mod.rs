//! Test helper: spawn a real `bitaiird` process, drive it over
//! JSON-RPC, and tear it down cleanly.
//!
//! Every test scenario in `tests/multinode.rs` builds on this —
//! nothing here is BitAiir-specific except the command line and the
//! RPC method names.  The helper:
//!
//!   - Picks unused TCP ports from the OS so tests run in parallel
//!     without colliding.
//!   - Spawns `bitaiird` with `--testnet`, a unique data dir, and
//!     cookie auth (default).
//!   - Waits for the RPC endpoint to respond before returning.
//!   - Kills the child process and cleans the data dir on `Drop`.
//!
//! Test binaries discover the compiled `bitaiird` through the
//! cargo-injected env var `CARGO_BIN_EXE_bitaiird`, so they always
//! use the up-to-date build from the current `cargo test` run.

#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde_json::Value;
use tempfile::TempDir;

/// Bind a TCP socket to port 0, let the kernel assign a free port,
/// then drop the listener so `bitaiird` can grab it.  There's a
/// microscopic race window between drop and re-bind, but inside a
/// single test runner it's never an issue in practice.
pub fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// A running `bitaiird` child process plus the RPC client that
/// talks to it.  Owned by the test; dropping kills the daemon.
pub struct TestNode {
    child: Option<Child>,
    data_dir: Option<TempDir>,
    /// Manual path — set when the data dir ownership has been moved
    /// out via [`take_data_dir`], so `Drop` still knows where it is.
    data_dir_path: PathBuf,
    pub rpc_port: u16,
    pub p2p_port: u16,
    client: HttpClient,
}

impl TestNode {
    /// Spawn a fresh testnet daemon with a new tempdir.
    pub async fn spawn() -> Self {
        Self::spawn_with(NodeConfig::default()).await
    }

    /// Spawn a daemon with custom configuration.  Panics if the
    /// process doesn't become RPC-ready within 60 seconds (long to
    /// tolerate CI runners mining the first genesis block).
    pub async fn spawn_with(cfg: NodeConfig) -> Self {
        let NodeConfig {
            rpc_port,
            p2p_port,
            config_toml,
            reuse_dir,
            connect,
        } = cfg;

        let data_dir = reuse_dir.unwrap_or_else(|| TempDir::new().expect("create temp data dir"));
        let data_dir_path = data_dir.path().to_path_buf();
        let rpc_port = rpc_port.unwrap_or_else(pick_free_port);
        let p2p_port = p2p_port.unwrap_or_else(pick_free_port);
        let tls_enabled = config_toml
            .as_deref()
            .map(|s| s.contains("tls = true"))
            .unwrap_or(false);

        if let Some(toml) = &config_toml {
            let path = data_dir_path.join("bitaiir.toml");
            std::fs::write(&path, toml).expect("write config file");
        }

        // Remove any stale cookie from a previous daemon on the
        // same data dir — otherwise the test framework risks
        // reading the old token before the new daemon rewrites it.
        let cookie_path = data_dir_path.join(".cookie");
        let _ = std::fs::remove_file(&cookie_path);

        let bin = env!("CARGO_BIN_EXE_bitaiird");
        let mut cmd = Command::new(bin);
        cmd.arg("--testnet")
            .arg("--data-dir")
            .arg(&data_dir_path)
            .arg("--rpc-addr")
            .arg(format!("127.0.0.1:{rpc_port}"))
            .arg("--p2p-addr")
            .arg(format!("127.0.0.1:{p2p_port}"))
            .arg("--config")
            .arg(data_dir_path.join("bitaiir.toml"));
        for addr in connect {
            cmd.arg("--connect").arg(addr);
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let child = cmd.spawn().expect("spawn bitaiird");

        // Wait for the cookie file — means RPC auth resolution
        // finished and the listener is about to come up.
        wait_for_file(&cookie_path, Duration::from_secs(60))
            .await
            .unwrap_or_else(|e| panic!("daemon {rpc_port} failed to start: {e}"));

        let cookie = std::fs::read_to_string(&cookie_path).expect("read cookie");
        let basic_token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());

        let scheme = if tls_enabled { "https" } else { "http" };
        let url = format!("{scheme}://127.0.0.1:{rpc_port}");

        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Basic {basic_token}")).expect("header value"),
        );
        let mut builder = HttpClientBuilder::default().set_headers(headers);
        if tls_enabled {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls_cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(InsecureVerifier))
                .with_no_client_auth();
            builder = builder.with_custom_cert_store(tls_cfg);
        }
        let client = builder.build(&url).expect("build rpc client");

        let mut node = Self {
            child: Some(child),
            data_dir: Some(data_dir),
            data_dir_path,
            rpc_port,
            p2p_port,
            client,
        };

        // Poll /getblockchaininfo until it responds — full readiness.
        for _ in 0..600 {
            if node
                .rpc::<Value>("getblockchaininfo", rpc_params![])
                .await
                .is_ok()
            {
                return node;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Kill the process before panicking so the port is freed.
        if let Some(mut c) = node.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        panic!("daemon on port {rpc_port} never became RPC-ready");
    }

    /// Issue a JSON-RPC call and deserialize the result.
    pub async fn rpc<T>(
        &self,
        method: &str,
        params: jsonrpsee::core::params::ArrayParams,
    ) -> Result<T, String>
    where
        T: serde::de::DeserializeOwned,
    {
        self.client
            .request(method, params)
            .await
            .map_err(|e| format!("rpc {method}: {e}"))
    }

    /// Current tip height (0 = only genesis).
    pub async fn height(&self) -> u64 {
        let v: Value = self
            .rpc("getblockchaininfo", rpc_params![])
            .await
            .expect("getblockchaininfo");
        v.get("height").and_then(|h| h.as_u64()).unwrap_or(0)
    }

    /// Current tip hash (hex string).
    pub async fn tip_hash(&self) -> String {
        let v: Value = self
            .rpc("getblockchaininfo", rpc_params![])
            .await
            .expect("getblockchaininfo");
        v.get("tip")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    /// Connect this node to another by calling `addpeer`.  Fire-
    /// and-forget — pair with [`wait_for_peers`] if the test
    /// needs the connection to actually be up before proceeding.
    pub async fn connect_to(&self, other: &TestNode) {
        let addr = format!("127.0.0.1:{}", other.p2p_port);
        let _: Value = self
            .rpc("addpeer", rpc_params![addr])
            .await
            .expect("addpeer");
    }

    /// Block until `listpeers` reports at least `count` connected
    /// peers, polling every 100 ms.  `listpeers` returns
    /// `{count, peers}` — we check the numeric `count` field.
    pub async fn wait_for_peers(&self, count: u64, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let resp: Value = self
                .rpc("listpeers", rpc_params![])
                .await
                .unwrap_or(Value::Null);
            let n = resp.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
            if n >= count {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "timeout waiting for {count} peer(s) on port {}",
            self.rpc_port,
        ))
    }

    /// Current mempool size (number of txs).
    pub async fn mempool_size(&self) -> u64 {
        let info: Value = self
            .rpc("getmempoolinfo", rpc_params![])
            .await
            .unwrap_or(Value::Null);
        info.get("size").and_then(|c| c.as_u64()).unwrap_or(0)
    }

    /// Block until mempool has at least `count` entries.
    pub async fn wait_for_mempool(&self, count: u64, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.mempool_size().await >= count {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!(
            "timeout waiting for {count} tx in mempool on port {}",
            self.rpc_port,
        ))
    }

    /// Start / stop the background miner.
    pub async fn set_mining(&self, on: bool) {
        let _: Value = self
            .rpc("setmining", rpc_params![on])
            .await
            .expect("setmining");
    }

    /// Block until the reported chain height is `>= target`, polling
    /// every 100 ms, or return an error on timeout.
    pub async fn wait_for_height(&self, target: u64, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.height().await >= target {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "timeout waiting for height {target} on port {} (current {})",
            self.rpc_port,
            self.height().await,
        ))
    }

    /// Block until the tip hash matches `expected`, polling every
    /// 100 ms.  Used by reorg tests where two chains converge.
    pub async fn wait_for_tip(&self, expected: &str, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.tip_hash().await == expected {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "timeout waiting for tip {expected} on port {} (current {})",
            self.rpc_port,
            self.tip_hash().await,
        ))
    }

    /// Path to this node's data directory (useful for respawning).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir_path
    }

    /// Move the tempdir out so it isn't deleted when this node is
    /// dropped.  Used by the reconnection test that needs to respawn
    /// on the same data.
    pub fn take_data_dir(&mut self) -> TempDir {
        self.data_dir.take().expect("data dir already taken")
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Default)]
pub struct NodeConfig {
    pub rpc_port: Option<u16>,
    pub p2p_port: Option<u16>,
    pub config_toml: Option<String>,
    pub reuse_dir: Option<TempDir>,
    /// Addresses passed as `--connect host:port` — peer_manager
    /// will attempt to dial them on its first tick.  Use this (not
    /// the `addpeer` RPC) when a test needs the full gossip loop
    /// with header-first sync + reorg support.
    pub connect: Vec<String>,
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("file {} never appeared", path.display()))
}

/// Accept any TLS certificate — fine because every test connects
/// back to a daemon on loopback under our own control.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
