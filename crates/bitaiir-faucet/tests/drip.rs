//! End-to-end integration test for the testnet faucet.
//!
//! Spawns:
//!
//!   1. A real `bitaiird --testnet` on a random port, mines a few
//!      mature coinbases so the wallet has spendable balance.
//!   2. A `bitaiir-faucet` process pointed at that daemon.
//!
//! Then drives the faucet's HTTP API and asserts on the daemon's
//! mempool to prove the drip really created a transaction.
//!
//! Marked `#[ignore]` like the daemon's `multinode.rs` tests: it
//! launches actual binaries and Argon2id at 64 MiB takes seconds
//! per block, so it's too slow for the default `cargo test` run.
//!
//!     cargo test --release -p bitaiir-faucet --test drip -- --ignored --nocapture

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use bitaiir_crypto::address::Address;
use bitaiir_crypto::key::PrivateKey;
use serde_json::{Value, json};
use tempfile::TempDir;

const COOKIE_FILE: &str = ".cookie";

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// Generate a fresh keypair and return the corresponding BitAiir
/// address.  We use this instead of `getnewaddress` so the recipient
/// is **not** owned by the daemon's wallet — the daemon rejects
/// `sendtoaddress` calls whose target is one of its own addresses
/// ("cannot send to your own address"), which would otherwise turn
/// every faucet drip in this test into a 502.
fn external_address() -> String {
    let priv_key = PrivateKey::generate();
    let pub_key = priv_key.public_key();
    Address::from_compressed_public_key(&pub_key).to_string()
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

/// Resolve the absolute path to the `bitaiird` binary by deriving
/// it from the faucet binary cargo built for us.  Both end up in
/// the same `target/<profile>/` directory.
fn bitaiird_path() -> PathBuf {
    let faucet = env!("CARGO_BIN_EXE_bitaiir-faucet");
    let target_dir = Path::new(faucet)
        .parent()
        .expect("faucet binary has a parent dir");
    let name = if cfg!(windows) {
        "bitaiird.exe"
    } else {
        "bitaiird"
    };
    let path = target_dir.join(name);
    if !path.exists() {
        panic!(
            "bitaiird not built at {} — run `cargo build --workspace` (or `--release` for the release profile) before running this test.",
            path.display(),
        );
    }
    path
}

/// Block on a closure until it returns `Some` or the deadline passes.
async fn poll<T, F, Fut>(timeout: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

/// Issue a JSON-RPC call to bitaiird on `https://127.0.0.1:<port>`
/// using the cookie file at `<data_dir>/.cookie` and the self-signed
/// cert from `<data_dir>/rpc.cert`.
async fn rpc(
    client: &reqwest::Client,
    url: &str,
    auth: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = client
        .post(url)
        .header("Authorization", format!("Basic {auth}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("rpc {method}: {e}"))?;
    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("rpc {method} parse: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc {method} returned error: {err}"));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| format!("rpc {method} missing result: {v}"))
}

/// One running daemon + the credentials needed to talk to its RPC.
#[allow(dead_code)]
struct Daemon {
    child: Option<Child>,
    _data_dir: TempDir,
    data_dir_path: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    rpc_url: String,
    auth_token: String,
    client: reqwest::Client,
}

impl Daemon {
    async fn spawn() -> Self {
        let data_dir = TempDir::new().expect("tempdir");
        let data_dir_path = data_dir.path().to_path_buf();
        let rpc_port = pick_free_port();
        let p2p_port = pick_free_port();

        let mut cmd = Command::new(bitaiird_path());
        cmd.arg("--testnet")
            .arg("--data-dir")
            .arg(&data_dir_path)
            .arg("--rpc-addr")
            .arg(format!("127.0.0.1:{rpc_port}"))
            .arg("--p2p-addr")
            .arg(format!("127.0.0.1:{p2p_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn bitaiird");

        // Wait for the cookie file — RPC is up shortly after.
        let cookie_path = data_dir_path.join(COOKIE_FILE);
        poll(Duration::from_secs(60), || async {
            tokio::fs::metadata(&cookie_path).await.ok().map(|_| ())
        })
        .await
        .expect("cookie never appeared");

        let cookie = std::fs::read_to_string(&cookie_path).expect("read cookie");
        let auth_token = base64::engine::general_purpose::STANDARD.encode(cookie.trim());

        // Default daemon config has no TLS, so the RPC endpoint is
        // plain HTTP.  No cert to trust, no extra reqwest config.
        let client = reqwest::Client::new();

        let rpc_url = format!("http://127.0.0.1:{rpc_port}");

        // Wait for getblockchaininfo to respond.
        let probe = poll(Duration::from_secs(60), || async {
            rpc(
                &client,
                &rpc_url,
                &auth_token,
                "getblockchaininfo",
                json!([]),
            )
            .await
            .ok()
        })
        .await;
        if probe.is_none() {
            // Cleanup before panicking.
            // (child kill happens in Drop, so we just panic.)
            panic!("daemon never answered getblockchaininfo on {rpc_url}");
        }

        Self {
            child: Some(child),
            _data_dir: data_dir,
            data_dir_path,
            rpc_port,
            p2p_port,
            rpc_url,
            auth_token,
            client,
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        rpc(
            &self.client,
            &self.rpc_url,
            &self.auth_token,
            method,
            params,
        )
        .await
    }

    async fn height(&self) -> u64 {
        let v = self
            .rpc("getblockchaininfo", json!([]))
            .await
            .unwrap_or(Value::Null);
        v.get("height").and_then(|h| h.as_u64()).unwrap_or(0)
    }

    async fn mempool_size(&self) -> u64 {
        let v = self
            .rpc("getmempoolinfo", json!([]))
            .await
            .unwrap_or(Value::Null);
        v.get("size").and_then(|c| c.as_u64()).unwrap_or(0)
    }

    async fn mine_to(&self, target: u64) {
        let _ = self.rpc("setmining", json!([true])).await;
        let _ = poll(Duration::from_secs(300), || async {
            if self.height().await >= target {
                Some(())
            } else {
                None
            }
        })
        .await;
        let _ = self.rpc("setmining", json!([false])).await;
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// One running faucet child process bound to a localhost port.
struct Faucet {
    child: Option<Child>,
    base_url: String,
    client: reqwest::Client,
}

impl Faucet {
    async fn spawn(daemon: &Daemon, drip_amount: f64, cooldown_secs: u64) -> Self {
        let bin = env!("CARGO_BIN_EXE_bitaiir-faucet");
        let listen = pick_free_port();

        let mut cmd = Command::new(bin);
        cmd.arg("--listen")
            .arg(format!("127.0.0.1:{listen}"))
            .arg("--rpc-url")
            .arg(&daemon.rpc_url)
            .arg("--data-dir")
            .arg(&daemon.data_dir_path)
            .arg("--drip-amount")
            .arg(drip_amount.to_string())
            .arg("--cooldown-secs")
            .arg(cooldown_secs.to_string())
            .arg("--max-per-ip")
            .arg("100")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn bitaiir-faucet");

        let base_url = format!("http://127.0.0.1:{listen}");
        let client = reqwest::Client::new();

        // Wait for /health to respond ok.
        let ok = poll(Duration::from_secs(20), || async {
            let r = client.get(format!("{base_url}/health")).send().await.ok()?;
            if r.status().is_success() {
                Some(())
            } else {
                None
            }
        })
        .await;
        if ok.is_none() {
            panic!("faucet never became ready on {base_url}");
        }

        Self {
            child: Some(child),
            base_url,
            client,
        }
    }

    async fn drip(&self, address: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/drip", self.base_url))
            .json(&json!({ "address": address }))
            .send()
            .await
            .expect("drip request")
    }
}

impl Drop for Faucet {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[tokio::test]
#[ignore = "spawns real bitaiird + bitaiir-faucet, runs in release mode only"]
async fn drip_creates_a_funded_transaction() {
    let daemon = Daemon::spawn().await;

    // Mine past testnet coinbase maturity (10) so the wallet has
    // mature spendable balance for the faucet to drain.
    daemon.mine_to(20).await;

    let faucet = Faucet::spawn(&daemon, 5.0, 60).await;

    // Pick a fresh recipient address that the wallet just generated
    // — different from the miner address so the drip ends up as a
    // real value transfer with change.
    let recipient = external_address();

    let resp = faucet.drip(&recipient).await;
    let status = resp.status();
    let body: Value = resp.json().await.expect("drip json");
    assert!(
        status.is_success(),
        "drip failed with status {status}: {body} (daemon height={}, recipient={recipient})",
        daemon.height().await,
    );
    assert_eq!(
        body.get("to").and_then(|v| v.as_str()),
        Some(recipient.as_str())
    );

    // The daemon's `sendtoaddress` is fire-and-forget: tx-PoW grinds
    // in the background.  Wait for the tx to land in the mempool.
    let appeared = poll(Duration::from_secs(60), || async {
        if daemon.mempool_size().await >= 1 {
            Some(())
        } else {
            None
        }
    })
    .await;
    assert!(
        appeared.is_some(),
        "drip transaction never reached the mempool"
    );
}

#[tokio::test]
#[ignore = "spawns real bitaiird + bitaiir-faucet, runs in release mode only"]
async fn second_drip_to_same_address_is_rate_limited() {
    let daemon = Daemon::spawn().await;
    daemon.mine_to(20).await;
    // 1 hour cooldown — far longer than the test runtime, so the
    // second drip should always hit the rate limit.
    let faucet = Faucet::spawn(&daemon, 1.0, 3600).await;

    let recipient = external_address();

    let first = faucet.drip(&recipient).await;
    assert!(
        first.status().is_success(),
        "first drip: {}",
        first.status()
    );
    let _ = first.text().await; // drain

    let second = faucet.drip(&recipient).await;
    assert_eq!(second.status().as_u16(), 429, "second drip should be 429");
    let body: Value = second.json().await.expect("429 body");
    assert!(
        body.get("retry_after")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0,
        "retry_after should be > 0, got {body}"
    );
}

#[tokio::test]
#[ignore = "spawns real bitaiird + bitaiir-faucet, runs in release mode only"]
async fn drip_rejects_invalid_address() {
    let daemon = Daemon::spawn().await;
    let faucet = Faucet::spawn(&daemon, 1.0, 60).await;

    let resp = faucet.drip("not-a-real-address").await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.expect("400 body");
    assert!(
        body.get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase()
            .contains("invalid"),
        "error should mention invalid address, got {body}"
    );
}
