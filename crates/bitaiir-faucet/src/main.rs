//! `bitaiir-faucet` — testnet faucet for BitAiir.
//!
//! A small HTTP service that drips testnet AIIR to developer
//! addresses on request.  The faucet itself holds no keys: it talks
//! to a co-located `bitaiird --testnet` over JSON-RPC and asks it to
//! `sendtoaddress` from the daemon's wallet.  The operator pre-funds
//! the daemon by mining or by manual transfer.
//!
//! ## Endpoints
//!
//! - `GET  /`       — short text describing the service.
//! - `GET  /info`   — JSON: drip amount, cooldown, network.
//! - `GET  /health` — `"ok"` (or 503 if the daemon is unreachable).
//! - `POST /drip`   — body `{"address": "aiir1..."}`, returns the
//!   daemon's `sendtoaddress` response on success (`from`, `to`,
//!   `amount`, `change`, `priority`, `peers_notified`, `status` —
//!   no `txid` because tx-PoW mining is fire-and-forget) or
//!   `{"error": "...", "retry_after": <secs>}` on rate-limit /
//!   validation failure.
//!
//! ## Rate limiting
//!
//! Two independent token-style limits, both in-memory:
//!
//! 1. **Per address** — one drip per address per `cooldown_secs`
//!    (default 24 h).  Stops a single dev from looping requests
//!    against the same address.
//! 2. **Per source IP** — at most `max_per_ip` drips per
//!    `cooldown_secs` window.  Stops a single host from spraying
//!    drips at many freshly-generated addresses.
//!
//! Restarting the faucet clears both limits.  Persisting them is a
//! deliberate non-goal — testnet faucet abuse is bounded by the
//! amount the operator chooses to pre-fund.

use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use clap::Parser;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{CustomCertStore, HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

const COOKIE_FILENAME: &str = ".cookie";
const CERT_FILENAME: &str = "rpc.cert";

// --- CLI ----------------------------------------------------------------- //

#[derive(Parser, Debug)]
#[command(
    name = "bitaiir-faucet",
    about = "BitAiir testnet faucet — drips testnet AIIR to developer addresses",
    version
)]
struct Args {
    /// Address the HTTP server binds to.
    #[arg(long, default_value = "127.0.0.1:8090")]
    listen: String,

    /// URL of the bitaiird JSON-RPC endpoint.  Default is the testnet
    /// HTTPS endpoint with self-signed cert auto-trusted from
    /// `<data_dir>/rpc.cert`.
    #[arg(long, default_value = "https://127.0.0.1:18443")]
    rpc_url: String,

    /// Explicit RPC username (set when the daemon runs with config
    /// auth instead of cookie auth).
    #[arg(long)]
    rpc_user: Option<String>,

    /// Explicit RPC password.  Paired with `--rpc-user`.
    #[arg(long)]
    rpc_password: Option<String>,

    /// Where the faucet looks for the cookie file and self-signed
    /// cert.  Defaults to the testnet data dir.
    #[arg(long, default_value = "bitaiir_testnet_data")]
    data_dir: PathBuf,

    /// AIIR per drip request.
    #[arg(long, default_value_t = 10.0)]
    drip_amount: f64,

    /// Cooldown window (seconds) per address and per source IP.
    /// Default: 24 hours.
    #[arg(long, default_value_t = 86_400)]
    cooldown_secs: u64,

    /// Max drips per source IP within the cooldown window.
    #[arg(long, default_value_t = 5)]
    max_per_ip: usize,

    /// `pow_priority` for the drip transactions (1 = baseline).
    #[arg(long, default_value_t = 1)]
    priority: u64,
}

// --- Shared state -------------------------------------------------------- //

struct AppState {
    rpc: HttpClient,
    drip_amount: f64,
    cooldown: Duration,
    max_per_ip: usize,
    priority: u64,
    /// Last successful drip per recipient address.
    last_drip_addr: Mutex<HashMap<String, Instant>>,
    /// Recent drip times per source IP (sliding window pruned on read).
    drips_by_ip: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

// --- HTTP request / response shapes ------------------------------------- //

#[derive(Deserialize)]
struct DripRequest {
    address: String,
}

#[derive(Serialize)]
struct DripError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

#[derive(Serialize)]
struct InfoResponse {
    drip_amount: String,
    cooldown_secs: u64,
    max_per_ip: usize,
    priority: u64,
}

// --- Address validation -------------------------------------------------- //

fn is_valid_address(addr: &str) -> bool {
    let Some(body) = addr.strip_prefix("aiir") else {
        return false;
    };
    let Ok(decoded) = bitaiir_crypto::base58::decode_check(body) else {
        return false;
    };
    decoded.len() == 21
}

// --- RPC client construction (mirrors bitaiir-cli auth/TLS handling) ---- //

fn resolve_basic_token(args: &Args) -> Result<String, String> {
    if let (Some(user), Some(pass)) = (&args.rpc_user, &args.rpc_password) {
        return Ok(base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")));
    }
    let cookie_path = args.data_dir.join(COOKIE_FILENAME);
    match std::fs::read_to_string(&cookie_path) {
        Ok(contents) => {
            let token = contents.trim();
            Ok(base64::engine::general_purpose::STANDARD.encode(token))
        }
        Err(e) => Err(format!(
            "cannot read RPC cookie at {}: {e}.  Pass --rpc-user/--rpc-password or fix --data-dir.",
            cookie_path.display(),
        )),
    }
}

fn build_tls_config(args: &Args) -> Option<CustomCertStore> {
    if !args.rpc_url.starts_with("https://") {
        return None;
    }
    let cert_path = args.data_dir.join(CERT_FILENAME);
    let pem = std::fs::read(&cert_path).ok()?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(&pem))
        .collect::<Result<_, _>>()
        .ok()?;
    if certs.is_empty() {
        return None;
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        let _ = roots.add(cert);
    }
    Some(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn build_rpc_client(args: &Args) -> Result<HttpClient, String> {
    let token = resolve_basic_token(args)?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Basic {token}").parse().expect("valid auth header"),
    );
    let mut builder = HttpClientBuilder::default().set_headers(headers);
    if let Some(tls) = build_tls_config(args) {
        builder = builder.with_custom_cert_store(tls);
    }
    builder
        .build(&args.rpc_url)
        .map_err(|e| format!("cannot build RPC client for {}: {e}", args.rpc_url))
}

// --- HTTP handlers ------------------------------------------------------- //

async fn root() -> &'static str {
    "BitAiir testnet faucet.  POST /drip with {\"address\":\"aiir1...\"} to claim."
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state
        .rpc
        .request::<serde_json::Value, _>("getblockchaininfo", rpc_params![])
        .await
    {
        Ok(_) => (StatusCode::OK, "ok").into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("daemon unreachable: {e}"),
        )
            .into_response(),
    }
}

async fn info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    Json(InfoResponse {
        drip_amount: format!("{:.8} AIIR", state.drip_amount),
        cooldown_secs: state.cooldown.as_secs(),
        max_per_ip: state.max_per_ip,
        priority: state.priority,
    })
}

async fn drip(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<DripRequest>,
) -> Response {
    let addr = req.address.trim().to_string();
    if !is_valid_address(&addr) {
        return (
            StatusCode::BAD_REQUEST,
            Json(DripError {
                error: "invalid BitAiir address".into(),
                retry_after: None,
            }),
        )
            .into_response();
    }

    let now = Instant::now();

    // Per-address cooldown.
    {
        let map = state.last_drip_addr.lock().await;
        if let Some(last) = map.get(&addr) {
            let elapsed = now.duration_since(*last);
            if elapsed < state.cooldown {
                let wait = (state.cooldown - elapsed).as_secs();
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(DripError {
                        error: "address recently drained from this faucet".into(),
                        retry_after: Some(wait),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Per-IP cooldown.
    let ip = remote.ip();
    {
        let mut map = state.drips_by_ip.lock().await;
        let entry = map.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < state.cooldown);
        if entry.len() >= state.max_per_ip {
            // Earliest timestamp inside the window decides the wait.
            let oldest = entry.iter().min().copied().unwrap_or(now);
            let wait = state
                .cooldown
                .saturating_sub(now.duration_since(oldest))
                .as_secs();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(DripError {
                    error: format!(
                        "rate limit ({} drips per {}s reached for this IP)",
                        state.max_per_ip,
                        state.cooldown.as_secs()
                    ),
                    retry_after: Some(wait),
                }),
            )
                .into_response();
        }
    }

    // RPC call.  No `from` argument — let the daemon pick a spendable
    // wallet address.  Operators who want a specific source can run a
    // dedicated faucet wallet.
    //
    // The daemon's `sendtoaddress` is fire-and-forget: tx-PoW mining
    // happens in a background task, so the response carries the
    // sender / amount / status but **not** a txid.  We pass the
    // whole JSON value back to the client so they see the same
    // fields they'd see in the TUI.
    let result: Result<serde_json::Value, _> = state
        .rpc
        .request(
            "sendtoaddress",
            rpc_params![addr.clone(), state.drip_amount, Some(state.priority)],
        )
        .await;

    match result {
        Ok(value) => {
            // Record success in both rate-limit maps before responding.
            state.last_drip_addr.lock().await.insert(addr.clone(), now);
            state
                .drips_by_ip
                .lock()
                .await
                .entry(ip)
                .or_default()
                .push(now);

            let from = value.get("from").and_then(|v| v.as_str()).unwrap_or("?");
            info!(target: "faucet", address = %addr, ip = %ip, from = %from, "drip ok");
            (StatusCode::OK, Json(value)).into_response()
        }
        Err(e) => {
            warn!(target: "faucet", address = %addr, ip = %ip, error = %e, "drip failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(DripError {
                    error: format!("daemon rejected the request: {e}"),
                    retry_after: None,
                }),
            )
                .into_response()
        }
    }
}

// --- Bootstrap ----------------------------------------------------------- //

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let rpc = match build_rpc_client(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState {
        rpc,
        drip_amount: args.drip_amount,
        cooldown: Duration::from_secs(args.cooldown_secs),
        max_per_ip: args.max_per_ip,
        priority: args.priority,
        last_drip_addr: Mutex::new(HashMap::new()),
        drips_by_ip: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/drip", post(drip))
        .with_state(state);

    let addr: SocketAddr = args
        .listen
        .parse()
        .expect("--listen must be a valid ip:port");
    info!(target: "faucet", %addr, rpc_url = %args.rpc_url, "faucet listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error: cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        eprintln!("Error: faucet server crashed: {e}");
        std::process::exit(1);
    }
}
