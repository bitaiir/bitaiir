//! `bitaiir-cli` — command-line client for the BitAiir daemon.
//!
//! Sends JSON-RPC requests to a running `bitaiird` and prints the
//! response. Every subcommand maps 1:1 to an RPC method.

use base64::Engine;
use clap::{Parser, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{CustomCertStore, HttpClientBuilder};
use jsonrpsee::rpc_params;
use rustls::pki_types::CertificateDer;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_MAINNET_RPC_URL: &str = "http://127.0.0.1:8443";
const DEFAULT_TESTNET_RPC_URL: &str = "http://127.0.0.1:18443";
const DEFAULT_MAINNET_DATA_DIR: &str = "bitaiir_data";
const DEFAULT_TESTNET_DATA_DIR: &str = "bitaiir_testnet_data";
const COOKIE_FILENAME: &str = ".cookie";
const CERT_FILENAME: &str = "rpc.cert";

/// Full validation of a BitAiir address: prefix + base58check + length.
fn is_valid_address(addr: &str) -> bool {
    let Some(body) = addr.strip_prefix("aiir") else {
        return false;
    };
    let Ok(decoded) = bitaiir_crypto::base58::decode_check(body) else {
        return false;
    };
    decoded.len() == 21
}

#[derive(Parser)]
#[command(
    name = "bitaiir-cli",
    about = "Command-line client for the BitAiir daemon",
    version
)]
struct Cli {
    /// URL of the daemon's JSON-RPC endpoint.  Defaults to
    /// `http://127.0.0.1:8443` (mainnet) or `http://127.0.0.1:18443`
    /// when `--testnet` is given.
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    /// Use the testnet default RPC port (18443) when `--rpc-url` is
    /// not given.  Has no effect if `--rpc-url` is provided.
    #[arg(long, global = true)]
    testnet: bool,

    /// Explicit RPC username.  Required when the daemon uses
    /// config-based auth (`[rpc] user = "..."` in `bitaiir.toml`).
    /// Ignored when the daemon writes a cookie file — the CLI
    /// reads the cookie automatically.
    #[arg(long, global = true)]
    rpc_user: Option<String>,

    /// Explicit RPC password.  Paired with `--rpc-user`.
    #[arg(long, global = true)]
    rpc_password: Option<String>,

    /// Override where the CLI looks for the `.cookie` file.  By
    /// default uses `bitaiir_data/` (mainnet) or
    /// `bitaiir_testnet_data/` (when `--testnet` is given).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Path to a PEM certificate (or CA bundle) that the CLI trusts
    /// for the RPC connection.  Only used when `--rpc-url` points at
    /// an `https://` endpoint.  When unset, the CLI auto-loads
    /// `<data_dir>/rpc.cert` — the cert the daemon generates on
    /// first startup with `[rpc] tls = true`.  If neither is
    /// present, the system trust store is consulted.
    #[arg(long, global = true)]
    rpc_cafile: Option<PathBuf>,

    /// Disable TLS certificate verification.  DANGEROUS — anyone on
    /// the network path can intercept or impersonate the RPC
    /// endpoint.  Use only for debugging.
    #[arg(long, global = true)]
    insecure: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Resolve the data dir from `--data-dir` or the network-default.
fn resolve_data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        PathBuf::from(if cli.testnet {
            DEFAULT_TESTNET_DATA_DIR
        } else {
            DEFAULT_MAINNET_DATA_DIR
        })
    })
}

/// Build the `Authorization: Basic <b64>` value the daemon expects.
/// Tries explicit credentials first, falls back to reading the
/// cookie file from the resolved data dir.
fn resolve_basic_token(cli: &Cli) -> String {
    if let (Some(user), Some(pass)) = (&cli.rpc_user, &cli.rpc_password) {
        return base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    }

    let cookie_path = resolve_data_dir(cli).join(COOKIE_FILENAME);
    let contents = match std::fs::read_to_string(&cookie_path) {
        Ok(c) => c.trim().to_string(),
        Err(e) => {
            eprintln!(
                "Error: cannot read RPC cookie at {}: {e}\n\
                 Pass --rpc-user and --rpc-password explicitly if the \
                 daemon is using config-based auth, or --data-dir to \
                 point at the daemon's data directory.",
                cookie_path.display(),
            );
            std::process::exit(1);
        }
    };
    base64::engine::general_purpose::STANDARD.encode(contents)
}

/// Build an optional rustls `ClientConfig` for the RPC connection.
///
/// Returns `None` when the URL is plain HTTP — no TLS material
/// needed.  Returns `Some` when the URL is HTTPS; in that case the
/// returned config either trusts a specific CA file, accepts any
/// cert (`--insecure`), or — the common case — trusts the daemon's
/// auto-generated `<data_dir>/rpc.cert`.  If none of those apply,
/// falls through to the platform verifier (system trust store).
fn build_tls_config(cli: &Cli, rpc_url: &str) -> Option<CustomCertStore> {
    if !rpc_url.starts_with("https://") {
        return None;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    if cli.insecure {
        return Some(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth(),
        );
    }

    let cafile = cli.rpc_cafile.clone().or_else(|| {
        let p = resolve_data_dir(cli).join(CERT_FILENAME);
        if p.exists() { Some(p) } else { None }
    });

    let Some(cafile) = cafile else {
        // No explicit trust material — let jsonrpsee fall back to
        // `rustls-platform-verifier` (system trust store).
        return None;
    };

    let pem = std::fs::read(&cafile).unwrap_or_else(|e| {
        eprintln!("Error: cannot read TLS cert {}: {e}", cafile.display());
        std::process::exit(1);
    });

    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(&pem))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| {
            eprintln!("Error: parsing {}: {e}", cafile.display());
            std::process::exit(1);
        });
    if certs.is_empty() {
        eprintln!("Error: no certificates found in {}", cafile.display());
        std::process::exit(1);
    }
    for cert in certs {
        let _ = roots.add(cert);
    }

    Some(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// `--insecure` verifier: accepts every cert.  Only used when the
/// user opts in with the CLI flag.
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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

#[derive(Subcommand)]
enum Commands {
    /// Show blockchain status.
    Getblockchaininfo,
    /// Show block details at a given height.
    Getblock {
        /// Block height (0 = genesis).
        height: u64,
    },
    /// Generate a new BitAiir address in the wallet.
    Getnewaddress,
    /// Show the balance of an address.
    Getbalance {
        /// BitAiir address (aiir...).
        address: String,
    },
    /// Send AIIR to an address.
    Sendtoaddress {
        /// Recipient BitAiir address (aiir...).
        address: String,
        /// Amount in AIIR (e.g. 10.5).
        amount: f64,
        /// Mempool priority: u64 multiplier of tx-PoW CPU cost over
        /// the minimum target.  Default 1 (minimum).  Priority 2
        /// costs ~2x more CPU, priority 10 costs ~10x, etc.  Only
        /// useful when the network is congested.
        #[arg(long, default_value_t = 1)]
        priority: u64,
    },
    /// Show transaction history for an address.
    Gettransactionhistory {
        /// BitAiir address to query.
        address: String,
    },
    /// Show the mempool status.
    Getmempoolinfo,
    /// Look up a transaction by txid.
    Gettransaction {
        /// Transaction ID (hex).
        txid: String,
    },
    /// List all wallet addresses with balances.
    Listaddresses,
    /// Start mining.
    #[command(name = "mine-start")]
    MineStart,
    /// Stop mining.
    #[command(name = "mine-stop")]
    MineStop,
    /// Connect to a peer node.
    Addpeer {
        /// Address of the peer (ip:port).
        addr: String,
    },
    /// List currently connected peers.
    Listpeers,
    /// List all known peer addresses (connected or not).
    Listknownpeers,
    /// Export all wallet keys to a JSON file.
    Exportwallet {
        /// Output file path.
        filename: String,
    },
    /// Import wallet keys from a JSON backup file.
    Importwallet {
        /// Backup file path.
        filename: String,
    },
    /// Import a single private key in WIF format.
    Importprivkey {
        /// WIF-encoded private key.
        wif: String,
    },
    /// Encrypt the wallet with a passphrase.
    Encryptwallet {
        /// The passphrase to encrypt with.
        passphrase: String,
    },
    /// Unlock the wallet for a number of seconds.
    Walletpassphrase {
        /// The wallet passphrase.
        passphrase: String,
        /// Seconds to keep unlocked (default: 60).
        #[arg(default_value_t = 60)]
        timeout: u64,
    },
    /// Lock the wallet immediately.
    Walletlock,
    /// Show the HD wallet seed phrase (24 words).
    Getmnemonic,
    /// Restore wallet from a BIP39 seed phrase.
    Importmnemonic {
        /// The 24-word mnemonic phrase (quoted).
        phrase: String,
    },
    /// Register an alias (on-chain name → address mapping).
    Registeralias {
        /// Alias name (1–32 chars, a-z0-9 and hyphens).
        name: String,
        /// Target BitAiir address the alias resolves to.
        address: String,
    },
    /// Resolve an alias to its target address.
    Resolvealias {
        /// Alias name to look up.
        name: String,
    },
    /// List all registered aliases.
    Listaliases,
    /// Ask the daemon to shut down gracefully.
    Stop,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let rpc_url = cli.rpc_url.clone().unwrap_or_else(|| {
        if cli.testnet {
            DEFAULT_TESTNET_RPC_URL.to_string()
        } else {
            DEFAULT_MAINNET_RPC_URL.to_string()
        }
    });

    let basic_token = resolve_basic_token(&cli);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Basic {basic_token}"))
            .expect("base64 token is ASCII"),
    );

    let mut builder = HttpClientBuilder::default().set_headers(headers);
    if let Some(tls_cfg) = build_tls_config(&cli, &rpc_url) {
        builder = builder.with_custom_cert_store(tls_cfg);
    }
    let client = builder.build(&rpc_url).unwrap_or_else(|e| {
        eprintln!("Error: cannot connect to {rpc_url}: {e}");
        std::process::exit(1);
    });

    // Validate parameters before sending to the daemon.
    match &cli.command {
        Commands::Getbalance { address } if !is_valid_address(address) => {
            eprintln!("Error: '{}' is not a valid BitAiir address.", address);
            std::process::exit(1);
        }
        Commands::Gettransactionhistory { address } if !is_valid_address(address) => {
            eprintln!("Error: '{}' is not a valid BitAiir address.", address);
            std::process::exit(1);
        }
        Commands::Sendtoaddress {
            address, amount, ..
        } => {
            if !address.starts_with('@') && !is_valid_address(address) {
                eprintln!(
                    "Error: '{}' is not a valid BitAiir address or alias.",
                    address
                );
                std::process::exit(1);
            }
            if *amount <= 0.0 {
                eprintln!("Error: amount must be greater than 0.");
                std::process::exit(1);
            }
        }
        Commands::Addpeer { addr } if !addr.contains(':') => {
            eprintln!("Error: '{}' needs a port. Example: 127.0.0.1:8444", addr);
            std::process::exit(1);
        }
        _ => {}
    }

    let result: Result<serde_json::Value, _> = match &cli.command {
        Commands::Getblockchaininfo => client.request("getblockchaininfo", rpc_params![]).await,
        Commands::Getblock { height } => client.request("getblock", rpc_params![*height]).await,
        Commands::Getnewaddress => client.request("getnewaddress", rpc_params![]).await,
        Commands::Getbalance { address } => {
            client
                .request("getbalance", rpc_params![address.clone()])
                .await
        }
        Commands::Sendtoaddress {
            address,
            amount,
            priority,
        } => {
            client
                .request(
                    "sendtoaddress",
                    rpc_params![address.clone(), *amount, Some(*priority)],
                )
                .await
        }
        Commands::Gettransactionhistory { address } => {
            client
                .request("gettransactionhistory", rpc_params![address.clone()])
                .await
        }
        Commands::Getmempoolinfo => client.request("getmempoolinfo", rpc_params![]).await,
        Commands::Gettransaction { txid } => {
            client
                .request("gettransaction", rpc_params![txid.clone()])
                .await
        }
        Commands::Listaddresses => client.request("listaddresses", rpc_params![]).await,
        Commands::MineStart => client.request("setmining", rpc_params![true]).await,
        Commands::MineStop => client.request("setmining", rpc_params![false]).await,
        Commands::Addpeer { addr } => client.request("addpeer", rpc_params![addr.clone()]).await,
        Commands::Listpeers => client.request("listpeers", rpc_params![]).await,
        Commands::Listknownpeers => client.request("listknownpeers", rpc_params![]).await,
        Commands::Exportwallet { filename } => {
            client
                .request("exportwallet", rpc_params![filename.clone()])
                .await
        }
        Commands::Importwallet { filename } => {
            client
                .request("importwallet", rpc_params![filename.clone()])
                .await
        }
        Commands::Importprivkey { wif } => {
            client
                .request("importprivkey", rpc_params![wif.clone()])
                .await
        }
        Commands::Encryptwallet { passphrase } => {
            client
                .request("encryptwallet", rpc_params![passphrase.clone()])
                .await
        }
        Commands::Walletpassphrase {
            passphrase,
            timeout,
        } => {
            client
                .request(
                    "walletpassphrase",
                    rpc_params![passphrase.clone(), *timeout],
                )
                .await
        }
        Commands::Walletlock => client.request("walletlock", rpc_params![]).await,
        Commands::Getmnemonic => client.request("getmnemonic", rpc_params![]).await,
        Commands::Importmnemonic { phrase } => {
            client
                .request("importmnemonic", rpc_params![phrase.clone()])
                .await
        }
        Commands::Registeralias { name, address } => {
            client
                .request("registeralias", rpc_params![name, address])
                .await
        }
        Commands::Resolvealias { name } => client.request("resolvealias", rpc_params![name]).await,
        Commands::Listaliases => client.request("listaliases", rpc_params![]).await,
        Commands::Stop => client.request("stop", rpc_params![]).await,
    };

    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        Err(e) => {
            eprintln!("{}", explain_rpc_error(&e.to_string(), &rpc_url));
            std::process::exit(1);
        }
    }
}

/// Raw jsonrpsee errors are terse and low-level ("client error
/// (SendRequest)", "connection refused", etc.).  Look at a handful
/// of common strings and emit a plain-language hint about what to
/// check — usually scheme mismatch, daemon not running, or auth.
fn explain_rpc_error(msg: &str, url: &str) -> String {
    let is_http = url.starts_with("http://");
    let is_https = url.starts_with("https://");
    let lower = msg.to_ascii_lowercase();

    // HTTP → HTTPS endpoint: hyper aborts the transport because
    // the "response" is a TLS record.  Most common misconfigure.
    if is_http
        && (lower.contains("sendrequest")
            || lower.contains("incompletemessage")
            || lower.contains("channel closed"))
    {
        let host = url.trim_start_matches("http://");
        return format!(
            "RPC error: {msg}\n\n\
             Hint: the daemon may be serving HTTPS (`[rpc] tls = true` in \
             bitaiir.toml).  Retry with `--rpc-url https://{host}`.",
        );
    }

    // Nothing on the other end of the socket (Linux / macOS).
    if lower.contains("connection refused") || lower.contains("connectionrefused") {
        return format!(
            "RPC error: {msg}\n\n\
             Hint: nothing is listening on {url}.  Is `bitaiird` running with \
             the matching `--rpc-addr`?",
        );
    }

    // Hyper wraps both "connection refused" and TLS handshake
    // failures as `(Connect)`.  We can't distinguish them from the
    // error string alone, so pair the hint to the URL scheme.
    if lower.contains("(connect)") {
        let (scheme_hint, alt_scheme) = if is_https {
            (
                "Hint: the daemon isn't answering TLS handshakes on this port.",
                Some(("https://", "http://")),
            )
        } else if is_http {
            (
                "Hint: the daemon isn't accepting plain-HTTP connections on this port.",
                Some(("http://", "https://")),
            )
        } else {
            ("Hint: the daemon isn't responding on this port.", None)
        };
        let mut out = format!(
            "RPC error: {msg}\n\n\
             {scheme_hint}  Is `bitaiird` running with the matching \
             `--rpc-addr`?",
        );
        if let Some((old, new)) = alt_scheme {
            let host = url.trim_start_matches(old);
            out.push_str(&format!(
                "  If it is running, the other scheme might be right: \
                 `--rpc-url {new}{host}`.",
            ));
        }
        return out;
    }

    // Authentication rejected.
    if lower.contains("401") || lower.contains("unauthorized") {
        return format!(
            "RPC error: {msg}\n\n\
             Hint: RPC credentials were rejected.  The daemon either writes a \
             cookie at `<data_dir>/.cookie` (default) or uses \
             `[rpc] user`/`password` from bitaiir.toml — the CLI flags must \
             match.  Try `--data-dir <path>` or `--rpc-user`/`--rpc-password`.",
        );
    }

    // HTTPS → HTTP endpoint: TLS client got a plain HTTP response.
    if is_https
        && (lower.contains("invalid certificate")
            || lower.contains("invaliddnsname")
            || lower.contains("bad record mac"))
    {
        let host = url.trim_start_matches("https://");
        return format!(
            "RPC error: {msg}\n\n\
             Hint: the daemon may be serving plain HTTP.  Retry with \
             `--rpc-url http://{host}`.",
        );
    }

    // Untrusted self-signed cert (no `rpc.cert` in data dir).
    if lower.contains("unknownissuer")
        || lower.contains("invalid peer certificate")
        || lower.contains("webpki")
    {
        return format!(
            "RPC error: {msg}\n\n\
             Hint: TLS cert not trusted.  The CLI auto-loads \
             `<data_dir>/rpc.cert`; point `--data-dir` at the daemon's data \
             dir, use `--rpc-cafile <path>`, or `--insecure` to skip \
             verification (not recommended).",
        );
    }

    format!("RPC error: {msg}")
}
