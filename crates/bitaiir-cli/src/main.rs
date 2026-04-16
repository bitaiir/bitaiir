//! `bitaiir-cli` — command-line client for the BitAiir daemon.
//!
//! Sends JSON-RPC requests to a running `bitaiird` and prints the
//! response. Every subcommand maps 1:1 to an RPC method.

use clap::{Parser, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

const DEFAULT_MAINNET_RPC_URL: &str = "http://127.0.0.1:8443";
const DEFAULT_TESTNET_RPC_URL: &str = "http://127.0.0.1:18443";

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

    #[command(subcommand)]
    command: Commands,
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

    let client = HttpClientBuilder::default()
        .build(&rpc_url)
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot connect to {rpc_url}: {e}");
            std::process::exit(1);
        });

    // Validate parameters before sending to the daemon.
    match &cli.command {
        Commands::Getbalance { address } => {
            if !is_valid_address(address) {
                eprintln!("Error: '{}' is not a valid BitAiir address.", address);
                std::process::exit(1);
            }
        }
        Commands::Gettransactionhistory { address } => {
            if !is_valid_address(address) {
                eprintln!("Error: '{}' is not a valid BitAiir address.", address);
                std::process::exit(1);
            }
        }
        Commands::Sendtoaddress {
            address, amount, ..
        } => {
            if !is_valid_address(address) {
                eprintln!("Error: '{}' is not a valid BitAiir address.", address);
                std::process::exit(1);
            }
            if *amount <= 0.0 {
                eprintln!("Error: amount must be greater than 0.");
                std::process::exit(1);
            }
        }
        Commands::Addpeer { addr } => {
            if !addr.contains(':') {
                eprintln!("Error: '{}' needs a port. Example: 127.0.0.1:8444", addr);
                std::process::exit(1);
            }
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
        Commands::Stop => client.request("stop", rpc_params![]).await,
    };

    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        Err(e) => {
            eprintln!("RPC error: {e}");
            std::process::exit(1);
        }
    }
}
