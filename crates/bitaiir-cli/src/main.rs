//! `bitaiir-cli` — command-line client for the BitAiir daemon.
//!
//! Sends JSON-RPC requests to a running `bitaiird` and prints the
//! response. Every subcommand maps 1:1 to an RPC method.

use clap::{Parser, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8443";

#[derive(Parser)]
#[command(
    name = "bitaiir-cli",
    about = "Command-line client for the BitAiir daemon",
    version
)]
struct Cli {
    /// URL of the daemon's JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_RPC_URL, global = true)]
    rpc_url: String,

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
    /// Ask the daemon to shut down gracefully.
    Stop,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let client = HttpClientBuilder::default()
        .build(&cli.rpc_url)
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot connect to {}: {e}", cli.rpc_url);
            std::process::exit(1);
        });

    // Validate parameters before sending to the daemon.
    match &cli.command {
        Commands::Getbalance { address } => {
            if !address.starts_with("aiir") {
                eprintln!(
                    "Error: '{}' doesn't look like a BitAiir address (must start with 'aiir').",
                    address
                );
                std::process::exit(1);
            }
        }
        Commands::Sendtoaddress { address, amount } => {
            if !address.starts_with("aiir") {
                eprintln!("Error: '{}' doesn't look like a BitAiir address.", address);
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
        Commands::Sendtoaddress { address, amount } => {
            client
                .request("sendtoaddress", rpc_params![address.clone(), *amount])
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
