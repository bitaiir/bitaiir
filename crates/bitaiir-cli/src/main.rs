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
