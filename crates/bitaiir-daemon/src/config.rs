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
}

#[derive(Debug, Deserialize, Default)]
pub struct NetworkConfig {
    /// Run on the testnet network instead of mainnet.
    pub testnet: Option<bool>,
    pub rpc_addr: Option<String>,
    pub p2p_addr: Option<String>,
    pub connect: Option<Vec<String>>,
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

[mining]
# enabled = false
# threads = 0        # 0 = auto (min(4, cores/2))

[storage]
# data_dir = "bitaiir_data"          # mainnet default;
                                     # testnet is "bitaiir_testnet_data"
"#;
    let _ = std::fs::write(path, template);
}
