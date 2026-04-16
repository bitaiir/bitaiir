//! Network identification — Mainnet vs Testnet.
//!
//! BitAiir supports two parallel networks that share the same protocol
//! code but diverge in the parameters that matter for isolation:
//!
//! - **Mainnet** — the production network where real AIIR lives.
//! - **Testnet** — a development network with faster coinbase maturity
//!   and a different genesis, magic bytes, and default ports so nodes
//!   on the two networks cannot accidentally peer with each other.
//!
//! The active network is chosen once at daemon startup (via the
//! `--testnet` CLI flag or the `network.testnet = true` config option)
//! and stored in a process-wide [`OnceLock`]. Every consensus,
//! networking, and storage decision that depends on the network reads
//! [`Network::active`].
//!
//! This module lives in `bitaiir-types` (rather than `bitaiir-chain`)
//! because `bitaiir-net` also needs to consult the active network for
//! its magic bytes, and `bitaiir-net` does not depend on
//! `bitaiir-chain`.

use std::sync::OnceLock;

/// The two supported networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Production network: 100-block coinbase maturity, mainnet magic.
    Mainnet,
    /// Development network: 10-block coinbase maturity, testnet magic.
    Testnet,
}

/// Process-wide active network. Set once at startup; subsequent calls
/// to [`Network::set_active`] are silently ignored. If never set,
/// [`Network::active`] returns [`Network::Mainnet`].
static ACTIVE: OnceLock<Network> = OnceLock::new();

impl Network {
    /// Set the active network for this process. Must be called before
    /// any code that reads network-dependent constants (magic bytes,
    /// genesis parameters, coinbase maturity). Idempotent: the first
    /// call wins; later calls are ignored.
    pub fn set_active(self) {
        let _ = ACTIVE.set(self);
    }

    /// The active network. Defaults to [`Network::Mainnet`] if
    /// [`Network::set_active`] has not been called.
    pub fn active() -> Network {
        *ACTIVE.get().unwrap_or(&Network::Mainnet)
    }

    /// Short human-readable name ("mainnet" / "testnet").
    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    /// Number of blocks a coinbase output must mature before it can
    /// be spent. Lower on testnet so developers don't wait minutes.
    pub fn coinbase_maturity(self) -> u64 {
        match self {
            Self::Mainnet => 100,
            Self::Testnet => 10,
        }
    }

    /// Network magic bytes — the 4-byte prefix on every P2P message.
    /// Different magic bytes prevent mainnet and testnet nodes from
    /// accidentally talking to each other.
    pub fn magic(self) -> [u8; 4] {
        match self {
            // B1 7A 11 ED — "BitAiir Edition".
            Self::Mainnet => [0xB1, 0x7A, 0x11, 0xED],
            // B1 7A 11 7E — trailing 7E ("te" → testnet).
            Self::Testnet => [0xB1, 0x7A, 0x11, 0x7E],
        }
    }

    /// Default RPC server port.
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Self::Mainnet => 8443,
            Self::Testnet => 18443,
        }
    }

    /// Default P2P listener port.
    pub fn default_p2p_port(self) -> u16 {
        match self {
            Self::Mainnet => 8444,
            Self::Testnet => 18444,
        }
    }

    /// Default on-disk data directory.  Parallel directories (rather
    /// than subdirs) make it easy to run both networks side by side
    /// and to wipe testnet without touching mainnet.
    pub fn default_data_dir(self) -> &'static str {
        match self {
            Self::Mainnet => "bitaiir_data",
            Self::Testnet => "bitaiir_testnet_data",
        }
    }

    /// The phrase whose `hash160` produces the genesis burn address.
    /// Different phrases on each network produce different burn
    /// addresses and therefore different genesis blocks.
    pub fn genesis_burn_phrase(self) -> &'static str {
        match self {
            Self::Mainnet => "BitAiir Genesis Burn",
            Self::Testnet => "BitAiir Testnet Genesis Burn",
        }
    }

    /// Fixed timestamp for the genesis block.
    pub fn genesis_timestamp(self) -> u64 {
        match self {
            // 2026-03-29 00:00:00 UTC — matches the coinbase headline.
            Self::Mainnet => 1743206400,
            // 2026-04-06 00:00:00 UTC — distinct from mainnet so the
            // two genesis blocks have different hashes even if every
            // other parameter were somehow equal.
            Self::Testnet => 1743897600,
        }
    }

    /// Coinbase message embedded in the genesis block.
    pub fn genesis_message(self) -> &'static str {
        match self {
            Self::Mainnet => {
                "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos"
            }
            Self::Testnet => "BitAiir Testnet Genesis",
        }
    }
}
