//! JSON-RPC interface to a running BitAiir node.
//!
//! This crate defines the RPC methods that `bitaiir-cli` (and any
//! third-party tooling) can call on a running daemon. The server
//! implementation holds a reference to the shared node state and
//! translates RPC calls into reads/writes on the chain, UTXO set,
//! mempool, and wallet.

pub mod wallet_crypto;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitaiir_chain::{Chain, Mempool, UtxoSet, subsidy, validate_transaction};
use bitaiir_crypto::address::Address;
use bitaiir_crypto::hash::hash160;
use bitaiir_crypto::key::{PrivateKey, PublicKey};
use bitaiir_storage::Storage;
use bitaiir_types::{Amount, Hash256, OutPoint, Transaction, TxIn, TxOut};
use jsonrpsee::core::RpcResult;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use serde::Serialize;
use tokio::sync::RwLock;

// -------------------------------------------------------------------------
// Shared state
// -------------------------------------------------------------------------

/// The shared mutable state every RPC handler reads or writes.
pub struct NodeState {
    pub chain: Chain,
    pub utxo: UtxoSet,
    pub mempool: Mempool,
    pub wallet: Wallet,
    /// Currently connected peers (inbound + outbound).
    pub peers: Vec<ConnectedPeer>,
    /// All peers we've ever heard about (manual, gossip, seeds).
    pub known_peers: std::collections::HashMap<String, KnownPeer>,
    /// Whether the wallet on disk is encrypted.
    pub wallet_encrypted: bool,
    /// Whether the wallet is currently unlocked (keys in memory).
    /// `true` = can sign. `false` = read-only (balances visible,
    /// sending blocked).  Unencrypted wallets are always unlocked.
    pub wallet_unlocked: bool,
    /// When the wallet should auto-lock (Unix timestamp, 0 = never).
    pub wallet_lock_at: u64,
}

/// One live P2P connection.
pub struct ConnectedPeer {
    pub addr: String,
    pub user_agent: String,
    pub best_height: u64,
    pub direction: PeerDirection,
    pub connected_at: std::time::Instant,
    pub sender: tokio::sync::mpsc::Sender<bitaiir_net::NetMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

impl PeerDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerDirection::Inbound => "inbound",
            PeerDirection::Outbound => "outbound",
        }
    }
}

/// A peer address we know about, whether or not we're currently
/// connected.  Persisted across restarts via `bitaiir-storage`.
#[derive(Debug, Clone)]
pub struct KnownPeer {
    pub addr: String,
    pub last_seen: u64,
    pub consecutive_failures: u32,
    pub banned_until: u64,
    pub source: PeerSource,
}

impl KnownPeer {
    /// Record a connection failure and apply a temporary ban if the
    /// threshold is reached.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= 5 {
            self.banned_until = unix_now() + 30 * 60; // 30 min ban
        }
    }

    /// Reset the failure counter on a successful connection.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.banned_until = 0;
        self.last_seen = unix_now();
    }

    /// Apply a ban for the given duration in seconds.
    pub fn ban(&mut self, seconds: u64) {
        self.banned_until = unix_now() + seconds;
    }

    /// Whether this peer is currently banned.
    pub fn is_banned(&self) -> bool {
        self.banned_until > unix_now()
    }

    /// Exponential backoff delay before next connection attempt.
    /// 5s * 2^failures, capped at 5 minutes.
    pub fn backoff_secs(&self) -> u64 {
        let base = 5u64;
        let delay = base.saturating_mul(1u64 << self.consecutive_failures.min(6));
        delay.min(300) // cap at 5 min
    }

    /// Numeric source code for storage serialization.
    pub fn source_byte(&self) -> u8 {
        match self.source {
            PeerSource::Manual => 0,
            PeerSource::Addr => 1,
            PeerSource::Seed => 2,
        }
    }

    /// Reconstruct a `PeerSource` from the byte stored in redb.
    pub fn source_from_byte(b: u8) -> PeerSource {
        match b {
            0 => PeerSource::Manual,
            1 => PeerSource::Addr,
            2 => PeerSource::Seed,
            _ => PeerSource::Addr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSource {
    /// Added via `--connect` flag or `/addpeer` command.
    Manual,
    /// Learned via `addr` gossip from another peer.
    Addr,
    /// From the hardcoded seed list.
    Seed,
}

impl PeerSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerSource::Manual => "manual",
            PeerSource::Addr => "addr",
            PeerSource::Seed => "seed",
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Thread-safe handle to the node state.
pub type SharedState = Arc<RwLock<NodeState>>;

// -------------------------------------------------------------------------
// Wallet (in-memory keystore)
// -------------------------------------------------------------------------

/// A simple in-memory wallet that stores keypairs and can build
/// signed transactions. No persistence — keys are lost on restart.
pub struct Wallet {
    /// Map from address string ("aiir...") to (private_key, public_key).
    keys: HashMap<String, (PrivateKey, PublicKey)>,
    /// All addresses that belong to this wallet.  Persists across
    /// lock/unlock so `listaddresses` and balance queries still work
    /// when the wallet is locked.
    all_addresses: Vec<String>,
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallet {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            all_addresses: Vec::new(),
        }
    }

    /// Generate a new keypair and return the BitAiir address.
    pub fn generate_address(&mut self) -> String {
        let privkey = PrivateKey::generate();
        let pubkey = privkey.public_key();
        let address = Address::from_compressed_public_key(&pubkey);
        let addr_str = address.as_str().to_string();
        self.keys.insert(addr_str.clone(), (privkey, pubkey));
        if !self.all_addresses.contains(&addr_str) {
            self.all_addresses.push(addr_str.clone());
        }
        addr_str
    }

    /// Import an existing keypair (used when loading from storage).
    pub fn import_key(&mut self, address: String, privkey: PrivateKey, pubkey: PublicKey) {
        if !self.all_addresses.contains(&address) {
            self.all_addresses.push(address.clone());
        }
        self.keys.insert(address, (privkey, pubkey));
    }

    /// Register an address without a keypair (for locked wallets
    /// that loaded addresses from storage but haven't decrypted
    /// the keys yet).
    pub fn register_address(&mut self, address: String) {
        if !self.all_addresses.contains(&address) {
            self.all_addresses.push(address);
        }
    }

    /// Look up a keypair by address.
    pub fn get_keys(&self, address: &str) -> Option<&(PrivateKey, PublicKey)> {
        self.keys.get(address)
    }

    /// List all addresses in the wallet (works even when locked).
    pub fn addresses(&self) -> Vec<String> {
        self.all_addresses.clone()
    }

    /// Clear all private keys from memory (lock the wallet).
    /// Addresses are preserved so balance queries still work.
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    /// Scan the UTXO set for outputs belonging to a given address
    /// and return the total balance in atomic units.
    /// Total balance of `address`, including outputs that aren't yet
    /// spendable (e.g. immature coinbases).  Use `spendable_balance_of`
    /// instead when deciding what the user can actually send.
    pub fn balance_of(address: &str, utxo: &UtxoSet) -> u64 {
        let recipient_hash = match address_to_recipient_hash(address) {
            Some(h) => h,
            None => return 0,
        };

        let mut total: u64 = 0;
        for (_, txout) in utxo.iter() {
            if txout.recipient_hash == recipient_hash {
                total = total.saturating_add(txout.amount.to_atomic());
            }
        }
        total
    }

    /// Spendable balance of `address` at the given chain `tip_height`.
    /// Excludes coinbase outputs that haven't reached
    /// `COINBASE_MATURITY` confirmations — those are in the total
    /// `balance_of` but can't be used as transaction inputs yet.
    pub fn spendable_balance_of(address: &str, utxo: &UtxoSet, tip_height: u64) -> u64 {
        let recipient_hash = match address_to_recipient_hash(address) {
            Some(h) => h,
            None => return 0,
        };
        let maturity = bitaiir_chain::consensus::coinbase_maturity();

        let mut total: u64 = 0;
        for (outpoint, txout) in utxo.iter() {
            if txout.recipient_hash != recipient_hash {
                continue;
            }
            if let Some(cb_height) = utxo.coinbase_height(outpoint) {
                if tip_height < cb_height + maturity {
                    continue;
                }
            }
            total = total.saturating_add(txout.amount.to_atomic());
        }
        total
    }

    /// Balance split into `(confirmed, unconfirmed, immature)`.
    ///
    /// - **confirmed**: outputs with >= `RECOMMENDED_CONFIRMATIONS`
    ///   (12 blocks, ~60 s) and not coinbase-immature.
    /// - **unconfirmed**: outputs with 1–11 confirmations and not
    ///   coinbase-immature.
    /// - **immature**: coinbase outputs with < `COINBASE_MATURITY`
    ///   (100 blocks).
    pub fn balance_breakdown(address: &str, utxo: &UtxoSet, tip_height: u64) -> (u64, u64, u64) {
        let recipient_hash = match address_to_recipient_hash(address) {
            Some(h) => h,
            None => return (0, 0, 0),
        };
        let maturity = bitaiir_chain::consensus::coinbase_maturity();
        let rec_confs = bitaiir_chain::consensus::RECOMMENDED_CONFIRMATIONS;

        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let mut immature: u64 = 0;

        for (outpoint, txout) in utxo.iter() {
            if txout.recipient_hash != recipient_hash {
                continue;
            }
            let amount = txout.amount.to_atomic();

            // Coinbase maturity check first.
            if let Some(cb_height) = utxo.coinbase_height(outpoint) {
                if tip_height < cb_height + maturity {
                    immature += amount;
                    continue;
                }
            }

            // Confirmation depth.
            let created = utxo.output_height(outpoint).unwrap_or(0);
            let confs = tip_height.saturating_sub(created);
            if confs >= rec_confs {
                confirmed += amount;
            } else {
                unconfirmed += amount;
            }
        }

        (confirmed, unconfirmed, immature)
    }
}

/// Decode a BitAiir address ("aiir...") to its 20-byte recipient_hash.
fn address_to_recipient_hash(address: &str) -> Option<[u8; 20]> {
    let body = address.strip_prefix("aiir")?;
    let decoded = bitaiir_crypto::base58::decode_check(body).ok()?;
    // decoded = version_byte (1) + hash160 (20) = 21 bytes
    if decoded.len() != 21 {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[1..]);
    Some(hash)
}

// -------------------------------------------------------------------------
// RPC API definition
// -------------------------------------------------------------------------

#[rpc(server)]
pub trait BitaiirApi {
    #[method(name = "getblockchaininfo")]
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo>;

    #[method(name = "getblock")]
    async fn get_block(&self, height: u64) -> RpcResult<serde_json::Value>;

    #[method(name = "getnewaddress")]
    async fn get_new_address(&self) -> RpcResult<String>;

    #[method(name = "getbalance")]
    async fn get_balance(&self, address: String) -> RpcResult<serde_json::Value>;

    #[method(name = "sendtoaddress")]
    async fn send_to_address(
        &self,
        to_address: String,
        amount: f64,
    ) -> RpcResult<serde_json::Value>;

    /// List all transactions involving an address (sent and received),
    /// in reverse chronological order (newest first).
    #[method(name = "gettransactionhistory")]
    async fn get_transaction_history(&self, address: String) -> RpcResult<serde_json::Value>;

    #[method(name = "getmempoolinfo")]
    async fn get_mempool_info(&self) -> RpcResult<serde_json::Value>;

    /// Start or stop mining. Pass `true` to start, `false` to stop.
    #[method(name = "setmining")]
    async fn set_mining(&self, active: bool) -> RpcResult<String>;

    /// List all wallet addresses with their balances.
    #[method(name = "listaddresses")]
    async fn list_addresses(&self) -> RpcResult<serde_json::Value>;

    /// Connect to a peer at the given address (ip:port) and perform
    /// the BitAiir handshake.
    #[method(name = "addpeer")]
    async fn add_peer(&self, addr: String) -> RpcResult<serde_json::Value>;

    /// Look up a transaction by its txid (hex).  Checks the mempool
    /// first (0 confirmations), then scans the chain backwards.
    #[method(name = "gettransaction")]
    async fn get_transaction(&self, txid: String) -> RpcResult<serde_json::Value>;

    /// List currently connected peers with their metadata.
    #[method(name = "listpeers")]
    async fn list_peers(&self) -> RpcResult<serde_json::Value>;

    /// List all known peer addresses (connected or not).
    #[method(name = "listknownpeers")]
    async fn list_known_peers(&self) -> RpcResult<serde_json::Value>;

    /// Export all wallet keys to a JSON file (WIF format).
    /// Requires the wallet to be unlocked if encrypted.
    #[method(name = "exportwallet")]
    async fn export_wallet(&self, filename: String) -> RpcResult<String>;

    /// Import wallet keys from a JSON backup file.
    #[method(name = "importwallet")]
    async fn import_wallet(&self, filename: String) -> RpcResult<String>;

    /// Import a single private key in WIF format.
    #[method(name = "importprivkey")]
    async fn import_privkey(&self, wif: String) -> RpcResult<serde_json::Value>;

    /// Encrypt the wallet with a passphrase.  All private keys are
    /// re-encrypted on disk.  The wallet stays unlocked after this
    /// call.  Subsequent restarts will require the passphrase.
    #[method(name = "encryptwallet")]
    async fn encrypt_wallet(&self, passphrase: String) -> RpcResult<String>;

    /// Unlock an encrypted wallet for `timeout` seconds.
    #[method(name = "walletpassphrase")]
    async fn wallet_passphrase(&self, passphrase: String, timeout: u64) -> RpcResult<String>;

    /// Lock the wallet immediately.
    #[method(name = "walletlock")]
    async fn wallet_lock(&self) -> RpcResult<String>;

    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockchainInfo {
    /// Active network ("mainnet" or "testnet").
    pub network: String,
    pub height: u64,
    pub tip: String,
    pub blocks: usize,
    pub utxos: usize,
    pub mempool: usize,
    pub subsidy: String,
}

// -------------------------------------------------------------------------
// RPC server implementation
// -------------------------------------------------------------------------

pub struct BitaiirRpcImpl {
    pub state: SharedState,
    pub shutdown: Arc<AtomicBool>,
    pub mining_active: Arc<AtomicBool>,
    pub storage: Arc<Storage>,
    /// Optional event channel — when set (interactive mode) RPC
    /// handlers push human-readable status lines here so the TUI can
    /// display them alongside mining output.
    pub events: Option<std::sync::mpsc::Sender<String>>,
}

impl BitaiirRpcImpl {
    /// Push a status line to the TUI event channel if one is wired up.
    fn emit(&self, msg: String) {
        if let Some(tx) = &self.events {
            let _ = tx.send(msg);
        }
    }

    /// Build a JSON object describing a transaction.
    fn format_tx(
        tx: &Transaction,
        txid: Hash256,
        block_info: Option<(u64, Hash256)>,
        tip: u64,
        rec_confs: u64,
    ) -> serde_json::Value {
        let is_coinbase = tx.is_coinbase();
        let (status, confirmations, block_height, block_hash) = match block_info {
            Some((h, bh)) => {
                let confs = tip.saturating_sub(h);
                let status = if confs >= rec_confs {
                    "confirmed"
                } else {
                    "unconfirmed"
                };
                (status, confs, Some(h), Some(bh.to_string()))
            }
            None => ("pending (mempool)", 0, None, None),
        };

        let inputs: Vec<serde_json::Value> = tx
            .inputs
            .iter()
            .map(|inp| {
                if inp.prev_out == OutPoint::NULL {
                    serde_json::json!({ "coinbase": true })
                } else {
                    serde_json::json!({
                        "txid": inp.prev_out.txid.to_string(),
                        "vout": inp.prev_out.vout,
                    })
                }
            })
            .collect();

        let outputs: Vec<serde_json::Value> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(i, out)| {
                let addr =
                    bitaiir_crypto::address::Address::from_recipient_hash(&out.recipient_hash);
                serde_json::json!({
                    "vout": i,
                    "address": addr.as_str(),
                    "amount": format!("{}", out.amount),
                })
            })
            .collect();

        serde_json::json!({
            "txid": txid.to_string(),
            "status": status,
            "confirmations": confirmations,
            "block_height": block_height,
            "block_hash": block_hash,
            "is_coinbase": is_coinbase,
            "inputs": inputs,
            "outputs": outputs,
        })
    }
}

#[async_trait]
impl BitaiirApiServer for BitaiirRpcImpl {
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo> {
        let state = self.state.read().await;
        let height = state.chain.height();
        Ok(BlockchainInfo {
            network: bitaiir_types::Network::active().name().to_string(),
            height,
            tip: state.chain.tip().to_string(),
            blocks: state.chain.len(),
            utxos: state.utxo.len(),
            mempool: state.mempool.len(),
            subsidy: format!("{}", subsidy(height + 1)),
        })
    }

    async fn get_block(&self, height: u64) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        match state.chain.block_at(height) {
            Some(block) => {
                let header = &block.header;
                let txids: Vec<String> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.txid().to_string())
                    .collect();
                Ok(serde_json::json!({
                    "height": height,
                    "hash": block.block_hash().to_string(),
                    "prev_block_hash": header.prev_block_hash.to_string(),
                    "merkle_root": header.merkle_root.to_string(),
                    "timestamp": header.timestamp,
                    "bits": format!("{:#010x}", header.bits),
                    "nonce": header.nonce,
                    "transactions": block.transactions.len(),
                    "txids": txids,
                    "coinbase_reward": block.transactions.first()
                        .map(|tx| {
                            let total: u64 = tx.outputs.iter()
                                .map(|o| o.amount.to_atomic())
                                .sum();
                            format!("{}", Amount::from_atomic(total))
                        })
                        .unwrap_or_default(),
                }))
            }
            None => Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -1,
                format!("block at height {height} not found"),
                None::<()>,
            )),
        }
    }

    async fn get_new_address(&self) -> RpcResult<String> {
        let mut state = self.state.write().await;
        let address = state.wallet.generate_address();
        // Persist the new key to disk so it survives restarts.
        let (privkey, pubkey) = state.wallet.get_keys(&address).unwrap().clone();
        if let Err(e) = self.storage.save_wallet_key(&address, &privkey, &pubkey) {
            tracing::warn!("failed to persist wallet key: {e}");
        }
        Ok(address)
    }

    async fn get_balance(&self, address: String) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let tip = state.chain.height();
        let (confirmed, unconfirmed, immature) =
            Wallet::balance_breakdown(&address, &state.utxo, tip);
        let spendable = confirmed + unconfirmed;
        let total = spendable + immature;
        Ok(serde_json::json!({
            "address": address,
            "spendable": format!("{}", Amount::from_atomic(spendable)),
            "confirmed": format!("{}", Amount::from_atomic(confirmed)),
            "unconfirmed": format!("{}", Amount::from_atomic(unconfirmed)),
            "immature": format!("{}", Amount::from_atomic(immature)),
            "total": format!("{}", Amount::from_atomic(total)),
        }))
    }

    async fn send_to_address(
        &self,
        to_address: String,
        amount: f64,
    ) -> RpcResult<serde_json::Value> {
        // Check wallet lock state.
        {
            let state = self.state.read().await;
            if state.wallet_encrypted && !state.wallet_unlocked {
                return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                    -13,
                    "wallet is locked, use /walletpassphrase to unlock",
                    None::<()>,
                ));
            }
            // Auto-lock if timeout expired.
            if state.wallet_lock_at > 0 && unix_now() >= state.wallet_lock_at {
                drop(state);
                let mut state = self.state.write().await;
                state.wallet.clear_keys();
                state.wallet_unlocked = false;
                state.wallet_lock_at = 0;
                return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                    -13,
                    "wallet auto-locked (timeout expired), use /walletpassphrase",
                    None::<()>,
                ));
            }
        }

        // Reject sending to your own wallet.
        {
            let state = self.state.read().await;
            if state.wallet.addresses().contains(&to_address) {
                return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                    -6,
                    "cannot send to your own address",
                    None::<()>,
                ));
            }
        }

        let amount_atoms = (amount * 100_000_000.0) as u64;

        let to_recipient_hash = address_to_recipient_hash(&to_address).ok_or_else(|| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -3,
                format!("invalid recipient address: {to_address}"),
                None::<()>,
            )
        })?;

        // --- Phase 1: snapshot under a READ lock ------------------------ //
        //
        // Collect everything we need to build the transaction (keys,
        // inputs, balances) and then drop the lock before running the
        // ~2 s anti-spam PoW.  Holding the write lock across that work
        // would freeze the mining thread and the TUI.
        //
        // UTXO selection skips immature coinbases — they pass the
        // `recipient_hash` check but would be rejected by consensus
        // rules downstream, so picking them here would make the
        // transaction explode with a confusing error.
        let (from_address, privkey, pubkey_bytes, from_hash, selected_utxos, inputs_total) = {
            let state = self.state.read().await;
            let tip_height = state.chain.height();
            let maturity = bitaiir_chain::consensus::coinbase_maturity();

            // Find a wallet address with enough *spendable* balance.
            let addresses = state.wallet.addresses();
            let mut from_address: Option<String> = None;
            for addr in &addresses {
                let bal = Wallet::spendable_balance_of(addr, &state.utxo, tip_height);
                if bal >= amount_atoms {
                    from_address = Some(addr.clone());
                    break;
                }
            }
            let from_address = from_address.ok_or_else(|| {
                jsonrpsee::types::ErrorObjectOwned::owned(
                    -2,
                    "insufficient spendable balance (immature coinbases don't count)",
                    None::<()>,
                )
            })?;

            let (privkey, pubkey) = state
                .wallet
                .get_keys(&from_address)
                .expect("address exists in wallet")
                .clone();

            let pubkey_bytes = pubkey.to_compressed();
            let from_hash = hash160(&pubkey_bytes);

            // Collect mature UTXOs from this address.
            let mut inputs_total: u64 = 0;
            let mut selected_utxos: Vec<(OutPoint, TxOut)> = Vec::new();
            for (outpoint, txout) in state.utxo.iter() {
                if txout.recipient_hash != from_hash {
                    continue;
                }
                // Skip immature coinbases — they can't be spent yet.
                if let Some(cb_height) = state.utxo.coinbase_height(outpoint) {
                    if tip_height < cb_height + maturity {
                        continue;
                    }
                }
                selected_utxos.push((*outpoint, *txout));
                inputs_total = inputs_total.saturating_add(txout.amount.to_atomic());
                if inputs_total >= amount_atoms {
                    break;
                }
            }

            if inputs_total < amount_atoms {
                return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                    -2,
                    "insufficient spendable balance (immature coinbases don't count)",
                    None::<()>,
                ));
            }

            (
                from_address,
                privkey,
                pubkey_bytes,
                from_hash,
                selected_utxos,
                inputs_total,
            )
        };

        // --- Phase 2: build + sign + mine PoW (NO lock) ----------------- //

        // Build transaction outputs (recipient + change).
        let mut outputs = vec![TxOut {
            amount: Amount::from_atomic(amount_atoms),
            recipient_hash: to_recipient_hash,
        }];
        let change = inputs_total - amount_atoms;
        if change > 0 {
            outputs.push(TxOut {
                amount: Amount::from_atomic(change),
                recipient_hash: from_hash,
            });
        }

        let mut tx = Transaction {
            version: 1,
            inputs: selected_utxos
                .iter()
                .map(|(outpoint, _)| TxIn {
                    prev_out: *outpoint,
                    signature: Vec::new(),
                    pubkey: pubkey_bytes.to_vec(),
                    sequence: u32::MAX,
                })
                .collect(),
            outputs,
            locktime: 0,
            pow_nonce: 0,
        };

        // Sign each input.
        let sighash = tx.sighash();
        let sig = privkey.sign_digest(sighash.as_bytes());
        for input in &mut tx.inputs {
            input.signature = sig.clone();
        }

        // Mine the anti-spam PoW on the blocking thread pool so the
        // Tokio reactor stays responsive while the CPU grinds.
        let tx = tokio::task::spawn_blocking(move || {
            bitaiir_chain::mine_tx_pow(&mut tx);
            tx
        })
        .await
        .map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -5,
                format!("tx pow mining task failed: {e}"),
                None::<()>,
            )
        })?;

        // --- Phase 3: re-validate + broadcast under WRITE lock ---------- //

        let mut state = self.state.write().await;

        // Re-validate: a block may have landed between phase 1 and
        // here, so the UTXOs we picked might no longer exist.
        let current_height = state.chain.height();
        if let Err(e) = validate_transaction(&tx, &state.utxo, current_height) {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -4,
                e.to_string(),
                None::<()>,
            ));
        }

        let txid = tx.txid();

        // Broadcast tx to all connected peers before adding to local mempool.
        let tx_bytes = bitaiir_types::encoding::to_bytes(&tx).expect("Transaction always encodes");
        for peer in &state.peers {
            let _ = peer
                .sender
                .try_send(bitaiir_net::NetMessage::TxData(tx_bytes.clone()));
        }
        let peers_notified = state.peers.len();

        state.mempool.add(tx);

        Ok(serde_json::json!({
            "txid": txid.to_string(),
            "from": from_address,
            "to": to_address,
            "amount": format!("{}", Amount::from_atomic(amount_atoms)),
            "change": format!("{}", Amount::from_atomic(change)),
            "peers_notified": peers_notified,
            "status": "added to mempool",
        }))
    }

    async fn get_transaction_history(&self, address: String) -> RpcResult<serde_json::Value> {
        let target_hash = address_to_recipient_hash(&address).ok_or_else(|| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -1,
                format!("invalid address: {address}"),
                None::<()>,
            )
        })?;

        let state = self.state.read().await;
        let tip = state.chain.height();
        let rec_confs = bitaiir_chain::consensus::RECOMMENDED_CONFIRMATIONS;
        let mut history: Vec<serde_json::Value> = Vec::new();

        // Scan the chain from genesis to tip.
        for h in 0..=tip {
            let Some(block) = state.chain.block_at(h) else {
                continue;
            };
            let timestamp = block.header.timestamp;
            let confs = tip.saturating_sub(h);

            for tx in &block.transactions {
                let txid = tx.txid();
                let is_coinbase = tx.is_coinbase();

                // Check if we RECEIVED in this tx (outputs to our address).
                let mut received: u64 = 0;
                for out in &tx.outputs {
                    if out.recipient_hash == target_hash {
                        received += out.amount.to_atomic();
                    }
                }

                // Check if we SENT from this tx (inputs signed by our key).
                let mut sent: u64 = 0;
                let mut is_sender = false;
                if !is_coinbase {
                    for inp in &tx.inputs {
                        if !inp.pubkey.is_empty() {
                            let pk_hash = hash160(&inp.pubkey);
                            if pk_hash == target_hash {
                                is_sender = true;
                            }
                        }
                    }
                    if is_sender {
                        // Amount sent = outputs NOT going to our address.
                        for out in &tx.outputs {
                            if out.recipient_hash != target_hash {
                                sent += out.amount.to_atomic();
                            }
                        }
                    }
                }

                // Skip txs that don't involve this address at all.
                if received == 0 && !is_sender {
                    continue;
                }

                let status = if confs >= rec_confs {
                    "confirmed"
                } else {
                    "unconfirmed"
                };

                if is_coinbase && received > 0 {
                    history.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "type": "coinbase",
                        "amount": format!("{}", Amount::from_atomic(received)),
                        "block_height": h,
                        "timestamp": timestamp,
                        "confirmations": confs,
                        "status": status,
                    }));
                } else if is_sender && received > 0 {
                    // Sent but also got change back — show as "send".
                    history.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "type": "send",
                        "amount": format!("-{}", Amount::from_atomic(sent)),
                        "block_height": h,
                        "timestamp": timestamp,
                        "confirmations": confs,
                        "status": status,
                    }));
                } else if is_sender {
                    history.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "type": "send",
                        "amount": format!("-{}", Amount::from_atomic(sent)),
                        "block_height": h,
                        "timestamp": timestamp,
                        "confirmations": confs,
                        "status": status,
                    }));
                } else if received > 0 {
                    history.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "type": "receive",
                        "amount": format!("+{}", Amount::from_atomic(received)),
                        "block_height": h,
                        "timestamp": timestamp,
                        "confirmations": confs,
                        "status": status,
                    }));
                }
            }
        }

        // Also check the mempool for pending txs.
        for (_txid_hash, tx) in state.mempool.iter() {
            let txid = tx.txid();
            let mut received: u64 = 0;
            for out in &tx.outputs {
                if out.recipient_hash == target_hash {
                    received += out.amount.to_atomic();
                }
            }
            let mut sent: u64 = 0;
            let mut is_sender = false;
            for inp in &tx.inputs {
                if !inp.pubkey.is_empty() {
                    let pk_hash = hash160(&inp.pubkey);
                    if pk_hash == target_hash {
                        is_sender = true;
                    }
                }
            }
            if is_sender {
                for out in &tx.outputs {
                    if out.recipient_hash != target_hash {
                        sent += out.amount.to_atomic();
                    }
                }
            }
            if is_sender {
                history.push(serde_json::json!({
                    "txid": txid.to_string(),
                    "type": "send",
                    "amount": format!("-{}", Amount::from_atomic(sent)),
                    "block_height": null,
                    "timestamp": null,
                    "confirmations": 0,
                    "status": "pending (mempool)",
                }));
            } else if received > 0 {
                history.push(serde_json::json!({
                    "txid": txid.to_string(),
                    "type": "receive",
                    "amount": format!("+{}", Amount::from_atomic(received)),
                    "block_height": null,
                    "timestamp": null,
                    "confirmations": 0,
                    "status": "pending (mempool)",
                }));
            }
        }

        // Reverse so newest first.
        history.reverse();

        Ok(serde_json::json!({
            "address": address,
            "count": history.len(),
            "transactions": history,
        }))
    }

    async fn get_mempool_info(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        Ok(serde_json::json!({
            "size": state.mempool.len(),
        }))
    }

    async fn list_addresses(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let tip = state.chain.height();
        let addresses = state.wallet.addresses();
        let mut result = Vec::new();
        for addr in &addresses {
            let (confirmed, unconfirmed, immature) =
                Wallet::balance_breakdown(addr, &state.utxo, tip);
            let spendable = confirmed + unconfirmed;
            let total = spendable + immature;
            result.push(serde_json::json!({
                "address": addr,
                "spendable": format!("{}", Amount::from_atomic(spendable)),
                "confirmed": format!("{}", Amount::from_atomic(confirmed)),
                "unconfirmed": format!("{}", Amount::from_atomic(unconfirmed)),
                "immature": format!("{}", Amount::from_atomic(immature)),
                "total": format!("{}", Amount::from_atomic(total)),
            }));
        }
        Ok(serde_json::json!({
            "count": addresses.len(),
            "addresses": result,
        }))
    }

    async fn set_mining(&self, active: bool) -> RpcResult<String> {
        self.mining_active.store(active, Ordering::Relaxed);
        if active {
            Ok("Mining started.".to_string())
        } else {
            Ok("Mining stopping after current block...".to_string())
        }
    }

    async fn add_peer(&self, addr: String) -> RpcResult<serde_json::Value> {
        use tokio::net::TcpStream;

        let stream = TcpStream::connect(&addr).await.map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -10,
                format!("failed to connect to {addr}: {e}"),
                None::<()>,
            )
        })?;

        let peer_addr = stream.peer_addr().unwrap_or_else(|_| addr.parse().unwrap());
        let mut peer = bitaiir_net::Peer::new(stream, peer_addr);

        let our_height = {
            let state = self.state.read().await;
            state.chain.height()
        };

        let their_version = peer.handshake_outbound(our_height).await.map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                format!("handshake failed: {e}"),
                None::<()>,
            )
        })?;

        // If the peer has more blocks, sync them.
        let mut synced_blocks: u64 = 0;
        if their_version.best_height > our_height {
            tracing::info!(
                "peer is ahead: their height={}, ours={}. Syncing...",
                their_version.best_height,
                our_height,
            );

            peer.send(&bitaiir_net::NetMessage::GetBlocks(our_height))
                .await
                .map_err(|e| {
                    jsonrpsee::types::ErrorObjectOwned::owned(
                        -12,
                        format!("failed to request blocks: {e}"),
                        None::<()>,
                    )
                })?;

            // Receive blocks until SyncDone.
            loop {
                let msg = peer.receive().await.map_err(|e| {
                    jsonrpsee::types::ErrorObjectOwned::owned(
                        -13,
                        format!("sync error: {e}"),
                        None::<()>,
                    )
                })?;

                match msg {
                    bitaiir_net::NetMessage::BlockData(bytes) => {
                        let block: bitaiir_types::Block =
                            bitaiir_types::encoding::from_bytes(&bytes).map_err(|e| {
                                jsonrpsee::types::ErrorObjectOwned::owned(
                                    -14,
                                    format!("invalid block data: {e}"),
                                    None::<()>,
                                )
                            })?;

                        let mut state = self.state.write().await;
                        let height = state.chain.height() + 1;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        // Validate the block (skip future-timestamp for synced blocks).
                        if let Err(e) = bitaiir_chain::validate_block(
                            &block,
                            &state.chain,
                            &state.utxo,
                            now + 7200,
                        ) {
                            tracing::warn!(
                                "synced block at height {height} failed validation: {e}"
                            );
                            break;
                        }

                        state.chain.push(block.clone()).unwrap();
                        // Apply the block's transactions to the UTXO
                        // set and capture the undo record in a
                        // single pass; persist both atomically.
                        let undo = match state.utxo.apply_block_with_undo(&block, height) {
                            Ok(u) => u,
                            Err(e) => {
                                tracing::warn!("synced block {height} UTXO apply failed: {e}");
                                break;
                            }
                        };

                        // Persist.
                        if let Err(e) = self.storage.apply_block(height, &block, &undo) {
                            tracing::warn!("failed to persist synced block {height}: {e}");
                        }

                        // Remove confirmed txs from mempool.
                        for tx in block.transactions.iter().skip(1) {
                            state.mempool.remove(&tx.txid());
                        }

                        synced_blocks += 1;
                        tracing::info!("synced block {height}");
                    }
                    bitaiir_net::NetMessage::SyncDone => {
                        tracing::info!("sync complete: {synced_blocks} blocks received");
                        break;
                    }
                    _ => {} // ignore other messages during sync
                }
            }
        }

        let new_height = {
            let state = self.state.read().await;
            state.chain.height()
        };

        // Keep the peer connection alive for tx gossip. Split into
        // reader/writer, spawn a background task that multiplexes
        // incoming messages with outgoing tx broadcasts.
        let (reader, writer, peer_addr) = peer.into_parts();
        let (tx_send, mut tx_recv) = tokio::sync::mpsc::channel::<bitaiir_net::NetMessage>(100);

        // Register this peer's metadata + sender channel in shared state,
        // and add/update the known-peer database so the PeerManager can
        // reconnect if the connection drops later.
        let peer_addr_key = peer_addr.to_string();
        {
            let mut state = self.state.write().await;
            state.peers.push(ConnectedPeer {
                addr: peer_addr_key.clone(),
                user_agent: their_version.user_agent.clone(),
                best_height: their_version.best_height,
                direction: PeerDirection::Outbound,
                connected_at: std::time::Instant::now(),
                sender: tx_send,
            });
            // Upsert known peer (or update existing entry on success).
            let kp = state
                .known_peers
                .entry(addr.clone())
                .or_insert_with(|| KnownPeer {
                    addr: addr.clone(),
                    last_seen: 0,
                    consecutive_failures: 0,
                    banned_until: 0,
                    source: PeerSource::Manual,
                });
            kp.record_success();
        }
        // Event line for the interactive TUI (plain text — the TUI
        // doesn't re-parse colors for free-form event strings).
        self.emit(format!(
            "  peer connected: {peer_addr_key} (outbound, {}, height {})",
            their_version.user_agent, their_version.best_height,
        ));

        let gossip_state = self.state.clone();
        let gossip_storage: Option<Arc<Storage>> = Some(self.storage.clone());
        let gossip_events = self.events.clone();
        let gossip_peer_key = peer_addr_key.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut reader = reader;
            let mut writer = writer;

            loop {
                tokio::select! {
                    // Outgoing: forward tx broadcasts from sendtoaddress
                    msg = tx_recv.recv() => {
                        match msg {
                            Some(m) => {
                                let payload = m.to_payload();
                                let frame = bitaiir_net::protocol::frame_message(m.command(), &payload);
                                if writer.write_all(&frame).await.is_err() {
                                    break;
                                }
                                let _ = writer.flush().await;
                            }
                            None => break, // channel closed
                        }
                    }
                    // Incoming: read messages from the peer
                    result = async {
                        let mut header_buf = [0u8; bitaiir_net::protocol::HEADER_SIZE];
                        reader.read_exact(&mut header_buf).await?;
                        let header = bitaiir_net::protocol::parse_header(&header_buf)
                            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad magic"))?;
                        let mut payload = vec![0u8; header.payload_len as usize];
                        if !payload.is_empty() {
                            reader.read_exact(&mut payload).await?;
                        }
                        Ok::<_, std::io::Error>(
                            bitaiir_net::NetMessage::from_payload(&header.command, &payload)
                        )
                    } => {
                        match result {
                            Ok(Some(bitaiir_net::NetMessage::TxData(bytes))) => {
                                if let Ok(tx) = bitaiir_types::encoding::from_bytes::<bitaiir_types::Transaction>(&bytes) {
                                    let txid = tx.txid();
                                    let mut s = gossip_state.write().await;
                                    if !s.mempool.contains(&txid) {
                                        s.mempool.add(tx);
                                        tracing::info!("received tx {txid} from peer {peer_addr}");
                                    }
                                }
                            }
                            Ok(Some(bitaiir_net::NetMessage::BlockData(bytes))) => {
                                if let Ok(block) = bitaiir_types::encoding::from_bytes::<bitaiir_types::Block>(&bytes) {
                                    let mut s = gossip_state.write().await;
                                    let height = s.chain.height() + 1;
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();
                                    if let Ok(()) = bitaiir_chain::validate_block(&block, &s.chain, &s.utxo, now + 7200) {
                                        if s.chain.push(block.clone()).is_ok() {
                                            if let Ok(undo) = s.utxo.apply_block_with_undo(&block, height) {
                                                if let Some(storage) = gossip_storage.as_ref() {
                                                    let _ = storage.apply_block(height, &block, &undo);
                                                }
                                                // Remove confirmed txs from mempool.
                                                for tx in block.transactions.iter().skip(1) {
                                                    s.mempool.remove(&tx.txid());
                                                }
                                                for p in &mut s.peers {
                                                    if p.addr == gossip_peer_key {
                                                        p.best_height = p.best_height.max(height);
                                                        break;
                                                    }
                                                }
                                                tracing::info!("received block {height} from peer {peer_addr}");
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Some(bitaiir_net::NetMessage::Ping(n))) => {
                                let pong = bitaiir_net::NetMessage::Pong(n);
                                let payload = pong.to_payload();
                                let frame = bitaiir_net::protocol::frame_message(pong.command(), &payload);
                                let _ = writer.write_all(&frame).await;
                                let _ = writer.flush().await;
                            }
                            Ok(_) => {} // ignore other messages
                            Err(_) => {
                                tracing::info!("peer {peer_addr} disconnected (gossip)");
                                break;
                            }
                        }
                    }
                }
            }

            // Peer is gone — remove it from NodeState so it no longer
            // shows up in `listpeers` and we stop trying to broadcast
            // to it.  Emit an event line for the TUI.
            {
                let mut s = gossip_state.write().await;
                s.peers.retain(|p| p.addr != gossip_peer_key);
            }
            if let Some(ev) = &gossip_events {
                let _ = ev.send(format!("  peer disconnected: {gossip_peer_key}"));
            }
        });

        Ok(serde_json::json!({
            "peer": addr,
            "user_agent": their_version.user_agent,
            "peer_height": their_version.best_height,
            "protocol_version": their_version.protocol_version,
            "synced_blocks": synced_blocks,
            "new_height": new_height,
            "status": if synced_blocks > 0 { "connected, synced, gossiping" } else { "connected, gossiping" },
        }))
    }

    async fn get_transaction(&self, txid_hex: String) -> RpcResult<serde_json::Value> {
        let target = txid_hex.parse::<Hash256>().map_err(|_| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -1,
                format!("invalid txid: {txid_hex}"),
                None::<()>,
            )
        })?;

        let state = self.state.read().await;
        let tip = state.chain.height();
        let rec_confs = bitaiir_chain::consensus::RECOMMENDED_CONFIRMATIONS;

        // Check the mempool first (0 confirmations).
        if let Some(tx) = state.mempool.get(&target) {
            return Ok(Self::format_tx(tx, target, None, tip, rec_confs));
        }

        // Scan the chain backwards (most recent blocks first).
        for h in (0..=tip).rev() {
            if let Some(block) = state.chain.block_at(h) {
                for tx in &block.transactions {
                    if tx.txid() == target {
                        return Ok(Self::format_tx(
                            tx,
                            target,
                            Some((h, block.block_hash())),
                            tip,
                            rec_confs,
                        ));
                    }
                }
            }
        }

        Err(jsonrpsee::types::ErrorObjectOwned::owned(
            -1,
            format!("transaction {txid_hex} not found"),
            None::<()>,
        ))
    }

    async fn list_peers(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let now = std::time::Instant::now();
        let peers: Vec<serde_json::Value> = state
            .peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "addr": p.addr,
                    "user_agent": p.user_agent,
                    "height": p.best_height,
                    "direction": p.direction.as_str(),
                    "connected_seconds": now.duration_since(p.connected_at).as_secs(),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "count": peers.len(),
            "peers": peers,
        }))
    }

    async fn list_known_peers(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        let now = unix_now();
        let mut peers: Vec<serde_json::Value> = state
            .known_peers
            .values()
            .map(|p| {
                let banned = p.banned_until > now;
                serde_json::json!({
                    "addr": p.addr,
                    "last_seen": p.last_seen,
                    "failures": p.consecutive_failures,
                    "banned": banned,
                    "source": p.source.as_str(),
                })
            })
            .collect();
        // Sort by last_seen descending (most recent first).
        peers.sort_by(|a, b| {
            let a_ts = a["last_seen"].as_u64().unwrap_or(0);
            let b_ts = b["last_seen"].as_u64().unwrap_or(0);
            b_ts.cmp(&a_ts)
        });
        Ok(serde_json::json!({
            "count": peers.len(),
            "peers": peers,
        }))
    }

    async fn export_wallet(&self, filename: String) -> RpcResult<String> {
        let state = self.state.read().await;
        if state.wallet_encrypted && !state.wallet_unlocked {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -13,
                "wallet is locked, unlock before exporting",
                None::<()>,
            ));
        }

        let addresses = state.wallet.addresses();
        let mut keys = Vec::new();
        for addr in &addresses {
            if let Some((privkey, pubkey)) = state.wallet.get_keys(addr) {
                let wif = bitaiir_crypto::wif::encode(privkey, true);
                keys.push(serde_json::json!({
                    "address": addr,
                    "private_key_wif": wif,
                    "private_key_hex": hex::encode(privkey.to_bytes()),
                    "public_key_hex": hex::encode(pubkey.to_compressed()),
                }));
            }
        }

        let backup = serde_json::json!({
            "version": 1,
            "network": "mainnet",
            "created_at": unix_now(),
            "keys": keys,
        });

        let json = serde_json::to_string_pretty(&backup).unwrap();
        std::fs::write(&filename, &json).map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                format!("failed to write file: {e}"),
                None::<()>,
            )
        })?;

        self.emit(format!("  Wallet exported to {filename}"));
        Ok(format!("exported {} key(s) to {filename}", keys.len()))
    }

    async fn import_wallet(&self, filename: String) -> RpcResult<String> {
        let content = std::fs::read_to_string(&filename).map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                format!("failed to read file: {e}"),
                None::<()>,
            )
        })?;

        let backup: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(-11, format!("invalid JSON: {e}"), None::<()>)
        })?;

        let keys = backup["keys"].as_array().ok_or_else(|| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                "missing 'keys' array in backup file",
                None::<()>,
            )
        })?;

        let mut imported = 0u32;
        let mut state = self.state.write().await;
        for entry in keys {
            let Some(wif) = entry["private_key_wif"].as_str() else {
                continue;
            };
            let Ok((privkey, _compressed)) = bitaiir_crypto::wif::decode(wif) else {
                continue;
            };
            let pubkey = privkey.public_key();
            let address = bitaiir_crypto::address::Address::from_compressed_public_key(&pubkey);
            let addr_str = address.as_str().to_string();

            // Save to storage.
            let _ = self.storage.save_wallet_key(&addr_str, &privkey, &pubkey);

            // Add to in-memory wallet.
            state.wallet.import_key(addr_str, privkey, pubkey);
            imported += 1;
        }

        self.emit(format!("  Imported {imported} key(s) from {filename}"));
        Ok(format!("imported {imported} key(s) from {filename}"))
    }

    async fn import_privkey(&self, wif: String) -> RpcResult<serde_json::Value> {
        let (privkey, _compressed) = bitaiir_crypto::wif::decode(&wif).map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                format!("invalid WIF key: {e}"),
                None::<()>,
            )
        })?;

        let pubkey = privkey.public_key();
        let address = bitaiir_crypto::address::Address::from_compressed_public_key(&pubkey);
        let addr_str = address.as_str().to_string();

        // Save to storage.
        self.storage
            .save_wallet_key(&addr_str, &privkey, &pubkey)
            .map_err(|e| {
                jsonrpsee::types::ErrorObjectOwned::owned(
                    -11,
                    format!("storage error: {e}"),
                    None::<()>,
                )
            })?;

        // Add to in-memory wallet.
        let mut state = self.state.write().await;
        state.wallet.import_key(addr_str.clone(), privkey, pubkey);

        self.emit(format!("  Imported key: {addr_str}"));
        Ok(serde_json::json!({
            "address": addr_str,
            "status": "imported",
        }))
    }

    async fn encrypt_wallet(&self, passphrase: String) -> RpcResult<String> {
        // Enforce minimum passphrase strength.
        if let Err(msg) = wallet_crypto::validate_passphrase(&passphrase) {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -10, msg, None::<()>,
            ));
        }

        let mut state = self.state.write().await;
        if state.wallet_encrypted {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -10,
                "wallet is already encrypted",
                None::<()>,
            ));
        }

        // Derive the AES key from the passphrase.
        // `key` is Zeroizing — zeroed in memory when dropped.
        let salt = wallet_crypto::random_salt();
        let key = wallet_crypto::derive_key(passphrase.as_bytes(), &salt);

        // Re-encrypt every private key on disk.
        let addresses = state.wallet.addresses();
        for addr in &addresses {
            let (privkey, pubkey) = state.wallet.get_keys(addr).expect("key exists").clone();
            let encrypted = wallet_crypto::encrypt_privkey(&key, &privkey.to_bytes());
            // Store: encrypted_privkey + pubkey (unencrypted).
            let mut value = Vec::with_capacity(encrypted.len() + 33);
            value.extend_from_slice(&encrypted);
            value.extend_from_slice(&pubkey.to_compressed());
            self.storage
                .save_wallet_key_raw(addr, &value)
                .map_err(|e| {
                    jsonrpsee::types::ErrorObjectOwned::owned(
                        -11,
                        format!("storage error: {e}"),
                        None::<()>,
                    )
                })?;
        }

        // Store salt and check blob in metadata.
        let check = wallet_crypto::create_check_blob(&key);
        let _ = self.storage.set_metadata("wallet_salt", &salt);
        let _ = self.storage.set_metadata("wallet_check", &check);
        let _ = self.storage.set_metadata("wallet_encrypted", &[1]);

        state.wallet_encrypted = true;
        state.wallet_unlocked = true; // stays unlocked after encryption

        self.emit("  Wallet encrypted successfully.".to_string());
        Ok(format!(
            "wallet encrypted ({} key(s)). Remember your passphrase!",
            addresses.len()
        ))
    }

    async fn wallet_passphrase(&self, passphrase: String, timeout: u64) -> RpcResult<String> {
        let mut state = self.state.write().await;
        if !state.wallet_encrypted {
            return Ok("wallet is not encrypted".to_string());
        }
        if state.wallet_unlocked {
            // Just extend the timeout.
            state.wallet_lock_at = if timeout == 0 {
                0
            } else {
                unix_now() + timeout
            };
            return Ok(format!(
                "wallet already unlocked (timeout extended to {timeout}s)"
            ));
        }

        // Load salt and verify passphrase.
        let salt = self
            .storage
            .get_metadata("wallet_salt")
            .ok()
            .flatten()
            .ok_or_else(|| {
                jsonrpsee::types::ErrorObjectOwned::owned(
                    -12,
                    "wallet salt not found in storage",
                    None::<()>,
                )
            })?;
        let check = self
            .storage
            .get_metadata("wallet_check")
            .ok()
            .flatten()
            .ok_or_else(|| {
                jsonrpsee::types::ErrorObjectOwned::owned(
                    -12,
                    "wallet check blob not found in storage",
                    None::<()>,
                )
            })?;

        let key = wallet_crypto::derive_key(passphrase.as_bytes(), &salt);
        if !wallet_crypto::verify_check_blob(&key, &check) {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -13,
                "incorrect passphrase",
                None::<()>,
            ));
        }

        // Decrypt all private keys from storage into the in-memory wallet.
        let stored_keys = self.storage.load_wallet_keys_raw().map_err(|e| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -11,
                format!("storage error: {e}"),
                None::<()>,
            )
        })?;

        for (addr, bytes) in &stored_keys {
            // Encrypted format: encrypted_privkey(60) + pubkey(33) = 93
            if bytes.len() < 60 + 33 {
                continue;
            }
            let encrypted_privkey = &bytes[..60];
            let pubkey_bytes = &bytes[60..];

            let privkey_bytes = wallet_crypto::decrypt_privkey(&key, encrypted_privkey)
                .ok_or_else(|| {
                    jsonrpsee::types::ErrorObjectOwned::owned(
                        -13,
                        format!("failed to decrypt key for {addr}"),
                        None::<()>,
                    )
                })?;

            if let (Ok(privkey), Ok(pubkey)) = (
                bitaiir_crypto::key::PrivateKey::from_bytes(&privkey_bytes),
                bitaiir_crypto::key::PublicKey::from_slice(pubkey_bytes),
            ) {
                state.wallet.import_key(addr.clone(), privkey, pubkey);
            }
        }

        state.wallet_unlocked = true;
        state.wallet_lock_at = if timeout == 0 {
            0
        } else {
            unix_now() + timeout
        };

        self.emit("  Wallet unlocked.".to_string());
        Ok(format!("wallet unlocked for {timeout}s"))
    }

    async fn wallet_lock(&self) -> RpcResult<String> {
        let mut state = self.state.write().await;
        if !state.wallet_encrypted {
            return Ok("wallet is not encrypted, nothing to lock".to_string());
        }
        // Clear private keys from memory.
        state.wallet.clear_keys();
        state.wallet_unlocked = false;
        state.wallet_lock_at = 0;
        self.emit("  Wallet locked.".to_string());
        Ok("wallet locked".to_string())
    }

    async fn stop(&self) -> RpcResult<String> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok("BitAiir daemon stopping...".to_string())
    }
}
