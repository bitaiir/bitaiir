//! JSON-RPC interface to a running BitAiir node.
//!
//! This crate defines the RPC methods that `bitaiir-cli` (and any
//! third-party tooling) can call on a running daemon. The server
//! implementation holds a reference to the shared node state and
//! translates RPC calls into reads/writes on the chain, UTXO set,
//! mempool, and wallet.

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
}

/// One live P2P connection.  Holds both the broadcast channel
/// (used to relay new blocks and transactions to the peer) and the
/// metadata we expose via the `listpeers` RPC.
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

/// Thread-safe handle to the node state.
pub type SharedState = Arc<RwLock<NodeState>>;

// -------------------------------------------------------------------------
// Wallet (in-memory keystore)
// -------------------------------------------------------------------------

/// A simple in-memory wallet that stores keypairs and can build
/// signed transactions. No persistence — keys are lost on restart.
pub struct Wallet {
    /// Map from address string ("aiir...") to (private_key, public_key, compressed).
    keys: HashMap<String, (PrivateKey, PublicKey)>,
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
        }
    }

    /// Generate a new keypair and return the BitAiir address.
    pub fn generate_address(&mut self) -> String {
        let privkey = PrivateKey::generate();
        let pubkey = privkey.public_key();
        let address = Address::from_compressed_public_key(&pubkey);
        let addr_str = address.as_str().to_string();
        self.keys.insert(addr_str.clone(), (privkey, pubkey));
        addr_str
    }

    /// Import an existing keypair (used when loading from storage).
    pub fn import_key(&mut self, address: String, privkey: PrivateKey, pubkey: PublicKey) {
        self.keys.insert(address, (privkey, pubkey));
    }

    /// Look up a keypair by address.
    pub fn get_keys(&self, address: &str) -> Option<&(PrivateKey, PublicKey)> {
        self.keys.get(address)
    }

    /// List all addresses in the wallet.
    pub fn addresses(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
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
        let maturity = bitaiir_chain::consensus::COINBASE_MATURITY;

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
        let maturity = bitaiir_chain::consensus::COINBASE_MATURITY;
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

    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockchainInfo {
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
    fn emit(&self, msg: impl Into<String>) {
        if let Some(tx) = &self.events {
            let _ = tx.send(msg.into());
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
                Ok(serde_json::json!({
                    "height": height,
                    "hash": block.block_hash().to_string(),
                    "prev_block_hash": header.prev_block_hash.to_string(),
                    "merkle_root": header.merkle_root.to_string(),
                    "timestamp": header.timestamp,
                    "bits": format!("{:#010x}", header.bits),
                    "nonce": header.nonce,
                    "transactions": block.transactions.len(),
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
            let maturity = bitaiir_chain::consensus::COINBASE_MATURITY;

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

                        // Collect spent outpoints for storage.
                        let spent: Vec<OutPoint> = block
                            .transactions
                            .iter()
                            .skip(1)
                            .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
                            .collect();

                        state.chain.push(block.clone()).unwrap();
                        for tx in &block.transactions {
                            state.utxo.apply_transaction(tx, height).unwrap();
                        }

                        // Persist.
                        if let Err(e) = self.storage.apply_block(height, &block, &spent) {
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

        // Register this peer's metadata + sender channel in shared state.
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
                                        let spent: Vec<OutPoint> = block.transactions.iter().skip(1)
                                            .flat_map(|tx| tx.inputs.iter().map(|i| i.prev_out))
                                            .collect();
                                        if s.chain.push(block.clone()).is_ok() {
                                            for tx in &block.transactions {
                                                let _ = s.utxo.apply_transaction(tx, height);
                                            }
                                            if let Some(storage) = gossip_storage.as_ref() {
                                                let _ = storage.apply_block(height, &block, &spent);
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

    async fn stop(&self) -> RpcResult<String> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok("BitAiir daemon stopping...".to_string())
    }
}
