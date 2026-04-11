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
use bitaiir_types::{Amount, OutPoint, Transaction, TxIn, TxOut};
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
    /// Channels to send messages to connected peers (for tx gossip).
    pub peer_senders: Vec<tokio::sync::mpsc::Sender<bitaiir_net::NetMessage>>,
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
    pub fn balance_of(address: &str, utxo: &UtxoSet) -> u64 {
        // Strip the "aiir" prefix to get the base58check body, then
        // decode to get the recipient_hash. BUT it's simpler to just
        // compute hash160 for every known address and scan.
        // Since we have the pubkey, compute the recipient_hash directly.
        // This is a O(n) scan of the UTXO set — fine for development.
        //
        // Actually, we need the recipient_hash from the address. The
        // easiest approach: iterate all UTXOs and compare recipient_hash.
        // We need a way to go from address -> recipient_hash. Let's
        // compute it from the pubkey if we have it, or decode the address.

        // For arbitrary addresses (not in our wallet), decode the address.
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
        let balance_atoms = Wallet::balance_of(&address, &state.utxo);
        Ok(serde_json::json!({
            "address": address,
            "balance": format!("{}", Amount::from_atomic(balance_atoms)),
            "balance_atomic": balance_atoms,
        }))
    }

    async fn send_to_address(
        &self,
        to_address: String,
        amount: f64,
    ) -> RpcResult<serde_json::Value> {
        let amount_atoms = (amount * 100_000_000.0) as u64;

        let mut state = self.state.write().await;

        // Find a wallet address with enough balance.
        let addresses = state.wallet.addresses();
        let mut from_address: Option<String> = None;
        for addr in &addresses {
            let bal = Wallet::balance_of(addr, &state.utxo);
            if bal >= amount_atoms {
                from_address = Some(addr.clone());
                break;
            }
        }
        let from_address = from_address.ok_or_else(|| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -2,
                "insufficient balance in wallet",
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

        let to_recipient_hash = address_to_recipient_hash(&to_address).ok_or_else(|| {
            jsonrpsee::types::ErrorObjectOwned::owned(
                -3,
                format!("invalid recipient address: {to_address}"),
                None::<()>,
            )
        })?;

        // Collect UTXOs from this address.
        let mut inputs_total: u64 = 0;
        let mut selected_utxos: Vec<(OutPoint, TxOut)> = Vec::new();
        for (outpoint, txout) in state.utxo.iter() {
            if txout.recipient_hash == from_hash {
                selected_utxos.push((*outpoint, *txout));
                inputs_total = inputs_total.saturating_add(txout.amount.to_atomic());
                if inputs_total >= amount_atoms {
                    break;
                }
            }
        }

        if inputs_total < amount_atoms {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -2,
                "insufficient balance after UTXO selection",
                None::<()>,
            ));
        }

        // Build transaction.
        let mut outputs = vec![TxOut {
            amount: Amount::from_atomic(amount_atoms),
            recipient_hash: to_recipient_hash,
        }];
        // Change back to sender.
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

        // Mine the anti-spam proof of work (protocol §6.7).
        bitaiir_chain::mine_tx_pow(&mut tx);

        // Validate the transaction against the UTXO set.
        let current_height = state.chain.height();
        if let Err(e) = validate_transaction(&tx, &state.utxo, current_height) {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -4,
                format!("transaction validation failed: {e}"),
                None::<()>,
            ));
        }

        let txid = tx.txid();

        // Broadcast tx to all connected peers before adding to local mempool.
        let tx_bytes = bitaiir_types::encoding::to_bytes(&tx).expect("Transaction always encodes");
        for sender in &state.peer_senders {
            let _ = sender.try_send(bitaiir_net::NetMessage::TxData(tx_bytes.clone()));
        }
        let peers_notified = state.peer_senders.len();

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
        let addresses = state.wallet.addresses();
        let mut result = Vec::new();
        for addr in &addresses {
            let balance = Wallet::balance_of(addr, &state.utxo);
            result.push(serde_json::json!({
                "address": addr,
                "balance": format!("{}", Amount::from_atomic(balance)),
                "balance_atomic": balance,
            }));
        }
        Ok(serde_json::json!({
            "addresses": result,
            "total": addresses.len(),
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

        // Register this peer's sender channel in the shared state.
        {
            let mut state = self.state.write().await;
            state.peer_senders.push(tx_send);
        }

        let gossip_state = self.state.clone();
        let gossip_storage: Option<Arc<Storage>> = Some(self.storage.clone());
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

    async fn stop(&self) -> RpcResult<String> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok("BitAiir daemon stopping...".to_string())
    }
}
