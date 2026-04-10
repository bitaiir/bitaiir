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

        // Validate the transaction against the UTXO set.
        if let Err(e) = validate_transaction(&tx, &state.utxo) {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned(
                -4,
                format!("transaction validation failed: {e}"),
                None::<()>,
            ));
        }

        let txid = tx.txid();
        state.mempool.add(tx);

        Ok(serde_json::json!({
            "txid": txid.to_string(),
            "from": from_address,
            "to": to_address,
            "amount": format!("{}", Amount::from_atomic(amount_atoms)),
            "change": format!("{}", Amount::from_atomic(change)),
            "status": "added to mempool",
        }))
    }

    async fn get_mempool_info(&self) -> RpcResult<serde_json::Value> {
        let state = self.state.read().await;
        Ok(serde_json::json!({
            "size": state.mempool.len(),
        }))
    }

    async fn stop(&self) -> RpcResult<String> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok("BitAiir daemon stopping...".to_string())
    }
}
