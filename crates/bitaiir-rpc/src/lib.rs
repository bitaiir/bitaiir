//! JSON-RPC interface to a running BitAiir node.
//!
//! This crate defines the RPC methods that `bitaiir-cli` (and any
//! third-party tooling) can call on a running daemon. The server
//! implementation lives here too — it holds a reference to the shared
//! node state and translates RPC calls into reads/writes on the
//! chain, UTXO set, and mempool.
//!
//! Phase C2 ships two methods:
//!
//! - `getblockchaininfo` — read-only summary of the chain state.
//! - `stop` — graceful shutdown of the daemon.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitaiir_chain::{Chain, UtxoSet, subsidy};
use jsonrpsee::core::RpcResult;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use serde::Serialize;
use tokio::sync::RwLock;

/// The shared mutable state every RPC handler reads or writes.
pub struct NodeState {
    pub chain: Chain,
    pub utxo: UtxoSet,
}

/// Thread-safe handle to the node state, cloneable across async tasks.
pub type SharedState = Arc<RwLock<NodeState>>;

/// RPC method definitions. The `#[rpc(server)]` attribute generates a
/// `BitaiirApiServer` trait that the daemon must implement and register
/// with the jsonrpsee server.
#[rpc(server)]
pub trait BitaiirApi {
    /// Return a summary of the current blockchain state.
    #[method(name = "getblockchaininfo")]
    async fn get_blockchain_info(&self) -> RpcResult<BlockchainInfo>;

    /// Return block information at a given height.
    #[method(name = "getblock")]
    async fn get_block(&self, height: u64) -> RpcResult<serde_json::Value>;

    /// Gracefully shut down the daemon.
    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;
}

/// Response payload for `getblockchaininfo`.
#[derive(Debug, Clone, Serialize)]
pub struct BlockchainInfo {
    pub height: u64,
    pub tip: String,
    pub blocks: usize,
    pub utxos: usize,
    pub subsidy: String,
}

/// The server-side implementation of [`BitaiirApi`].
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
                            format!("{}", bitaiir_types::Amount::from_atomic(total))
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

    async fn stop(&self) -> RpcResult<String> {
        self.shutdown.store(true, Ordering::Relaxed);
        Ok("BitAiir daemon stopping...".to_string())
    }
}
