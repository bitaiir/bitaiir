//! Block headers and full blocks.
//!
//! A [`BlockHeader`] contains everything a proof-of-work miner needs to
//! grind: the link to the previous block, a commitment to the block's
//! transactions (the merkle root), a timestamp, a compact difficulty
//! target, and a nonce to vary. A [`Block`] is a header plus its
//! transactions.
//!
//! The header layout matches Bitcoin's general shape, with one change:
//! `timestamp` is a `u64` seconds-since-epoch value instead of Bitcoin's
//! `u32`. The `u32` runs out in 2106; a `u64` is effectively forever.

use bitaiir_crypto::hash::double_sha256;
use serde::{Deserialize, Serialize};

use crate::encoding;
use crate::hash::Hash256;
use crate::merkle::merkle_root;
use crate::transaction::Transaction;

/// The fixed-size header that a miner grinds and that peers use to track
/// the chain tip. `BlockHeader` is `Copy` because it contains no heap
/// allocations: every field is a scalar or a fixed-size hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block format version.
    pub version: u32,
    /// Hash of the previous block's header, linking this block into the
    /// chain.
    pub prev_block_hash: Hash256,
    /// Merkle root of the block's transaction IDs.
    pub merkle_root: Hash256,
    /// Unix timestamp in seconds, when this block was produced.
    pub timestamp: u64,
    /// Compact encoding of the proof-of-work difficulty target.
    pub bits: u32,
    /// Nonce varied by the miner to find a hash below `bits`.
    pub nonce: u32,
}

impl BlockHeader {
    /// Compute the block hash: `double_sha256` of the canonical encoding
    /// of the header.
    pub fn block_hash(&self) -> Hash256 {
        // As with Transaction::txid, encoding a `BlockHeader` can never
        // fail: every field is a fixed-size scalar.
        let bytes = encoding::to_bytes(self).expect("BlockHeader always encodes");
        Hash256::from_bytes(double_sha256(&bytes))
    }
}

/// A complete block: its header plus the list of transactions it commits
/// to. The first transaction in `transactions` is the coinbase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Return the block's hash, delegating to the header.
    pub fn block_hash(&self) -> Hash256 {
        self.header.block_hash()
    }

    /// Recompute the merkle root from the current list of transactions.
    /// A block is internally consistent when this equals
    /// `self.header.merkle_root`.
    pub fn compute_merkle_root(&self) -> Hash256 {
        let txids: Vec<Hash256> = self.transactions.iter().map(Transaction::txid).collect();
        merkle_root(&txids)
    }
}
