//! Compact block relay — BIP 152–style short IDs.
//!
//! When a miner broadcasts a newly-mined block to its peers, most of
//! them already have the non-coinbase transactions in their mempool
//! — they only need to know *which* txs are in the block and in what
//! order. Compact blocks exploit this by sending:
//!
//!   - the block **header** (80 bytes),
//!   - a random per-block **nonce salt** (8 bytes),
//!   - a list of 6-byte **short IDs** (one per non-prefilled tx),
//!   - a list of **prefilled transactions** (always at least the
//!     coinbase, which the receiver cannot possibly have in mempool).
//!
//! Receivers compute the short ID of every tx in their mempool using
//! the same salted SipHash key. Matching short IDs fill the block
//! slots; any slot that stays empty is requested via `GetBlockTxn`.
//!
//! On a warm mempool this cuts new-block traffic from ~1 MB down to
//! tens of KiB — a 50–100x bandwidth saving on the block-relay path.

use bitaiir_types::{BlockHeader, Hash256, Transaction, encoding};
use sha2::{Digest, Sha256};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// Length of a compact-block short ID in bytes.
pub const SHORT_ID_LEN: usize = 6;

/// A 6-byte short transaction ID, the low-order bytes of a SipHash
/// keyed by the compact block's nonce salt and header hash.
pub type ShortId = [u8; SHORT_ID_LEN];

/// Derive the 16-byte SipHash key for a compact block from its
/// header and a per-block nonce salt. BIP 152 concatenates
/// `sha256(header || nonce)` and takes the first 16 bytes; we do
/// the same.
///
/// Using a per-block salt means the short-ID collision resistance
/// doesn't degrade across blocks: even if an attacker could pre-mine
/// tx collisions for one block, the next block has a fresh key.
pub fn derive_sip_key(header: &BlockHeader, nonce_salt: u64) -> [u8; 16] {
    let header_bytes = encoding::to_bytes(header).expect("header encodes");
    let mut hasher = Sha256::new();
    hasher.update(&header_bytes);
    hasher.update(nonce_salt.to_le_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// Compute the 6-byte short ID of a transaction under the given
/// SipHash key. The 8-byte SipHash-2-4 output is truncated to its
/// low 6 bytes (little-endian).
pub fn short_id_for(txid: &Hash256, sip_key: &[u8; 16]) -> ShortId {
    // SipHasher24 takes two u64 halves of the key.
    let k0 = u64::from_le_bytes(sip_key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(sip_key[8..16].try_into().unwrap());
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(txid.as_bytes());
    let full = hasher.finish().to_le_bytes();
    let mut out = [0u8; SHORT_ID_LEN];
    out.copy_from_slice(&full[..SHORT_ID_LEN]);
    out
}

/// A compact representation of a block suitable for relay.
///
/// `prefilled` always contains at least the coinbase (absolute
/// index 0) — the receiver cannot reconstruct it from its mempool.
/// `short_ids` holds one entry per non-prefilled transaction, in the
/// same relative order as they appear in the block.
#[derive(Debug, Clone)]
pub struct CompactBlockMsg {
    pub header: BlockHeader,
    /// Random per-block salt used to key the SipHash function.
    pub nonce_salt: u64,
    /// Short IDs for transactions NOT present in `prefilled`.
    pub short_ids: Vec<ShortId>,
    /// `(absolute_index, transaction)` pairs that the receiver almost
    /// certainly does not have in its mempool — always includes the
    /// coinbase at index 0.
    pub prefilled: Vec<(u16, Transaction)>,
}

/// A peer's request for missing transactions after reconstructing a
/// compact block: the block hash it refers to and the absolute
/// indexes of the slots it could not fill from its mempool.
#[derive(Debug, Clone)]
pub struct GetBlockTxnMsg {
    pub block_hash: Hash256,
    pub indexes: Vec<u16>,
}

/// The sender's reply to `GetBlockTxn`: the requested transactions
/// in the same order as the requested indexes.
#[derive(Debug, Clone)]
pub struct BlockTxnMsg {
    pub block_hash: Hash256,
    pub txs: Vec<Transaction>,
}
