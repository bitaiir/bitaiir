//! Persistent storage for BitAiir using redb.
//!
//! This crate wraps `redb` (a pure-Rust ACID key-value store) and
//! provides typed methods for persisting blocks, the UTXO set, the
//! chain tip, and wallet keys. The daemon uses this so the chain
//! survives restarts.
//!
//! Data directory layout:
//! ```text
//! bitaiir_data/
//!   chain.redb    — all tables live in this single file
//! ```
//!
//! Tables:
//! - `blocks`:         block_hash (32 bytes) → serialized Block
//! - `height_to_hash`: height (u64 BE)       → block_hash (32 bytes)
//! - `utxos`:          serialized OutPoint    → serialized TxOut
//! - `block_undo`:     block_hash (32 bytes)  → serialized BlockUndo
//! - `wallet_keys`:    address string         → privkey (32) + pubkey (33)
//! - `metadata`:       key string             → value bytes

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::Path;

use bitaiir_chain::BlockUndo;
use bitaiir_crypto::key::{PrivateKey, PublicKey};
use bitaiir_types::{Block, Hash256, OutPoint, TxOut, encoding};
use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;

// --- Table definitions --------------------------------------------------- //

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEIGHT_TO_HASH: TableDefinition<u64, &[u8]> = TableDefinition::new("height_to_hash");
const UTXOS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
const BLOCK_UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("block_undo");
const WALLET_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_keys");
const KNOWN_PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("known_peers");
const METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");

// --- Errors -------------------------------------------------------------- //

#[derive(Debug, Error)]
pub enum Error {
    #[error("redb error: {0}")]
    Redb(#[from] redb::Error),

    #[error("redb storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("redb transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("redb table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("redb commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("redb database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("invalid stored data: {0}")]
    InvalidData(String),
}

pub type Result<T> = core::result::Result<T, Error>;

// --- Storage ------------------------------------------------------------- //

/// Persistent storage backed by a single redb database file.
pub struct Storage {
    db: Database,
}

impl Storage {
    /// Open (or create) the database at the given directory path.
    /// Creates `<dir>/chain.redb` if it doesn't exist.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::InvalidData(e.to_string()))?;
        let db_path = dir.join("chain.redb");
        let db = Database::create(db_path)?;
        Ok(Self { db })
    }

    // --- Generic metadata ------------------------------------------------ //

    /// Read a metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read = self.db.begin_read()?;
        let table = match read.open_table(METADATA) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Write a metadata value by key.
    pub fn set_metadata(&self, key: &str, value: &[u8]) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(METADATA)?;
            table.insert(key, value)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Whether the database already has a stored chain (at least one block).
    pub fn has_chain(&self) -> Result<bool> {
        let read = self.db.begin_read()?;
        match read.open_table(METADATA) {
            Ok(table) => Ok(table.get("tip_height")?.is_some()),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    // --- Block storage --------------------------------------------------- //

    /// Persist a block, its undo record, and the resulting UTXO + tip
    /// updates — all in a single atomic redb transaction.
    ///
    /// The `undo` record is produced by
    /// [`bitaiir_chain::UtxoSet::apply_block_with_undo`] and is
    /// persisted so a future reorg can reverse the block without
    /// replaying the chain.  Callers MUST pass an `undo` whose
    /// `block_hash` matches `block.block_hash()` — this invariant
    /// isn't re-checked here (caller already built it from the same
    /// block it's now persisting).
    pub fn apply_block(&self, height: u64, block: &Block, undo: &BlockUndo) -> Result<()> {
        let block_hash = block.block_hash();
        let block_bytes = encoding::to_bytes(block).map_err(|e| Error::Encoding(e.to_string()))?;
        let undo_bytes = encoding::to_bytes(undo).map_err(|e| Error::Encoding(e.to_string()))?;

        let write = self.db.begin_write()?;
        {
            // Store block by hash.
            let mut blocks = write.open_table(BLOCKS)?;
            blocks.insert(block_hash.as_bytes().as_slice(), block_bytes.as_slice())?;

            // Store height → hash mapping.
            let mut heights = write.open_table(HEIGHT_TO_HASH)?;
            heights.insert(height, block_hash.as_bytes().as_slice())?;

            // Store the undo record under the block hash.
            let mut undo_table = write.open_table(BLOCK_UNDO)?;
            undo_table.insert(block_hash.as_bytes().as_slice(), undo_bytes.as_slice())?;

            // Remove spent UTXOs (derived from the undo record).
            let mut utxos = write.open_table(UTXOS)?;
            for spent in &undo.spent_inputs {
                let key = encoding::to_bytes(&spent.outpoint)
                    .map_err(|e| Error::Encoding(e.to_string()))?;
                utxos.remove(key.as_slice())?;
            }

            // Add new UTXOs from every transaction in the block.
            for tx in &block.transactions {
                let txid = tx.txid();
                for (vout, txout) in tx.outputs.iter().enumerate() {
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let key = encoding::to_bytes(&outpoint)
                        .map_err(|e| Error::Encoding(e.to_string()))?;
                    let value =
                        encoding::to_bytes(txout).map_err(|e| Error::Encoding(e.to_string()))?;
                    utxos.insert(key.as_slice(), value.as_slice())?;
                }
            }

            // Update chain tip.
            let mut meta = write.open_table(METADATA)?;
            meta.insert("tip_height", &height.to_be_bytes() as &[u8])?;
            meta.insert("tip_hash", block_hash.as_bytes().as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Persist a **reorg** — undo a set of old-chain blocks and apply
    /// a set of new-chain blocks — entirely inside a single redb
    /// write transaction, so disk state is either fully pre-reorg
    /// (if any step fails and the transaction is dropped before
    /// `commit`) or fully post-reorg (if `commit` succeeds).  No
    /// partial-reorg state is ever observable on disk.
    ///
    /// Parameters:
    ///
    /// - `old_tip_height`, `new_tip_height`, `new_tip_hash`:
    ///   pre- and post-reorg chain tips.  If `new_tip_height <
    ///   old_tip_height` the leftover `height_to_hash` entries
    ///   for the abandoned tail of the old chain are cleaned up,
    ///   so `load_block_at` never returns a block that isn't on
    ///   the current main chain.
    /// - `undone`: the old-chain blocks being rolled back, paired
    ///   with their undo records, in **tip-first** order (matches
    ///   [`bitaiir_chain::AcceptOutcome::Reorg::undone`]).
    /// - `applied`: the new-chain blocks being applied, in
    ///   **oldest-first** order, each with its target height and
    ///   freshly-computed undo record.
    ///
    /// Caller is expected to have validated every applied block
    /// against the post-undo state in memory before handing its
    /// undo record here — this method does no consensus checks,
    /// it only moves bytes around on disk.
    pub fn apply_reorg(
        &self,
        old_tip_height: u64,
        new_tip_height: u64,
        new_tip_hash: Hash256,
        undone: &[(Block, BlockUndo)],
        applied: &[(u64, Block, BlockUndo)],
    ) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut blocks = write.open_table(BLOCKS)?;
            let mut heights = write.open_table(HEIGHT_TO_HASH)?;
            let mut undo_table = write.open_table(BLOCK_UNDO)?;
            let mut utxos = write.open_table(UTXOS)?;
            let mut meta = write.open_table(METADATA)?;

            // --- Undo: reverse each old block's UTXO effect ------------- //
            for (block, undo) in undone {
                // Remove each output the block created.
                for tx in &block.transactions {
                    let txid = tx.txid();
                    for vout in 0..tx.outputs.len() {
                        let outpoint = OutPoint {
                            txid,
                            vout: vout as u32,
                        };
                        let key = encoding::to_bytes(&outpoint)
                            .map_err(|e| Error::Encoding(e.to_string()))?;
                        utxos.remove(key.as_slice())?;
                    }
                }
                // Restore each input the block consumed.  The stored
                // block and undo record themselves are kept under
                // their hash keys so the block is still retrievable
                // as side-chain data.
                for spent in &undo.spent_inputs {
                    let key = encoding::to_bytes(&spent.outpoint)
                        .map_err(|e| Error::Encoding(e.to_string()))?;
                    let value = encoding::to_bytes(&spent.txout)
                        .map_err(|e| Error::Encoding(e.to_string()))?;
                    utxos.insert(key.as_slice(), value.as_slice())?;
                }
            }

            // --- Apply: write each new block's forward effect ----------- //
            for (height, block, undo) in applied {
                let block_hash = block.block_hash();
                let block_bytes =
                    encoding::to_bytes(block).map_err(|e| Error::Encoding(e.to_string()))?;
                let undo_bytes =
                    encoding::to_bytes(undo).map_err(|e| Error::Encoding(e.to_string()))?;

                blocks.insert(block_hash.as_bytes().as_slice(), block_bytes.as_slice())?;
                heights.insert(*height, block_hash.as_bytes().as_slice())?;
                undo_table.insert(block_hash.as_bytes().as_slice(), undo_bytes.as_slice())?;

                for spent in &undo.spent_inputs {
                    let key = encoding::to_bytes(&spent.outpoint)
                        .map_err(|e| Error::Encoding(e.to_string()))?;
                    utxos.remove(key.as_slice())?;
                }
                for tx in &block.transactions {
                    let txid = tx.txid();
                    for (vout, txout) in tx.outputs.iter().enumerate() {
                        let outpoint = OutPoint {
                            txid,
                            vout: vout as u32,
                        };
                        let key = encoding::to_bytes(&outpoint)
                            .map_err(|e| Error::Encoding(e.to_string()))?;
                        let value = encoding::to_bytes(txout)
                            .map_err(|e| Error::Encoding(e.to_string()))?;
                        utxos.insert(key.as_slice(), value.as_slice())?;
                    }
                }
            }

            // --- Trim orphaned height_to_hash entries ------------------- //
            //
            // If the new chain is shorter (possible when a single
            // very-hard block overtakes many easy ones), the height
            // slots between `new_tip_height + 1` and `old_tip_height`
            // still point at abandoned-chain blocks.  `load_block_at`
            // would otherwise return side-chain blocks as if they
            // were on the main chain.
            if new_tip_height < old_tip_height {
                for h in (new_tip_height + 1)..=old_tip_height {
                    heights.remove(h)?;
                }
            }

            // --- Update chain tip --------------------------------------- //
            meta.insert("tip_height", &new_tip_height.to_be_bytes() as &[u8])?;
            meta.insert("tip_hash", new_tip_hash.as_bytes().as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Load the undo record for a block, if one was persisted.
    ///
    /// Databases created before the `block_undo` table existed will
    /// return `None` for their old blocks — the table is created on
    /// first write, and old blocks never got an undo record.  A reorg
    /// that tries to rewind past such a block will fail fast, which
    /// is the right behaviour: deeper than N blocks we never stored
    /// undo for, rewinding is not supported.
    pub fn load_block_undo(&self, block_hash: &Hash256) -> Result<Option<BlockUndo>> {
        let read = self.db.begin_read()?;
        let table = match read.open_table(BLOCK_UNDO) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(bytes) = table.get(block_hash.as_bytes().as_slice())? else {
            return Ok(None);
        };
        let undo: BlockUndo =
            encoding::from_bytes(bytes.value()).map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(Some(undo))
    }

    // --- Chain loading --------------------------------------------------- //

    /// Load the stored chain tip (height, hash).
    pub fn load_chain_tip(&self) -> Result<Option<(u64, Hash256)>> {
        let read = self.db.begin_read()?;
        let meta = match read.open_table(METADATA) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let height_bytes = match meta.get("tip_height")? {
            Some(v) => v,
            None => return Ok(None),
        };
        let height = u64::from_be_bytes(
            height_bytes
                .value()
                .try_into()
                .map_err(|_| Error::InvalidData("tip_height is not 8 bytes".into()))?,
        );

        let hash_bytes = meta
            .get("tip_hash")?
            .ok_or_else(|| Error::InvalidData("tip_hash missing".into()))?;
        let hash: [u8; 32] = hash_bytes
            .value()
            .try_into()
            .map_err(|_| Error::InvalidData("tip_hash is not 32 bytes".into()))?;

        Ok(Some((height, Hash256::from_bytes(hash))))
    }

    /// Load a block by height.
    pub fn load_block_at(&self, height: u64) -> Result<Option<Block>> {
        let read = self.db.begin_read()?;
        let heights = match read.open_table(HEIGHT_TO_HASH) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let hash_bytes = match heights.get(height)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };

        let blocks = read.open_table(BLOCKS)?;
        let block_bytes = match blocks.get(hash_bytes.as_slice())? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };

        let block: Block =
            encoding::from_bytes(&block_bytes).map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(Some(block))
    }

    /// Load all UTXOs into a HashMap for rebuilding the in-memory UtxoSet.
    pub fn load_all_utxos(&self) -> Result<HashMap<OutPoint, TxOut>> {
        let read = self.db.begin_read()?;
        let utxos = match read.open_table(UTXOS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(HashMap::new()),
            Err(e) => return Err(e.into()),
        };

        let mut map = HashMap::new();
        for entry in utxos.iter()? {
            let (key, value) = entry?;
            let outpoint: OutPoint =
                encoding::from_bytes(key.value()).map_err(|e| Error::Encoding(e.to_string()))?;
            let txout: TxOut =
                encoding::from_bytes(value.value()).map_err(|e| Error::Encoding(e.to_string()))?;
            map.insert(outpoint, txout);
        }
        Ok(map)
    }

    // --- Wallet ---------------------------------------------------------- //

    /// Save a wallet keypair (plaintext format).
    pub fn save_wallet_key(
        &self,
        address: &str,
        privkey: &PrivateKey,
        pubkey: &PublicKey,
    ) -> Result<()> {
        let mut value = Vec::with_capacity(65);
        value.extend_from_slice(&privkey.to_bytes());
        value.extend_from_slice(&pubkey.to_compressed());

        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(WALLET_KEYS)?;
            table.insert(address, value.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Save a wallet key entry as raw bytes (for encrypted storage).
    pub fn save_wallet_key_raw(&self, address: &str, value: &[u8]) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(WALLET_KEYS)?;
            table.insert(address, value)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Load all wallet key entries as raw bytes (for encrypted wallets).
    pub fn load_wallet_keys_raw(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let read = self.db.begin_read()?;
        let table = match read.open_table(WALLET_KEYS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            result.push((key.value().to_string(), value.value().to_vec()));
        }
        Ok(result)
    }

    /// Load all wallet keypairs.
    pub fn load_wallet_keys(&self) -> Result<HashMap<String, (PrivateKey, PublicKey)>> {
        let read = self.db.begin_read()?;
        let table = match read.open_table(WALLET_KEYS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(HashMap::new()),
            Err(e) => return Err(e.into()),
        };

        let mut map = HashMap::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let address = key.value().to_string();
            let bytes = value.value();
            if bytes.len() != 65 {
                continue; // skip corrupted entries
            }
            let privkey_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
            let pubkey_bytes = &bytes[32..65];

            if let (Ok(privkey), Ok(pubkey)) = (
                PrivateKey::from_bytes(&privkey_bytes),
                PublicKey::from_slice(pubkey_bytes),
            ) {
                map.insert(address, (privkey, pubkey));
            }
        }
        Ok(map)
    }

    // --- Known peers storage --------------------------------------------- //

    /// Persist a known peer record.
    ///
    /// Record layout (21 bytes):
    /// `last_seen(8) + failures(4) + banned_until(8) + source(1)`
    pub fn save_known_peer(
        &self,
        addr: &str,
        last_seen: u64,
        failures: u32,
        banned_until: u64,
        source: u8,
    ) -> Result<()> {
        let mut value = Vec::with_capacity(21);
        value.extend_from_slice(&last_seen.to_le_bytes());
        value.extend_from_slice(&failures.to_le_bytes());
        value.extend_from_slice(&banned_until.to_le_bytes());
        value.push(source);

        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(KNOWN_PEERS)?;
            table.insert(addr, value.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Load all known peer records.
    ///
    /// Returns `(addr, last_seen, failures, banned_until, source)` tuples.
    #[allow(clippy::type_complexity)]
    pub fn load_known_peers(&self) -> Result<Vec<(String, u64, u32, u64, u8)>> {
        let read = self.db.begin_read()?;
        let table = match read.open_table(KNOWN_PEERS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut peers = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let addr = key.value().to_string();
            let bytes = value.value();
            if bytes.len() < 21 {
                continue;
            }
            let last_seen = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let failures = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            let banned_until = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
            let source = bytes[20];
            peers.push((addr, last_seen, failures, banned_until, source));
        }
        Ok(peers)
    }

    /// Remove a peer from the known peers table.
    pub fn remove_known_peer(&self, addr: &str) -> Result<()> {
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(KNOWN_PEERS)?;
            table.remove(addr)?;
        }
        write.commit()?;
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitaiir_chain::{SpentInput, UtxoSet};
    use bitaiir_types::{
        Amount, Block, BlockHeader, Hash256, Transaction, TxIn, TxOut, merkle_root,
    };

    /// Build a minimal coinbase tx whose output differs per `tag` so
    /// tests can produce distinct blocks without recomputing PoW.
    fn coinbase(tag: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint::NULL,
                signature: tag.to_le_bytes().to_vec(),
                pubkey: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                amount: Amount::from_atomic(100),
                recipient_hash: [tag as u8; 20],
            }],
            locktime: 0,
            pow_nonce: 0,
        }
    }

    /// Build a block with a single coinbase and a deterministic
    /// header.  We do NOT run PoW here — storage doesn't care about
    /// PoW; it just shuffles bytes.
    fn block(prev: Hash256, tag: u64) -> Block {
        let cb = coinbase(tag);
        let merkle = merkle_root(&[cb.txid()]);
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: merkle,
                timestamp: 0,
                bits: 0x2000_ffff,
                nonce: tag as u32,
            },
            transactions: vec![cb],
        }
    }

    /// Produce a paired (Block, BlockUndo) applied to a fresh utxo
    /// set at the given height — exactly what a real caller would
    /// feed to `apply_block` / `apply_reorg`.
    fn block_with_undo(prev: Hash256, tag: u64, height: u64) -> (Block, bitaiir_chain::BlockUndo) {
        let b = block(prev, tag);
        let mut utxo = UtxoSet::new();
        let undo = utxo
            .apply_block_with_undo(&b, height)
            .expect("coinbase-only block applies");
        (b, undo)
    }

    fn open_storage(dir: &tempfile::TempDir) -> Storage {
        Storage::open(dir.path()).expect("open storage")
    }

    #[test]
    fn apply_reorg_round_trips_a_simple_swap() {
        // Scenario: storage has chain [genesis -> A1 -> A2].  Reorg
        // it to [genesis -> B1 -> B2].  After the reorg, B2 is the
        // tip and A1/A2's UTXOs are gone.
        let tmp = tempfile::tempdir().unwrap();
        let storage = open_storage(&tmp);

        let genesis_hash = Hash256::ZERO;
        let (a1, a1_undo) = block_with_undo(genesis_hash, 10, 1);
        let (a2, a2_undo) = block_with_undo(a1.block_hash(), 11, 2);
        storage.apply_block(1, &a1, &a1_undo).unwrap();
        storage.apply_block(2, &a2, &a2_undo).unwrap();

        assert_eq!(storage.load_chain_tip().unwrap().unwrap().0, 2);

        // Build the competing chain.
        let (b1, b1_undo) = block_with_undo(genesis_hash, 20, 1);
        let (b2, b2_undo) = block_with_undo(b1.block_hash(), 21, 2);

        storage
            .apply_reorg(
                2,                               // old tip height
                2,                               // new tip height
                b2.block_hash(),                 // new tip hash
                &[(a2, a2_undo), (a1, a1_undo)], // undone, tip-first
                &[(1, b1.clone(), b1_undo), (2, b2.clone(), b2_undo)],
            )
            .expect("reorg persists");

        // Tip moved to the new branch.
        let (new_h, new_tip) = storage.load_chain_tip().unwrap().unwrap();
        assert_eq!(new_h, 2);
        assert_eq!(new_tip, b2.block_hash());

        // height_to_hash for heights 1 and 2 now points at B's blocks.
        assert_eq!(
            storage.load_block_at(1).unwrap().unwrap().block_hash(),
            b1.block_hash(),
        );
        assert_eq!(
            storage.load_block_at(2).unwrap().unwrap().block_hash(),
            b2.block_hash(),
        );

        // Undo records for B's blocks are present.
        assert!(storage.load_block_undo(&b1.block_hash()).unwrap().is_some());
        assert!(storage.load_block_undo(&b2.block_hash()).unwrap().is_some());
    }

    #[test]
    fn apply_reorg_trims_orphaned_height_entries_when_new_chain_is_shorter() {
        // Scenario: old chain reached height 3; new chain reaches
        // only height 1 (but carries more work — in reality a
        // single super-hard block).  The height_to_hash entries at
        // heights 2 and 3 must be cleaned up so `load_block_at`
        // doesn't return abandoned-chain blocks.
        let tmp = tempfile::tempdir().unwrap();
        let storage = open_storage(&tmp);

        let genesis_hash = Hash256::ZERO;
        let (a1, a1_undo) = block_with_undo(genesis_hash, 10, 1);
        let (a2, a2_undo) = block_with_undo(a1.block_hash(), 11, 2);
        let (a3, a3_undo) = block_with_undo(a2.block_hash(), 12, 3);
        storage.apply_block(1, &a1, &a1_undo).unwrap();
        storage.apply_block(2, &a2, &a2_undo).unwrap();
        storage.apply_block(3, &a3, &a3_undo).unwrap();

        // Replace with a single block at height 1.
        let (b1, b1_undo) = block_with_undo(genesis_hash, 20, 1);
        storage
            .apply_reorg(
                3,
                1,
                b1.block_hash(),
                &[(a3, a3_undo), (a2, a2_undo), (a1, a1_undo)],
                &[(1, b1.clone(), b1_undo)],
            )
            .expect("shorter reorg persists");

        assert_eq!(
            storage.load_chain_tip().unwrap().unwrap(),
            (1, b1.block_hash())
        );
        // Heights 2 and 3 no longer map to anything on the main chain.
        assert!(storage.load_block_at(2).unwrap().is_none());
        assert!(storage.load_block_at(3).unwrap().is_none());
        // Height 1 points at the new branch.
        assert_eq!(
            storage.load_block_at(1).unwrap().unwrap().block_hash(),
            b1.block_hash(),
        );
    }

    #[test]
    fn apply_reorg_restores_spent_inputs_of_undone_blocks() {
        // Apply a block that consumes a pre-existing UTXO, then
        // undo it via apply_reorg with its undo record.  The
        // consumed UTXO must reappear in storage.
        let tmp = tempfile::tempdir().unwrap();
        let storage = open_storage(&tmp);

        // Seed a pre-existing UTXO directly — simulates the
        // genesis coinbase being spendable.
        let seed_op = OutPoint {
            txid: Hash256::from_bytes([0xaa; 32]),
            vout: 0,
        };
        let seed_txout = TxOut {
            amount: Amount::from_atomic(50),
            recipient_hash: [0xbb; 20],
        };
        // Insert directly via apply_block with a coinbase that
        // creates this outpoint: easier is to just write through
        // a hand-rolled transaction.
        let mut seed_utxo = UtxoSet::new();
        seed_utxo.insert(seed_op, seed_txout);
        // Build a block that "spends" this seed UTXO.
        let spender_tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: seed_op,
                signature: Vec::new(),
                pubkey: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                amount: Amount::from_atomic(50),
                recipient_hash: [0xcc; 20],
            }],
            locktime: 0,
            pow_nonce: 0,
        };
        let cb = coinbase(100);
        let merkle = merkle_root(&[cb.txid(), spender_tx.txid()]);
        let spending_block = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 0,
                bits: 0x2000_ffff,
                nonce: 100,
            },
            transactions: vec![cb.clone(), spender_tx.clone()],
        };

        // Hand-build the undo record for this block: one spent input.
        let undo = bitaiir_chain::BlockUndo {
            block_hash: spending_block.block_hash(),
            spent_inputs: vec![SpentInput {
                outpoint: seed_op,
                txout: seed_txout,
                created_at_height: 0,
                was_coinbase: false,
            }],
        };

        // Seed storage by writing the pre-existing UTXO then
        // persisting the spending block.  The spender_tx consumes
        // seed_op, leaving only cb's outputs + spender_tx's outputs.
        storage.apply_block(1, &spending_block, &undo).unwrap();

        // Confirm seed_op was removed by the initial apply.
        let utxos = storage.load_all_utxos().unwrap();
        assert!(!utxos.contains_key(&seed_op));

        // Now reorg it away — the spending block is undone and the
        // new chain is empty (hypothetically a rival block at the
        // same height; we simplify by passing no applied blocks,
        // but that's not a valid reorg input in production).  For
        // this test we only assert the undo branch of apply_reorg:
        // produce a replacement block at height 1 that spends
        // nothing, so the seed UTXO comes back.
        let (replacement, replacement_undo) = block_with_undo(Hash256::ZERO, 200, 1);

        storage
            .apply_reorg(
                1,
                1,
                replacement.block_hash(),
                &[(spending_block, undo)],
                &[(1, replacement.clone(), replacement_undo)],
            )
            .expect("reorg persists");

        // seed_op is back in the UTXO table.
        let utxos_after = storage.load_all_utxos().unwrap();
        assert!(utxos_after.contains_key(&seed_op));
        assert_eq!(utxos_after[&seed_op].amount.to_atomic(), 50);
    }
}
