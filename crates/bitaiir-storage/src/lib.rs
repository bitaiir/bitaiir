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
