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
//! - `wallet_keys`:    address string         → privkey (32) + pubkey (33)
//! - `metadata`:       key string             → value bytes

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::Path;

use bitaiir_crypto::key::{PrivateKey, PublicKey};
use bitaiir_types::{Block, Hash256, OutPoint, TxOut, encoding};
use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;

// --- Table definitions --------------------------------------------------- //

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEIGHT_TO_HASH: TableDefinition<u64, &[u8]> = TableDefinition::new("height_to_hash");
const UTXOS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
const WALLET_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("wallet_keys");
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

    /// Persist a block and update the chain tip + UTXO set atomically.
    ///
    /// `spent_outpoints` is the list of outpoints consumed by the
    /// block's non-coinbase transactions. These are removed from the
    /// UTXO table while the block's new outputs are added.
    pub fn apply_block(
        &self,
        height: u64,
        block: &Block,
        spent_outpoints: &[OutPoint],
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let block_bytes = encoding::to_bytes(block).map_err(|e| Error::Encoding(e.to_string()))?;

        let write = self.db.begin_write()?;
        {
            // Store block by hash.
            let mut blocks = write.open_table(BLOCKS)?;
            blocks.insert(block_hash.as_bytes().as_slice(), block_bytes.as_slice())?;

            // Store height → hash mapping.
            let mut heights = write.open_table(HEIGHT_TO_HASH)?;
            heights.insert(height, block_hash.as_bytes().as_slice())?;

            // Remove spent UTXOs.
            let mut utxos = write.open_table(UTXOS)?;
            for outpoint in spent_outpoints {
                let key =
                    encoding::to_bytes(outpoint).map_err(|e| Error::Encoding(e.to_string()))?;
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

    /// Save a wallet keypair.
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
}
