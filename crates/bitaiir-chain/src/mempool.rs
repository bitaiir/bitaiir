//! In-memory mempool: pending transactions waiting to be mined.
//!
//! Transactions enter the mempool when they are broadcast by a peer
//! (or crafted locally by a wallet) and leave it when a miner
//! includes them in a block. Phase 1b provides just the container
//! and basic operations; transaction validation, fee-based ordering,
//! expiry, and eviction policies will all come in later phases.
//!
//! Keys are transaction IDs. The mempool is a simple
//! `HashMap<Hash256, Transaction>`, which gives O(1) lookup, add,
//! and removal with no guarantees on iteration order.

use std::collections::HashMap;

use bitaiir_types::{Hash256, Transaction};

/// A pool of pending, not-yet-mined transactions.
pub struct Mempool {
    transactions: HashMap<Hash256, Transaction>,
}

impl Mempool {
    /// Build an empty mempool.
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the pool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Whether a transaction with this txid is in the pool.
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.transactions.contains_key(txid)
    }

    /// Look up a transaction by its txid.
    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    /// Add a transaction. Returns the transaction's txid.
    ///
    /// If a transaction with the same txid is already in the pool,
    /// this overwrites it and returns the new txid. The caller is
    /// responsible for any deduplication or validation semantics —
    /// the mempool itself imposes none in Phase 1b.
    pub fn add(&mut self, tx: Transaction) -> Hash256 {
        let txid = tx.txid();
        self.transactions.insert(txid, tx);
        txid
    }

    /// Remove a transaction by its txid, returning it if present.
    pub fn remove(&mut self, txid: &Hash256) -> Option<Transaction> {
        self.transactions.remove(txid)
    }

    /// Iterate over every `(txid, transaction)` pair in the pool.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash256, &Transaction)> {
        self.transactions.iter()
    }

    /// Drain up to `max_count` transactions from the pool. The
    /// transactions are returned in an unspecified order; fee-based
    /// priority will land in a later phase.
    ///
    /// This is the operation a miner calls when assembling a block:
    /// it removes the selected transactions from the pool so they
    /// do not get mined into a second block after the first one is
    /// accepted.
    pub fn take_for_block(&mut self, max_count: usize) -> Vec<Transaction> {
        // Collect the keys we want to pull so we can mutate the map
        // after the borrow ends.
        let keys: Vec<Hash256> = self.transactions.keys().take(max_count).copied().collect();
        keys.into_iter()
            .map(|k| {
                self.transactions
                    .remove(&k)
                    .expect("key came from the map a moment ago")
            })
            .collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

// Manual Debug: just the count, not every transaction.
impl core::fmt::Debug for Mempool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mempool")
            .field("len", &self.transactions.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{sample_coinbase, sample_normal_tx};
    use bitaiir_types::{Hash256, OutPoint};

    #[test]
    fn new_mempool_is_empty() {
        let pool = Mempool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn default_mempool_is_empty() {
        let pool = Mempool::default();
        assert!(pool.is_empty());
    }

    #[test]
    fn add_inserts_and_contains_reports_true() {
        let mut pool = Mempool::new();
        let tx = sample_normal_tx(
            OutPoint {
                txid: Hash256::from_bytes([0x01; 32]),
                vout: 0,
            },
            7,
        );
        let txid = pool.add(tx);

        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));
        assert!(pool.get(&txid).is_some());
    }

    #[test]
    fn add_same_txid_overwrites() {
        let mut pool = Mempool::new();
        let base = sample_normal_tx(
            OutPoint {
                txid: Hash256::from_bytes([0x01; 32]),
                vout: 0,
            },
            1,
        );
        let same = base.clone();

        let txid_first = pool.add(base);
        let txid_second = pool.add(same);
        assert_eq!(txid_first, txid_second);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn remove_returns_the_transaction_and_empties_the_pool() {
        let mut pool = Mempool::new();
        let tx = sample_coinbase(0);
        let txid = pool.add(tx);

        assert_eq!(pool.len(), 1);
        let removed = pool.remove(&txid).unwrap();
        assert_eq!(removed.txid(), txid);
        assert!(pool.is_empty());
        assert!(pool.remove(&txid).is_none());
    }

    #[test]
    fn iter_visits_every_transaction() {
        let mut pool = Mempool::new();
        let txs: Vec<_> = (0..5)
            .map(|i| {
                sample_normal_tx(
                    OutPoint {
                        txid: Hash256::from_bytes([i as u8; 32]),
                        vout: i,
                    },
                    i as u64,
                )
            })
            .collect();
        for tx in &txs {
            pool.add(tx.clone());
        }

        let mut visited = 0;
        for (txid, tx) in pool.iter() {
            assert_eq!(&tx.txid(), txid);
            visited += 1;
        }
        assert_eq!(visited, txs.len());
    }

    #[test]
    fn take_for_block_respects_limit_and_drains_the_pool() {
        let mut pool = Mempool::new();
        for i in 0..10u32 {
            pool.add(sample_normal_tx(
                OutPoint {
                    txid: Hash256::from_bytes([i as u8; 32]),
                    vout: i,
                },
                i as u64,
            ));
        }
        assert_eq!(pool.len(), 10);

        let batch = pool.take_for_block(4);
        assert_eq!(batch.len(), 4);
        assert_eq!(pool.len(), 6);

        // Transactions pulled into the batch are gone from the pool.
        for tx in &batch {
            assert!(!pool.contains(&tx.txid()));
        }
    }

    #[test]
    fn take_for_block_with_huge_limit_drains_everything() {
        let mut pool = Mempool::new();
        for i in 0..3u32 {
            pool.add(sample_normal_tx(
                OutPoint {
                    txid: Hash256::from_bytes([i as u8; 32]),
                    vout: i,
                },
                i as u64,
            ));
        }

        let batch = pool.take_for_block(1_000_000);
        assert_eq!(batch.len(), 3);
        assert!(pool.is_empty());
    }
}
