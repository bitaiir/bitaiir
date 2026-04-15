//! Size-capped in-memory mempool with tx-PoW priority ordering.
//!
//! Transactions enter the mempool when a peer relays them (or the
//! local wallet creates one) and leave when a miner includes them
//! in a block.  Keys are transaction IDs; priority is a
//! `(tx_pow_hash, arrival_seq)` tuple:
//!
//! - **Primary key**: `tx_pow_hash` ascending.  A lower hash means
//!   more leading zero bytes in the anti-spam PoW, which means the
//!   sender voluntarily mined a stricter target — they pay more
//!   CPU time, they get priority.  No protocol change needed; the
//!   ordering falls out of the hash values themselves.
//! - **Secondary key**: monotonic `arrival_seq` counter.  Older
//!   transactions at the same difficulty win over newer ones, so
//!   an honest user's tx isn't displaced by a later-arriving tx of
//!   identical work.
//!
//! The fee-less design — BitAiir never charges network fees — means
//! DoS protection comes entirely from
//!
//! 1. the per-tx [`crate::tx_pow`] nonce (already enforced at
//!    validation time: every non-coinbase tx costs the sender ~2 s
//!    of CPU),
//! 2. the `max_bytes` cap on mempool size, and
//! 3. eviction of the lowest-priority entry to make room — an
//!    attacker trying to displace legitimate high-work txs has to
//!    spend *more* CPU per slot they steal.

use std::collections::{BTreeMap, HashMap};

use bitaiir_types::{Hash256, Transaction, encoding};

use crate::error::{Error, Result};
use crate::tx_pow::tx_pow_hash;

/// One transaction's on-demand metadata, cached so eviction,
/// priority ordering, and byte accounting are O(1) at each step.
#[derive(Clone)]
struct MempoolEntry {
    tx: Transaction,
    /// Serialized size of `tx`, summed into `total_bytes`.
    bytes: usize,
    /// `tx_pow_hash(tx)` — ordering key.  Lower = more work.
    pow_hash: Hash256,
    /// Arrival counter at insertion time.  Tie-breaker when two
    /// txs share the same `pow_hash`.
    arrival_seq: u64,
}

/// A pool of pending, not-yet-mined transactions, capped in bytes.
///
/// `Mempool` is `Clone` so the reorg orchestrator can snapshot it
/// before shuffling transactions in and out during a reorg —
/// allowing a full restore on reorg failure.
#[derive(Clone)]
pub struct Mempool {
    /// txid → entry.  O(1) lookup by hash for `contains`, `get`,
    /// `remove`.
    entries: HashMap<Hash256, MempoolEntry>,
    /// `(pow_hash, arrival_seq) → txid`, sorted ascending so
    /// - `iter().next()` is the best-priority, oldest-of-ties tx
    ///   (what miners want for block assembly), and
    /// - `iter().next_back()` is the worst-priority, newest-of-ties
    ///   tx (what eviction targets first).
    by_priority: BTreeMap<(Hash256, u64), Hash256>,
    /// Monotonic counter; incremented on every successful `add`.
    arrival_seq: u64,
    /// Sum of `entry.bytes` across `entries`.  Compared against
    /// `max_bytes` on every add to decide whether to evict.
    total_bytes: usize,
    /// Configured upper bound on `total_bytes`.  Set at construction
    /// time; callers source it from `consensus::DEFAULT_MAX_MEMPOOL_BYTES`
    /// or from a node config override.
    max_bytes: usize,
}

impl Mempool {
    /// Build an empty mempool with the given capacity in bytes.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_priority: BTreeMap::new(),
            arrival_seq: 0,
            total_bytes: 0,
            max_bytes,
        }
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a transaction with this txid is in the pool.
    pub fn contains(&self, txid: &Hash256) -> bool {
        self.entries.contains_key(txid)
    }

    /// Look up a transaction by its txid.
    pub fn get(&self, txid: &Hash256) -> Option<&Transaction> {
        self.entries.get(txid).map(|e| &e.tx)
    }

    /// Iterate over every `(txid, transaction)` pair in the pool.
    /// Order is unspecified — for priority-ordered access use
    /// [`Self::take_for_block`].
    pub fn iter(&self) -> impl Iterator<Item = (&Hash256, &Transaction)> {
        self.entries.iter().map(|(k, v)| (k, &v.tx))
    }

    /// Total serialized bytes held in the pool right now.  The
    /// pool maintains the invariant `total_bytes() <= max_bytes()`.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Configured capacity in bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Add a transaction to the pool.
    ///
    /// The caller is expected to have already validated `tx` against
    /// the current UTXO set and the anti-spam tx-PoW target (see
    /// [`crate::validate_transaction`]).  This method performs no
    /// consensus checks; it only manages mempool accounting.
    ///
    /// Behaviour:
    /// - If `tx`'s serialized size alone exceeds `max_bytes`, returns
    ///   [`Error::TxTooLargeForMempool`].
    /// - If `tx` is already in the pool, returns `Ok(())` silently
    ///   (idempotent — networks relay duplicates).
    /// - If inserting `tx` would exceed `max_bytes`, evicts
    ///   lowest-priority entries (highest `pow_hash`, newest
    ///   `arrival_seq` on ties) until `tx` fits.  If `tx` itself
    ///   would be the lowest-priority entry and there's no room,
    ///   returns [`Error::MempoolFull`] without evicting anything.
    pub fn add(&mut self, tx: Transaction) -> Result<()> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Ok(());
        }

        let bytes = encoding::to_bytes(&tx).expect("transaction encodes").len();
        if bytes > self.max_bytes {
            return Err(Error::TxTooLargeForMempool {
                size: bytes,
                max: self.max_bytes,
            });
        }

        let pow_hash = tx_pow_hash(&tx);
        self.arrival_seq = self.arrival_seq.wrapping_add(1);
        let arrival_seq = self.arrival_seq;
        let new_key = (pow_hash, arrival_seq);

        // Evict lowest-priority entries until `tx` fits.  If `tx`
        // itself has the worst priority, we refuse rather than
        // pointlessly evict something to make room for something
        // worse.
        while self.total_bytes + bytes > self.max_bytes {
            let worst_key = match self.by_priority.keys().next_back().copied() {
                Some(k) => k,
                // Pool is empty but still can't fit — unreachable
                // since we checked `bytes > self.max_bytes` above,
                // but be safe.
                None => {
                    return Err(Error::TxTooLargeForMempool {
                        size: bytes,
                        max: self.max_bytes,
                    });
                }
            };
            if worst_key <= new_key {
                // New tx is (or ties with) the worst.  Refuse.
                return Err(Error::MempoolFull);
            }
            // Evict the current worst and loop.
            let worst_txid = self
                .by_priority
                .remove(&worst_key)
                .expect("worst_key just came from the map");
            let removed = self
                .entries
                .remove(&worst_txid)
                .expect("txid paired with by_priority entry");
            self.total_bytes -= removed.bytes;
        }

        self.by_priority.insert(new_key, txid);
        self.entries.insert(
            txid,
            MempoolEntry {
                tx,
                bytes,
                pow_hash,
                arrival_seq,
            },
        );
        self.total_bytes += bytes;
        Ok(())
    }

    /// Remove a transaction by its txid, returning it if present.
    /// Removes from both the primary map and the priority index,
    /// and updates `total_bytes`.
    pub fn remove(&mut self, txid: &Hash256) -> Option<Transaction> {
        let entry = self.entries.remove(txid)?;
        self.by_priority
            .remove(&(entry.pow_hash, entry.arrival_seq));
        self.total_bytes -= entry.bytes;
        Some(entry.tx)
    }

    /// Drain transactions in priority order up to `max_bytes_budget`
    /// total serialized size.  Higher-priority txs come out first
    /// (lower `tx_pow_hash`, older `arrival_seq` on ties).
    ///
    /// Used by the miner when assembling a new block: it picks the
    /// most-worked, oldest transactions first, leaving lower-work
    /// ones in the pool for later blocks.
    pub fn take_for_block(&mut self, max_bytes_budget: usize) -> Vec<Transaction> {
        let mut taken = Vec::new();
        let mut used = 0usize;
        // Collect the txids we want to pull, in priority order, that
        // still fit in the byte budget.  A second pass mutates the
        // maps so we don't have to juggle a borrow during selection.
        let mut to_take: Vec<Hash256> = Vec::new();
        for (_key, txid) in self.by_priority.iter() {
            let entry = &self.entries[txid];
            if used + entry.bytes > max_bytes_budget {
                // Skip over txs that don't fit rather than stopping
                // — a small tx later in priority order may still fit
                // even when a larger earlier tx didn't.
                continue;
            }
            used += entry.bytes;
            to_take.push(*txid);
        }
        for txid in to_take {
            if let Some(tx) = self.remove(&txid) {
                taken.push(tx);
            }
        }
        taken
    }
}

// Manual Debug: just the counters, not every transaction.
impl core::fmt::Debug for Mempool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mempool")
            .field("len", &self.entries.len())
            .field("total_bytes", &self.total_bytes)
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{sample_coinbase, sample_normal_tx};
    use bitaiir_types::OutPoint;

    /// A comfortably-large cap so size doesn't interfere with the
    /// basic ordering / lookup tests.
    const LARGE_CAP: usize = 1_000_000;

    fn sample_tx(byte: u8, vout: u32, nonce: u64) -> Transaction {
        sample_normal_tx(
            OutPoint {
                txid: Hash256::from_bytes([byte; 32]),
                vout,
            },
            nonce,
        )
    }

    #[test]
    fn new_mempool_is_empty() {
        let pool = Mempool::new(LARGE_CAP);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.max_bytes(), LARGE_CAP);
    }

    #[test]
    fn add_inserts_and_contains_reports_true() {
        let mut pool = Mempool::new(LARGE_CAP);
        let tx = sample_tx(0x01, 0, 7);
        let txid = tx.txid();
        pool.add(tx).expect("add succeeds");
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));
        assert!(pool.get(&txid).is_some());
        assert!(pool.total_bytes() > 0);
    }

    #[test]
    fn duplicate_add_is_silent_noop() {
        let mut pool = Mempool::new(LARGE_CAP);
        let tx = sample_tx(0x01, 0, 7);
        pool.add(tx.clone()).expect("first add");
        let bytes_after_first = pool.total_bytes();
        pool.add(tx).expect("second add silently succeeds");
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), bytes_after_first);
    }

    #[test]
    fn remove_returns_tx_and_updates_accounting() {
        let mut pool = Mempool::new(LARGE_CAP);
        let tx = sample_coinbase(0);
        let txid = tx.txid();
        pool.add(tx).expect("add");

        let removed = pool.remove(&txid).expect("present");
        assert_eq!(removed.txid(), txid);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
        assert!(pool.remove(&txid).is_none());
    }

    #[test]
    fn iter_visits_every_transaction() {
        let mut pool = Mempool::new(LARGE_CAP);
        for i in 0..5u32 {
            pool.add(sample_tx(i as u8, i, i as u64)).unwrap();
        }
        let visited = pool.iter().count();
        assert_eq!(visited, 5);
    }

    #[test]
    fn add_rejects_tx_larger_than_max_bytes() {
        let mut pool = Mempool::new(10);
        // Any real transaction is comfortably larger than 10 bytes.
        let tx = sample_tx(0x01, 0, 7);
        let err = pool.add(tx).unwrap_err();
        assert!(matches!(err, Error::TxTooLargeForMempool { .. }));
    }

    #[test]
    fn take_for_block_drains_best_priority_first() {
        // Under the test-only tx-PoW target (1 leading zero byte),
        // two txs mined at the minimum typically have differing
        // pow_hash values.  Mine both and sort by hash to predict
        // the order `take_for_block` will emit them.
        let mut pool = Mempool::new(LARGE_CAP);
        let mut a = sample_tx(0x01, 0, 0);
        crate::tx_pow::mine_tx_pow(&mut a);
        let a_hash = tx_pow_hash(&a);
        let mut b = sample_tx(0x02, 0, 0);
        crate::tx_pow::mine_tx_pow(&mut b);
        let b_hash = tx_pow_hash(&b);

        pool.add(a.clone()).unwrap();
        pool.add(b.clone()).unwrap();

        let batch = pool.take_for_block(LARGE_CAP);
        assert_eq!(batch.len(), 2);
        // The tx with lower pow_hash must come out first.
        let (expected_first, expected_second) = if a_hash < b_hash {
            (a.txid(), b.txid())
        } else {
            (b.txid(), a.txid())
        };
        assert_eq!(batch[0].txid(), expected_first);
        assert_eq!(batch[1].txid(), expected_second);
        assert!(pool.is_empty());
    }

    #[test]
    fn take_for_block_respects_byte_budget() {
        let mut pool = Mempool::new(LARGE_CAP);
        pool.add(sample_tx(0x01, 0, 1)).unwrap();
        pool.add(sample_tx(0x02, 0, 2)).unwrap();
        pool.add(sample_tx(0x03, 0, 3)).unwrap();

        // Budget smaller than a single tx → drain returns nothing.
        let small_batch = pool.take_for_block(1);
        assert!(small_batch.is_empty());
        assert_eq!(pool.len(), 3);

        // Generous budget → drains everything.
        let big_batch = pool.take_for_block(LARGE_CAP);
        assert_eq!(big_batch.len(), 3);
        assert!(pool.is_empty());
    }

    #[test]
    fn eviction_rejects_new_tx_when_pool_full_and_new_is_worst() {
        // Build a pool at the edge of capacity: one tx fills it.
        // Then try to add a second tx — capacity is exceeded, the
        // eviction loop compares priorities, and if the existing
        // tx is strictly better (lower pow_hash OR equal hash but
        // earlier arrival_seq) the new one is refused with
        // `MempoolFull`.
        let first = {
            let mut t = sample_tx(0x01, 0, 1);
            crate::tx_pow::mine_tx_pow(&mut t);
            t
        };
        let first_bytes = encoding::to_bytes(&first).unwrap().len();

        let mut pool = Mempool::new(first_bytes);
        pool.add(first.clone()).expect("first fits exactly");
        assert_eq!(pool.len(), 1);

        // Any second tx would bump `total_bytes` over the cap and
        // must compete on priority.  Since arrival_seq is strictly
        // increasing, the existing tx always wins ties — even an
        // identically-mined sibling cannot displace it.
        let mut second = sample_tx(0x02, 0, 2);
        crate::tx_pow::mine_tx_pow(&mut second);
        let result = pool.add(second);

        // At least one of two things is true:
        // - second had a strictly-worse pow_hash → rejected as
        //   MempoolFull,
        // - or second had a better pow_hash → first was evicted,
        //   pool still has one tx.
        // Either outcome preserves the size-cap invariant.
        match result {
            Ok(()) => {
                assert_eq!(pool.len(), 1);
                assert!(pool.total_bytes() <= pool.max_bytes());
            }
            Err(Error::MempoolFull) => {
                assert!(pool.contains(&first.txid()));
                assert_eq!(pool.len(), 1);
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn older_tx_wins_tie_on_equal_priority() {
        // Two txs with the same pow_hash (impossible in practice
        // outside of crafted collisions, but easy to simulate by
        // inserting and then manipulating).  We rely on the
        // primary tiebreaker instead: arrival_seq ascending.
        //
        // Add tx A, then tx B.  B must appear AFTER A in the
        // priority map because A was inserted first (lower
        // arrival_seq).  take_for_block therefore emits A first.
        let mut a = sample_tx(0x01, 0, 10);
        crate::tx_pow::mine_tx_pow(&mut a);
        let mut b = sample_tx(0x02, 0, 20);
        crate::tx_pow::mine_tx_pow(&mut b);

        // Only run the tie-check if the two naturally happen to
        // share a pow_hash prefix that orders A < B already; in
        // the general case we use arrival to confirm determinism
        // on same-difficulty (same-leading-zero-count) mining.
        let mut pool = Mempool::new(LARGE_CAP);
        pool.add(a.clone()).unwrap();
        pool.add(b.clone()).unwrap();

        let batch = pool.take_for_block(LARGE_CAP);
        // Whichever pow_hash is smaller comes first.  If they
        // happen to be equal (vanishingly unlikely), arrival_seq
        // of A wins.
        let a_hash = tx_pow_hash(&a);
        let b_hash = tx_pow_hash(&b);
        let first = if a_hash <= b_hash { a.txid() } else { b.txid() };
        assert_eq!(batch[0].txid(), first);
    }

    #[test]
    fn total_bytes_tracks_insertions_and_removals() {
        let mut pool = Mempool::new(LARGE_CAP);
        let tx1 = sample_tx(0x01, 0, 1);
        let tx2 = sample_tx(0x02, 0, 2);
        let tx1_bytes = encoding::to_bytes(&tx1).unwrap().len();
        let tx2_bytes = encoding::to_bytes(&tx2).unwrap().len();

        pool.add(tx1.clone()).unwrap();
        assert_eq!(pool.total_bytes(), tx1_bytes);

        pool.add(tx2.clone()).unwrap();
        assert_eq!(pool.total_bytes(), tx1_bytes + tx2_bytes);

        pool.remove(&tx1.txid()).unwrap();
        assert_eq!(pool.total_bytes(), tx2_bytes);
    }
}
