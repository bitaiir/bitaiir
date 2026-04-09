//! In-memory UTXO set.
//!
//! The Unspent Transaction Output set is the authoritative record of
//! which outputs exist and are available to spend. `UtxoSet` in
//! Phase 1b is a thin wrapper around `HashMap<OutPoint, TxOut>` with
//! just enough operations to drive the rest of the chain code:
//!
//! - `get` / `contains` for lookups during validation.
//! - `insert` / `remove` for direct manipulation when bootstrapping
//!   from storage.
//! - `apply_transaction` for the common case: remove all of a
//!   transaction's inputs (except the coinbase null input) and add
//!   all of its outputs.
//!
//! Undo (re-inserting spent outputs when a reorg rolls back a block)
//! is **not** implemented in Phase 1b. It will come alongside reorg
//! handling in a later phase.
//!
//! `apply_transaction` does not rollback partial changes on failure,
//! so a caller that hands it an invalid transaction will corrupt the
//! set. Every caller must therefore run consensus validation before
//! calling `apply_transaction`. The error return exists so the
//! caller can detect programming mistakes, not to recover from them.

use std::collections::HashMap;

use bitaiir_types::{OutPoint, Transaction, TxOut};

use crate::error::{Error, Result};

/// The set of all unspent transaction outputs, keyed by the
/// `OutPoint` (previous txid + vout) that identifies them.
pub struct UtxoSet {
    utxos: HashMap<OutPoint, TxOut>,
}

impl UtxoSet {
    /// Build an empty UTXO set.
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
        }
    }

    /// Number of unspent outputs currently tracked.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether the set contains no outputs.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Look up the output at `outpoint`, if it is still unspent.
    pub fn get(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.utxos.get(outpoint)
    }

    /// Whether `outpoint` is currently unspent.
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Insert an output directly, used for bootstrapping or tests.
    /// Returns the previous occupant, if any.
    pub fn insert(&mut self, outpoint: OutPoint, txout: TxOut) -> Option<TxOut> {
        self.utxos.insert(outpoint, txout)
    }

    /// Remove an output directly, returning it if it was present.
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<TxOut> {
        self.utxos.remove(outpoint)
    }

    /// Apply a transaction: remove every spent input and add every
    /// new output.
    ///
    /// Coinbase transactions are handled as a special case — the
    /// null outpoint in their single input is skipped instead of
    /// being looked up.
    ///
    /// Returns [`Error::MissingOutpoint`] if any non-coinbase input
    /// refers to an outpoint that is not currently in the set. Note
    /// that this leaves the set in a partially-modified state: any
    /// inputs already removed before the failing one stay removed.
    /// Callers must run consensus validation before calling this
    /// method; this is a backstop for programming bugs, not a
    /// rollback-capable transactional API.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<()> {
        // Remove each spent input. The coinbase transaction's single
        // input has `prev_out == OutPoint::NULL`, which is never
        // present in the UTXO set — skip it.
        for input in &tx.inputs {
            if input.prev_out == OutPoint::NULL {
                continue;
            }
            if self.utxos.remove(&input.prev_out).is_none() {
                return Err(Error::MissingOutpoint(input.prev_out));
            }
        }

        // Add each new output under its `(txid, vout)` key.
        let txid = tx.txid();
        for (vout, txout) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.utxos.insert(outpoint, *txout);
        }

        Ok(())
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

// Manual Debug impl: print the count, not every entry.
impl core::fmt::Debug for UtxoSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UtxoSet")
            .field("len", &self.utxos.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{sample_coinbase, sample_normal_tx};
    use bitaiir_types::{Amount, Hash256, OutPoint, TxOut};

    #[test]
    fn new_set_is_empty() {
        let set = UtxoSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn direct_insert_and_remove() {
        let mut set = UtxoSet::new();
        let outpoint = OutPoint {
            txid: Hash256::from_bytes([0x01; 32]),
            vout: 0,
        };
        let txout = TxOut {
            amount: Amount::from_atomic(123),
            recipient_hash: [0x42; 20],
        };

        assert!(set.insert(outpoint, txout).is_none());
        assert!(set.contains(&outpoint));
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(&outpoint).unwrap().amount.to_atomic(), 123);

        let removed = set.remove(&outpoint).unwrap();
        assert_eq!(removed.amount.to_atomic(), 123);
        assert!(!set.contains(&outpoint));
        assert!(set.is_empty());
    }

    #[test]
    fn apply_coinbase_adds_outputs_without_removing_anything() {
        let mut set = UtxoSet::new();
        let coinbase = sample_coinbase(0);
        let expected_txid = coinbase.txid();
        let expected_len = coinbase.outputs.len();

        set.apply_transaction(&coinbase).expect("coinbase applies");

        assert_eq!(set.len(), expected_len);
        // Every coinbase output is now reachable by its (txid, vout).
        for vout in 0..expected_len as u32 {
            assert!(set.contains(&OutPoint {
                txid: expected_txid,
                vout,
            }));
        }
    }

    #[test]
    fn apply_normal_transaction_removes_inputs_and_adds_outputs() {
        let mut set = UtxoSet::new();

        // Seed the set with one spendable UTXO: the coinbase output
        // from block 0.
        let coinbase = sample_coinbase(0);
        set.apply_transaction(&coinbase).unwrap();
        let spend = OutPoint {
            txid: coinbase.txid(),
            vout: 0,
        };
        assert!(set.contains(&spend));

        // Build a normal transaction that spends that output.
        let normal = sample_normal_tx(spend, 42);
        let normal_txid = normal.txid();

        set.apply_transaction(&normal).expect("normal tx applies");

        // The coinbase output is now spent.
        assert!(!set.contains(&spend));
        // The normal tx's new outputs are now unspent.
        for vout in 0..normal.outputs.len() as u32 {
            assert!(set.contains(&OutPoint {
                txid: normal_txid,
                vout,
            }));
        }
    }

    #[test]
    fn apply_transaction_errors_on_missing_input() {
        let mut set = UtxoSet::new();
        let phantom = OutPoint {
            txid: Hash256::from_bytes([0xaa; 32]),
            vout: 7,
        };
        let tx = sample_normal_tx(phantom, 1);

        let err = set.apply_transaction(&tx).unwrap_err();
        match err {
            Error::MissingOutpoint(op) => assert_eq!(op, phantom),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn applying_the_same_tx_twice_is_a_double_spend() {
        // Using a coinbase output as the funding source so we have
        // something real to double-spend.
        let mut set = UtxoSet::new();
        let coinbase = sample_coinbase(0);
        set.apply_transaction(&coinbase).unwrap();

        let spend = OutPoint {
            txid: coinbase.txid(),
            vout: 0,
        };
        let tx = sample_normal_tx(spend, 1);

        set.apply_transaction(&tx).expect("first spend");
        let err = set.apply_transaction(&tx).unwrap_err();
        assert!(matches!(err, Error::MissingOutpoint(_)));
    }

    #[test]
    fn default_is_empty() {
        let set = UtxoSet::default();
        assert!(set.is_empty());
    }
}
