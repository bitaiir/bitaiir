//! In-memory UTXO set.
//!
//! The Unspent Transaction Output set is the authoritative record of
//! which outputs exist and are available to spend.  `UtxoSet` wraps
//! `HashMap<OutPoint, TxOut>` plus two small side-maps that track
//! creation height and coinbase status:
//!
//! - `get` / `contains` for lookups during validation.
//! - `insert` / `remove` for direct manipulation when bootstrapping
//!   from storage.
//! - `apply_transaction` for the common case: remove all of a
//!   transaction's inputs (except the coinbase null input) and add
//!   all of its outputs.
//! - `apply_block_with_undo` + `undo_block` for reversible block
//!   application — required by reorg logic.  The `BlockUndo` returned
//!   by `apply_block_with_undo` is a compact record of what was
//!   consumed, enough to put the set back exactly as it was.
//!
//! `apply_transaction` does not rollback partial changes on failure,
//! so a caller that hands it an invalid transaction will corrupt the
//! set.  Every caller must therefore run consensus validation before
//! calling `apply_transaction`.  The error return exists so the
//! caller can detect programming mistakes, not to recover from them.

use std::collections::HashMap;

use bitaiir_types::{Block, Hash256, OutPoint, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// -------------------------------------------------------------------------
// Undo records
// -------------------------------------------------------------------------

/// A single UTXO consumed by a block, recorded so the block can be
/// undone by restoring it to the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentInput {
    /// The outpoint that was spent.
    pub outpoint: OutPoint,
    /// The `TxOut` that sat at that outpoint before the block applied.
    pub txout: TxOut,
    /// Block height at which the now-spent output was originally
    /// created.  Needed to restore `output_heights` on undo so
    /// confirmation counts remain correct across reorgs.
    pub created_at_height: u64,
    /// Whether the now-spent output was a coinbase output.  Tracked
    /// so `coinbase_heights` can be restored on undo (coinbase
    /// maturity still applies to outputs that come back via reorg).
    pub was_coinbase: bool,
}

/// Everything needed to revert a block's effect on the UTXO set.
///
/// Produced by [`UtxoSet::apply_block_with_undo`] and consumed by
/// [`UtxoSet::undo_block`].  Persisting this to storage lets a node
/// reverse a block during a reorg without replaying the whole chain.
///
/// The block's *created* outputs are not stored here — they can be
/// reconstructed from the `Block` itself, which storage already
/// keeps.  Only the data that is destroyed by application (the old
/// `TxOut`, its creation height, its coinbase flag) needs to live in
/// the undo record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockUndo {
    /// Hash of the block this undo record corresponds to.  Used as
    /// a sanity check when pairing undo with block data on reorg.
    pub block_hash: Hash256,
    /// Every non-coinbase input spent by the block, in the order the
    /// transactions appear and in the order the inputs appear within
    /// each transaction.  Coinbase null inputs are skipped.
    pub spent_inputs: Vec<SpentInput>,
}

/// The set of all unspent transaction outputs, keyed by the
/// `OutPoint` (previous txid + vout) that identifies them.
pub struct UtxoSet {
    utxos: HashMap<OutPoint, TxOut>,
    /// For coinbase outputs only: records the block height at which
    /// the output was created so we can enforce the 100-block
    /// maturity rule (protocol §6.5).
    coinbase_heights: HashMap<OutPoint, u64>,
    /// Block height at which each output was created.  Populated for
    /// ALL outputs (coinbase and non-coinbase) so the wallet layer
    /// can compute confirmation counts and display "confirmed" vs.
    /// "unconfirmed" splits.
    output_heights: HashMap<OutPoint, u64>,
}

impl UtxoSet {
    /// Build an empty UTXO set.
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
            coinbase_heights: HashMap::new(),
            output_heights: HashMap::new(),
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

    /// Iterate over every `(OutPoint, TxOut)` pair in the set.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &TxOut)> {
        self.utxos.iter()
    }

    /// If the outpoint is a coinbase output, return the height at
    /// which it was created. Returns `None` for non-coinbase outputs.
    pub fn coinbase_height(&self, outpoint: &OutPoint) -> Option<u64> {
        self.coinbase_heights.get(outpoint).copied()
    }

    /// Return the block height at which `outpoint` was created.
    /// Works for both coinbase and non-coinbase outputs.  Returns
    /// `None` only if the outpoint is not in the set or was loaded
    /// from storage without height info (pre-existing chain data).
    pub fn output_height(&self, outpoint: &OutPoint) -> Option<u64> {
        self.output_heights.get(outpoint).copied()
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
    pub fn apply_transaction(&mut self, tx: &Transaction, height: u64) -> Result<()> {
        let is_coinbase = tx.is_coinbase();

        // Remove each spent input.
        for input in &tx.inputs {
            if input.prev_out == OutPoint::NULL {
                continue;
            }
            self.coinbase_heights.remove(&input.prev_out);
            self.output_heights.remove(&input.prev_out);
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
            self.output_heights.insert(outpoint, height);
            if is_coinbase {
                self.coinbase_heights.insert(outpoint, height);
            }
        }

        Ok(())
    }

    /// Apply every transaction in a block and return a [`BlockUndo`]
    /// record capturing enough information to reverse the application.
    ///
    /// The undo record holds, for every non-coinbase input the block
    /// consumed, the outpoint, the previous `TxOut`, the height at
    /// which that output was originally created, and whether it was
    /// a coinbase output.  [`UtxoSet::undo_block`] restores the set
    /// from the undo record plus the block itself.
    ///
    /// On failure the set is left in a partially-modified state —
    /// caller must run consensus validation first, exactly like
    /// [`Self::apply_transaction`].
    pub fn apply_block_with_undo(&mut self, block: &Block, height: u64) -> Result<BlockUndo> {
        let mut spent_inputs: Vec<SpentInput> = Vec::new();

        for tx in &block.transactions {
            let is_coinbase = tx.is_coinbase();

            // Record and remove spent inputs.
            for input in &tx.inputs {
                if input.prev_out == OutPoint::NULL {
                    continue;
                }
                let outpoint = input.prev_out;
                let txout = *self
                    .utxos
                    .get(&outpoint)
                    .ok_or(Error::MissingOutpoint(outpoint))?;
                let created_at_height = self.output_heights.get(&outpoint).copied().unwrap_or(0);
                let was_coinbase = self.coinbase_heights.contains_key(&outpoint);
                spent_inputs.push(SpentInput {
                    outpoint,
                    txout,
                    created_at_height,
                    was_coinbase,
                });

                self.utxos.remove(&outpoint);
                self.output_heights.remove(&outpoint);
                self.coinbase_heights.remove(&outpoint);
            }

            // Add each new output.
            let txid = tx.txid();
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                self.utxos.insert(outpoint, *txout);
                self.output_heights.insert(outpoint, height);
                if is_coinbase {
                    self.coinbase_heights.insert(outpoint, height);
                }
            }
        }

        Ok(BlockUndo {
            block_hash: block.block_hash(),
            spent_inputs,
        })
    }

    /// Reverse the effect of a previous [`Self::apply_block_with_undo`]
    /// call, restoring the set to its pre-block state.
    ///
    /// The caller must supply both the original `block` (whose created
    /// outputs need to be removed) and the `undo` record produced by
    /// application (whose `spent_inputs` describe what to restore).
    /// If `undo.block_hash` does not match `block.block_hash()` the
    /// operation is refused — the two sides of a reorg must agree on
    /// which block is being rolled back.
    pub fn undo_block(&mut self, block: &Block, undo: &BlockUndo) -> Result<()> {
        let block_hash = block.block_hash();
        if undo.block_hash != block_hash {
            return Err(Error::UndoBlockHashMismatch {
                expected: block_hash,
                got: undo.block_hash,
            });
        }

        // Remove every output the block created.  Both maps (heights
        // and coinbase_heights) are cleaned up along the way.
        for tx in &block.transactions {
            let txid = tx.txid();
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                self.utxos.remove(&outpoint);
                self.output_heights.remove(&outpoint);
                self.coinbase_heights.remove(&outpoint);
            }
        }

        // Restore every spent input back to how it was.
        for spent in &undo.spent_inputs {
            self.utxos.insert(spent.outpoint, spent.txout);
            self.output_heights
                .insert(spent.outpoint, spent.created_at_height);
            if spent.was_coinbase {
                self.coinbase_heights
                    .insert(spent.outpoint, spent.created_at_height);
            }
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

        set.apply_transaction(&coinbase, 0)
            .expect("coinbase applies");

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
        set.apply_transaction(&coinbase, 0).unwrap();
        let spend = OutPoint {
            txid: coinbase.txid(),
            vout: 0,
        };
        assert!(set.contains(&spend));

        // Build a normal transaction that spends that output.
        let normal = sample_normal_tx(spend, 42);
        let normal_txid = normal.txid();

        set.apply_transaction(&normal, 0)
            .expect("normal tx applies");

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

        let err = set.apply_transaction(&tx, 0).unwrap_err();
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
        set.apply_transaction(&coinbase, 0).unwrap();

        let spend = OutPoint {
            txid: coinbase.txid(),
            vout: 0,
        };
        let tx = sample_normal_tx(spend, 1);

        set.apply_transaction(&tx, 1).expect("first spend");
        let err = set.apply_transaction(&tx, 0).unwrap_err();
        assert!(matches!(err, Error::MissingOutpoint(_)));
    }

    #[test]
    fn default_is_empty() {
        let set = UtxoSet::default();
        assert!(set.is_empty());
    }

    // --- Undo-data tests ------------------------------------------------ //

    /// Snapshot the UTXO set's observable state so two sets can be
    /// compared structurally.  `HashMap` implements `PartialEq` so
    /// the returned tuple compares by contents regardless of
    /// insertion order.
    fn snapshot(
        set: &UtxoSet,
    ) -> (
        HashMap<OutPoint, TxOut>,
        HashMap<OutPoint, u64>,
        HashMap<OutPoint, u64>,
    ) {
        (
            set.utxos.clone(),
            set.output_heights.clone(),
            set.coinbase_heights.clone(),
        )
    }

    /// Fabricate a one-tx block (coinbase only) at the given height,
    /// so we can exercise `apply_block_with_undo` / `undo_block`.
    fn coinbase_only_block(height: u64) -> bitaiir_types::Block {
        let coinbase = sample_coinbase(height);
        let merkle = coinbase.txid();
        bitaiir_types::Block {
            header: bitaiir_types::BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 0,
                bits: 0x2000_ffff,
                // `nonce` uniqueness keeps the block_hash distinct
                // when height changes, so our undo-hash sanity check
                // can differentiate the two blocks.
                nonce: height as u32,
            },
            transactions: vec![coinbase],
        }
    }

    /// Fabricate a two-tx block: coinbase + a normal tx spending the
    /// given outpoint with the given pow_nonce.
    fn block_with_spend(height: u64, spend: OutPoint, tx_pow: u64) -> bitaiir_types::Block {
        let coinbase = sample_coinbase(height);
        let normal = sample_normal_tx(spend, tx_pow);
        let merkle = coinbase.txid();
        bitaiir_types::Block {
            header: bitaiir_types::BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 0,
                bits: 0x2000_ffff,
                nonce: height as u32,
            },
            transactions: vec![coinbase, normal],
        }
    }

    #[test]
    fn apply_then_undo_round_trips_coinbase_only_block() {
        let mut set = UtxoSet::new();
        let before = snapshot(&set);

        let block = coinbase_only_block(1);
        let undo = set.apply_block_with_undo(&block, 1).expect("apply");
        // After apply, the set has the coinbase output.
        assert_eq!(set.len(), block.transactions[0].outputs.len());

        set.undo_block(&block, &undo).expect("undo");
        // Back to identity.
        assert_eq!(snapshot(&set), before);
    }

    #[test]
    fn apply_then_undo_round_trips_block_with_spend() {
        // Seed the set with a spendable coinbase output from a prior
        // block, then build a block that spends it + mints its own
        // coinbase.  Apply + undo must restore the original state
        // exactly, including the coinbase-maturity tracking.
        let mut set = UtxoSet::new();
        let genesis_coinbase = sample_coinbase(0);
        set.apply_transaction(&genesis_coinbase, 0).unwrap();
        let spend = OutPoint {
            txid: genesis_coinbase.txid(),
            vout: 0,
        };
        assert!(set.contains(&spend));
        assert_eq!(set.coinbase_height(&spend), Some(0));

        let before = snapshot(&set);
        let block = block_with_spend(1, spend, 7);
        let undo = set.apply_block_with_undo(&block, 1).expect("apply");

        // Mid-state: coinbase output spent, block's new outputs present.
        assert!(!set.contains(&spend));

        set.undo_block(&block, &undo).expect("undo");
        assert_eq!(snapshot(&set), before);
        // Specifically, the coinbase-maturity tracking came back too.
        assert_eq!(set.coinbase_height(&spend), Some(0));
    }

    #[test]
    fn undo_block_rejects_mismatched_hash() {
        let mut set = UtxoSet::new();
        let block_a = coinbase_only_block(1);
        let block_b = coinbase_only_block(2);

        let undo_a = set.apply_block_with_undo(&block_a, 1).expect("apply a");
        // Rewind manually so `set` is free for the mismatched call.
        set.undo_block(&block_a, &undo_a).expect("undo a");
        let _undo_b = set.apply_block_with_undo(&block_b, 2).expect("apply b");

        // Hand `undo_a` to a call that wants to undo block_b — refused.
        let err = set.undo_block(&block_b, &undo_a).unwrap_err();
        assert!(matches!(err, Error::UndoBlockHashMismatch { .. }));
    }

    #[test]
    fn undo_restores_multiple_spends_in_order() {
        // A block spending two separate coinbase outputs, then being
        // undone.  Exercises the ordering of `spent_inputs` — the
        // undo must put each outpoint back with its correct height
        // and coinbase flag.
        let mut set = UtxoSet::new();

        let cb0 = sample_coinbase(0);
        set.apply_transaction(&cb0, 0).unwrap();
        let spend0 = OutPoint {
            txid: cb0.txid(),
            vout: 0,
        };

        let cb5 = sample_coinbase(5);
        set.apply_transaction(&cb5, 5).unwrap();
        let spend5 = OutPoint {
            txid: cb5.txid(),
            vout: 0,
        };

        let before = snapshot(&set);

        // A hand-built block with two normal txs, one per outpoint.
        let coinbase = sample_coinbase(10);
        let tx_a = sample_normal_tx(spend0, 1);
        let tx_b = sample_normal_tx(spend5, 2);
        let merkle = coinbase.txid();
        let block = bitaiir_types::Block {
            header: bitaiir_types::BlockHeader {
                version: 1,
                prev_block_hash: Hash256::ZERO,
                merkle_root: merkle,
                timestamp: 0,
                bits: 0x2000_ffff,
                nonce: 10,
            },
            transactions: vec![coinbase, tx_a, tx_b],
        };

        let undo = set.apply_block_with_undo(&block, 10).expect("apply");
        assert!(!set.contains(&spend0));
        assert!(!set.contains(&spend5));

        set.undo_block(&block, &undo).expect("undo");
        assert_eq!(snapshot(&set), before);
        assert_eq!(set.coinbase_height(&spend0), Some(0));
        assert_eq!(set.coinbase_height(&spend5), Some(5));
    }
}
