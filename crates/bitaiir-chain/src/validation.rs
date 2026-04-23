//! Block and transaction validation — the consensus rules.
//!
//! This module is where the protocol specification (§6.1, §7.4)
//! becomes executable code. Every validation function takes immutable
//! references to the data being validated and to the current chain
//! state, and returns `Ok(())` if the data passes all checks or
//! `Err(Error)` with a specific variant identifying the first broken
//! rule.
//!
//! Callers should run `validate_block` (which internally calls
//! `validate_transaction` for every non-coinbase transaction) before
//! passing a block to `Chain::push` and `UtxoSet::apply_transaction`.
//!
//! # Phase 1c scope
//!
//! Phase 1c implements the "big picture" rules: size limits, PoW,
//! merkle root, timestamps, coinbase cap, input existence, and no
//! double-spend. It does **not** yet check:
//!
//! - ECDSA signature validity (requires wiring `bitaiir-crypto`'s
//!   signature module into the chain crate).
//! - Anti-spam tx-level PoW (protocol §6.7, Phase 3).
//! - Coinbase maturity (requires tracking height per UTXO, Phase 1d
//!   or later).
//!
//! Those items will be added as new validation passes in subsequent
//! phases; nothing in the current code needs to be undone.

use std::collections::HashSet;

use bitaiir_crypto::hash::hash160;
use bitaiir_crypto::key::PublicKey;
use bitaiir_types::{Block, OutPoint, Transaction, encoding};

use crate::chain::Chain;
use crate::consensus::{MAX_BLOCK_SIZE, MAX_TX_SIZE, MEDIAN_TIME_SPAN};
use crate::error::{Error, Result};
use crate::pow::aiir_pow;
use crate::subsidy::subsidy;
use crate::target::CompactTarget;
use crate::tx_pow;
use crate::utxo::UtxoSet;

// -------------------------------------------------------------------------
// Transaction validation (protocol §6.1)
// -------------------------------------------------------------------------

/// Validate a non-coinbase transaction against the current UTXO set.
///
/// Returns `Ok(())` if the transaction passes every applicable
/// consensus check, or the first `Error` encountered.
///
/// # Rules checked
///
/// 1. At least one input and one output.
/// 2. Serialized size ≤ `MAX_TX_SIZE`.
/// 3. No duplicate inputs within the same transaction.
/// 4. Every input references an outpoint that exists in `utxo_set`.
/// 5. `sum(input_amounts) ≥ sum(output_amounts)` — no money creation.
///
/// # Rules NOT checked (yet)
///
/// - Anti-spam `pow_nonce` (Phase 3).
/// - Coinbase maturity of the spent outputs.
pub fn validate_transaction(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    current_height: u64,
) -> Result<()> {
    // Rule: must have inputs and outputs.
    if tx.inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    if tx.outputs.is_empty() {
        return Err(Error::NoOutputs);
    }

    // Rule: serialized size limit.
    let size = encoding::to_bytes(tx)
        .expect("Transaction always encodes")
        .len();
    if size > MAX_TX_SIZE {
        return Err(Error::TxTooLarge {
            size,
            max: MAX_TX_SIZE,
        });
    }

    // Rule: anti-spam proof of work (protocol §6.7).
    if !tx_pow::validate_tx_pow(tx) {
        return Err(Error::InvalidTxPow);
    }

    // Rule: no duplicate inputs.
    let mut seen_inputs: HashSet<OutPoint> = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen_inputs.insert(input.prev_out) {
            return Err(Error::DuplicateInput(input.prev_out));
        }
    }

    // Rule: every input exists, signature and pubkey are valid.
    let sighash = tx.sighash();
    let mut input_total: u64 = 0;
    for input in &tx.inputs {
        let utxo = utxo_set
            .get(&input.prev_out)
            .ok_or(Error::UnknownInput(input.prev_out))?;

        // Check coinbase maturity (protocol §6.5). Read the value
        // from the active network so testnet's shorter maturity is
        // honored here.
        if let Some(cb_height) = utxo_set.coinbase_height(&input.prev_out) {
            let maturity = crate::consensus::coinbase_maturity();
            if current_height < cb_height + maturity {
                let confirmations = current_height.saturating_sub(cb_height);
                let remaining = maturity.saturating_sub(confirmations);
                return Err(Error::ImmatureCoinbase {
                    outpoint: input.prev_out,
                    created_at: cb_height,
                    current_height,
                    maturity,
                    remaining,
                });
            }
        }

        // Check that the pubkey hashes to the UTXO's recipient_hash.
        let pubkey_hash = hash160(&input.pubkey);
        let utxo_hash = utxo
            .recipient_hash()
            .ok_or(Error::InvalidOutputType(input.prev_out))?;
        if pubkey_hash != utxo_hash {
            return Err(Error::PubkeyMismatch(input.prev_out));
        }

        // Verify the ECDSA signature against the sighash.
        let Ok(pubkey) = PublicKey::from_slice(&input.pubkey) else {
            return Err(Error::InvalidInputSignature(input.prev_out));
        };
        if !pubkey.verify_digest(sighash.as_bytes(), &input.signature) {
            return Err(Error::InvalidInputSignature(input.prev_out));
        }

        input_total = input_total.saturating_add(utxo.amount.to_atomic());
    }

    let output_total: u64 = tx
        .outputs
        .iter()
        .map(|o| o.amount.to_atomic())
        .fold(0u64, |acc, a| acc.saturating_add(a));

    // Rule: no money creation.
    if output_total > input_total {
        return Err(Error::OutputsExceedInputs {
            inputs: input_total,
            outputs: output_total,
        });
    }

    // Rule: alias outputs must pass name + fee + uniqueness checks.
    for output in &tx.outputs {
        if output.is_alias() {
            validate_alias_output(output, utxo_set, current_height)?;
        }
        if output.output_type != bitaiir_types::OUTPUT_TYPE_P2PKH
            && output.output_type != bitaiir_types::OUTPUT_TYPE_ALIAS
        {
            return Err(Error::UnknownOutputType(output.output_type));
        }
    }

    Ok(())
}

fn validate_alias_output(
    output: &bitaiir_types::TxOut,
    utxo_set: &UtxoSet,
    current_height: u64,
) -> Result<()> {
    let params = output.alias_params().ok_or(Error::MalformedAliasPayload)?;

    bitaiir_types::validate_alias_name(&params.name).map_err(Error::InvalidAliasName)?;

    if output.amount.to_atomic() < bitaiir_types::ALIAS_REGISTRATION_FEE.to_atomic() {
        return Err(Error::AliasFeeInsufficient);
    }

    if params.expiry_height <= current_height as u32 {
        return Err(Error::AliasExpiryInPast(params.expiry_height));
    }
    let max_expiry = current_height as u32 + bitaiir_types::ALIAS_PERIOD + 20;
    if params.expiry_height > max_expiry {
        return Err(Error::AliasExpiryTooFar {
            max: max_expiry,
            got: params.expiry_height,
        });
    }

    let name = String::from_utf8_lossy(&params.name).to_lowercase();
    if utxo_set.alias_exists(&name) {
        return Err(Error::AliasAlreadyRegistered(name));
    }

    Ok(())
}

// -------------------------------------------------------------------------
// Block validation (protocol §7.4)
// -------------------------------------------------------------------------

/// Check the subset of block-validity rules that depend **only on
/// the block itself**, not on any chain or UTXO state.
///
/// Used to reject obviously-bad blocks received from peers before
/// paying the cost of storing them or running stateful validation.
/// It's also the validation that's available for side-chain blocks,
/// where the UTXO state at the block's position can't easily be
/// reconstructed until the chain actually reorgs to that branch.
///
/// Rules checked:
/// - **1**: serialized size ≤ `MAX_BLOCK_SIZE`.
/// - **2**: proof of work (`aiir_pow(header)` ≤ target from `bits`).
/// - **7**: header merkle root matches the computed merkle root.
/// - **8**: first transaction is a coinbase.
/// - **10**: no duplicate transactions within the block.
///
/// Rules NOT checked here (they need chain/UTXO context):
///   parent linkage, retarget bits, timestamp vs MTP, timestamp vs
///   network time, input existence, tx signatures, coinbase overspend.
pub fn validate_block_standalone(block: &Block) -> Result<()> {
    let header = &block.header;

    // Rule 1: block size.
    let block_bytes = encoding::to_bytes(block).expect("Block always encodes");
    if block_bytes.len() > MAX_BLOCK_SIZE {
        return Err(Error::BlockTooLarge {
            size: block_bytes.len(),
            max: MAX_BLOCK_SIZE,
        });
    }

    // Rule 2: proof of work.
    let pow_hash = aiir_pow(header);
    let target = CompactTarget::from_bits(header.bits);
    if !target.hash_meets_target(pow_hash.as_bytes()) {
        return Err(Error::InsufficientProofOfWork);
    }

    // Rule 7: merkle root.
    let computed_merkle = block.compute_merkle_root();
    if header.merkle_root != computed_merkle {
        return Err(Error::MerkleRootMismatch {
            header: header.merkle_root,
            computed: computed_merkle,
        });
    }

    // Rule 8: first transaction must be a coinbase.
    let coinbase = block.transactions.first().ok_or(Error::InvalidCoinbase {
        reason: "block has no transactions",
    })?;
    if !coinbase.is_coinbase() {
        return Err(Error::InvalidCoinbase {
            reason: "first transaction is not a coinbase",
        });
    }

    // Rule 10: no duplicate transactions.
    let mut seen_txids: HashSet<bitaiir_types::Hash256> =
        HashSet::with_capacity(block.transactions.len());
    for tx in &block.transactions {
        let txid = tx.txid();
        if !seen_txids.insert(txid) {
            return Err(Error::DuplicateTransaction(txid));
        }
    }

    Ok(())
}

/// Validate a full block against the chain tip and UTXO set.
///
/// `network_time` is the node's current adjusted time in seconds
/// since epoch (used for the "not too far in the future" check). In
/// tests, pass a value a few seconds after the block's timestamp.
///
/// Returns `Ok(())` if every rule passes.
///
/// # Rules checked (protocol §7.4, numbered)
///
/// 1. Serialized block ≤ `MAX_BLOCK_SIZE`.
/// 2. `aiir_pow(header) ≤ target(bits)`.
/// 3. `bits` field matches the expected difficulty from the retarget algorithm.
/// 4. Timestamp > median-time-past of the previous 11 blocks.
/// 5. Timestamp ≤ network_time + `MAX_FUTURE_BLOCK_TIME`.
/// 6. `prev_block_hash == chain.tip()`.
/// 7. `header.merkle_root == computed merkle root`.
/// 8. First transaction is a coinbase.
/// 9. Every non-coinbase transaction is valid
///    (calls `validate_transaction`).
/// 10. No duplicate transactions.
/// 11. Coinbase outputs ≤ subsidy + fees.
pub fn validate_block(
    block: &Block,
    chain: &Chain,
    utxo_set: &UtxoSet,
    network_time: u64,
) -> Result<()> {
    let header = &block.header;

    // Rule 1: block size.
    let block_bytes = encoding::to_bytes(block).expect("Block always encodes");
    if block_bytes.len() > MAX_BLOCK_SIZE {
        return Err(Error::BlockTooLarge {
            size: block_bytes.len(),
            max: MAX_BLOCK_SIZE,
        });
    }

    // Rule 6 (checked early so later rules can trust the parent
    // relationship): prev_block_hash must be our tip.
    let expected_parent = chain.tip();
    if header.prev_block_hash != expected_parent {
        return Err(Error::ParentMismatch {
            expected: expected_parent,
            got: header.prev_block_hash,
        });
    }

    // Rule 2: proof of work.
    let pow_hash = aiir_pow(header);
    let target = CompactTarget::from_bits(header.bits);
    if !target.hash_meets_target(pow_hash.as_bytes()) {
        return Err(Error::InsufficientProofOfWork);
    }

    // Rule 3: difficulty bits must match the expected retarget value.
    let next_height = chain.height() + 1;
    let expected_bits = crate::mining::required_bits(chain, next_height);
    if header.bits != expected_bits {
        return Err(Error::WrongDifficulty {
            expected: expected_bits,
            got: header.bits,
        });
    }

    // Rule 4: timestamp > median-time-past.
    let mtp = median_time_past(chain);
    if header.timestamp <= mtp {
        return Err(Error::TimestampTooEarly {
            timestamp: header.timestamp,
            mtp,
        });
    }

    // Rule 5: timestamp not too far in the future.
    let max_future = crate::consensus::MAX_FUTURE_BLOCK_TIME;
    if header.timestamp > network_time + max_future {
        return Err(Error::TimestampTooFarInFuture {
            timestamp: header.timestamp,
            now: network_time,
            max_future,
        });
    }

    // Rule 7: merkle root.
    let computed_merkle = block.compute_merkle_root();
    if header.merkle_root != computed_merkle {
        return Err(Error::MerkleRootMismatch {
            header: header.merkle_root,
            computed: computed_merkle,
        });
    }

    // Rule 8: first transaction must be a coinbase.
    let coinbase = block.transactions.first().ok_or(Error::InvalidCoinbase {
        reason: "block has no transactions",
    })?;
    if !coinbase.is_coinbase() {
        return Err(Error::InvalidCoinbase {
            reason: "first transaction is not a coinbase",
        });
    }

    // Rule 10: no duplicate transactions.
    let mut seen_txids: HashSet<bitaiir_types::Hash256> =
        HashSet::with_capacity(block.transactions.len());
    for tx in &block.transactions {
        let txid = tx.txid();
        if !seen_txids.insert(txid) {
            return Err(Error::DuplicateTransaction(txid));
        }
    }

    // Rule 9: validate each non-coinbase transaction.
    for tx in block.transactions.iter().skip(1) {
        validate_transaction(tx, utxo_set, next_height)?;
    }

    // Rule 11: coinbase outputs ≤ subsidy + fees.
    let height = chain.height() + 1; // This block will sit at the next height.
    let subsidy_amount = subsidy(height).to_atomic();

    // Tally fees from non-coinbase transactions.
    let mut total_fees: u64 = 0;
    for tx in block.transactions.iter().skip(1) {
        let input_sum: u64 = tx
            .inputs
            .iter()
            .filter_map(|inp| utxo_set.get(&inp.prev_out))
            .map(|utxo| utxo.amount.to_atomic())
            .sum();
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount.to_atomic()).sum();
        // Fee = input_sum - output_sum. Validate_transaction already
        // ensured input_sum >= output_sum, so this never underflows.
        total_fees = total_fees.saturating_add(input_sum.saturating_sub(output_sum));
    }

    let allowed = subsidy_amount.saturating_add(total_fees);
    let coinbase_total: u64 = coinbase.outputs.iter().map(|o| o.amount.to_atomic()).sum();

    if coinbase_total > allowed {
        return Err(Error::CoinbaseOverspend {
            coinbase_total,
            allowed,
        });
    }

    Ok(())
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Compute the median-time-past: the median of the timestamps of the
/// previous `MEDIAN_TIME_SPAN` blocks (or fewer, if the chain is
/// shorter). Used by rule 4.
pub(crate) fn median_time_past(chain: &Chain) -> u64 {
    let height = chain.height();
    let count = MEDIAN_TIME_SPAN.min(height as usize + 1);

    let mut timestamps: Vec<u64> = (0..count)
        .map(|i| {
            let h = height - i as u64;
            chain
                .header_at(h)
                .expect("header_at within chain bounds")
                .timestamp
        })
        .collect();

    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        mine_test_nonce, sample_block, sample_coinbase, sample_normal_tx, test_private_key,
    };
    use bitaiir_types::{Amount, Hash256, OutPoint, TxOut};

    /// Build a small chain + UTXO set with one block (the genesis)
    /// and return everything needed to construct and validate a
    /// follow-up block.
    fn setup() -> (Chain, UtxoSet) {
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis.clone());

        let mut utxo = UtxoSet::new();
        for tx in &genesis.transactions {
            utxo.apply_transaction(tx, 0).unwrap();
        }

        (chain, utxo)
    }

    /// Build a valid block-1 on top of the genesis, with a mined
    /// PoW nonce. The block is fully valid under Phase 1c rules.
    fn valid_block_1(chain: &Chain) -> Block {
        let coinbase = sample_coinbase(1);
        let merkle_root = coinbase.txid();
        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root,
            timestamp: chain.header_at(chain.height()).unwrap().timestamp + 10,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    /// Convenience: build a block with the given header fields, mine
    /// its nonce, and return it. Used by tests that intentionally
    /// break a single rule but need PoW to pass so validation reaches
    /// the rule being tested.
    fn block_with_mined_nonce(
        chain: &Chain,
        coinbase: bitaiir_types::Transaction,
        timestamp: u64,
    ) -> Block {
        let merkle_root = coinbase.txid();
        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root,
            timestamp,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        Block {
            header,
            transactions: vec![coinbase],
        }
    }

    fn network_time_for(block: &Block) -> u64 {
        block.header.timestamp + 1
    }

    // --- Happy path ------------------------------------------------------ //

    #[test]
    fn valid_block_passes_all_rules() {
        let (chain, utxo) = setup();
        let block = valid_block_1(&chain);
        let net_time = network_time_for(&block);
        validate_block(&block, &chain, &utxo, net_time).expect("should validate");
    }

    // --- Rule 1: block size ---------------------------------------------- //

    // (Hard to trigger with real data under 1 MB; we skip a fabricated
    //  test for now and rely on the check being present in code.)

    // --- Rule 2: proof of work ------------------------------------------- //

    #[test]
    fn invalid_pow_is_rejected() {
        let (chain, utxo) = setup();
        let mut block = valid_block_1(&chain);
        // Set bits to an extremely difficult target so PoW fails.
        block.header.bits = 0x0100_0001;
        // Recompute merkle root (unchanged, but good hygiene).
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(
            matches!(err, Error::InsufficientProofOfWork),
            "expected InsufficientProofOfWork, got {err:?}",
        );
    }

    // --- Rule 4: timestamp > MTP ----------------------------------------- //

    #[test]
    fn timestamp_at_or_before_mtp_is_rejected() {
        let (chain, utxo) = setup();
        // Build a block with timestamp equal to the genesis (which is
        // the MTP when the chain has only one block). Mine a valid
        // nonce so we reach the timestamp check.
        let bad_ts = chain.header_at(0).unwrap().timestamp;
        let block = block_with_mined_nonce(&chain, sample_coinbase(1), bad_ts);
        let net_time = bad_ts + 1;
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(matches!(err, Error::TimestampTooEarly { .. }));
    }

    // --- Rule 5: timestamp not too far in the future --------------------- //

    #[test]
    fn timestamp_far_in_future_is_rejected() {
        let (chain, utxo) = setup();
        let now = chain.header_at(0).unwrap().timestamp + 10;
        let bad_ts = now + crate::consensus::MAX_FUTURE_BLOCK_TIME + 1;
        let block = block_with_mined_nonce(&chain, sample_coinbase(1), bad_ts);
        let err = validate_block(&block, &chain, &utxo, now).unwrap_err();
        assert!(matches!(err, Error::TimestampTooFarInFuture { .. }));
    }

    // --- Rule 6: prev_block_hash ----------------------------------------- //

    #[test]
    fn wrong_parent_hash_is_rejected() {
        let (chain, utxo) = setup();
        let mut block = valid_block_1(&chain);
        block.header.prev_block_hash = Hash256::from_bytes([0xde; 32]);
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(matches!(err, Error::ParentMismatch { .. }));
    }

    // --- Rule 7: merkle root --------------------------------------------- //

    #[test]
    fn wrong_merkle_root_is_rejected() {
        let (chain, utxo) = setup();
        let good_ts = chain.header_at(0).unwrap().timestamp + 10;
        let coinbase = sample_coinbase(1);
        // Build the header with a deliberately wrong merkle root, then
        // mine a valid nonce so PoW passes and we reach rule 7.
        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root: Hash256::from_bytes([0xab; 32]),
            timestamp: good_ts,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        let block = Block {
            header,
            transactions: vec![coinbase],
        };
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(matches!(err, Error::MerkleRootMismatch { .. }));
    }

    // --- Rule 8: first tx must be coinbase ------------------------------- //

    #[test]
    fn block_without_coinbase_is_rejected() {
        let (chain, utxo) = setup();
        let genesis_coinbase = chain.genesis().transactions[0].clone();
        let spend = OutPoint {
            txid: genesis_coinbase.txid(),
            vout: 0,
        };
        let normal = sample_normal_tx(spend, 7);
        let merkle = normal.txid();
        let good_ts = chain.header_at(0).unwrap().timestamp + 10;

        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root: merkle,
            timestamp: good_ts,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        let block = Block {
            header,
            transactions: vec![normal],
        };
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(matches!(err, Error::InvalidCoinbase { .. }));
    }

    // --- Rule 9: non-coinbase tx validation ------------------------------ //

    #[test]
    fn block_with_invalid_tx_is_rejected() {
        let (chain, utxo) = setup();
        let coinbase = sample_coinbase(1);
        let bad_tx = sample_normal_tx(
            OutPoint {
                txid: Hash256::from_bytes([0xff; 32]),
                vout: 0,
            },
            7,
        );
        let good_ts = chain.header_at(0).unwrap().timestamp + 10;
        let merkle = {
            use bitaiir_types::merkle_root;
            merkle_root(&[coinbase.txid(), bad_tx.txid()])
        };
        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root: merkle,
            timestamp: good_ts,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        let block = Block {
            header,
            transactions: vec![coinbase, bad_tx],
        };
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(matches!(err, Error::UnknownInput(_)));
    }

    // --- Rule 10: no duplicate txs --------------------------------------- //

    #[test]
    fn duplicate_transactions_are_rejected() {
        let (chain, utxo) = setup();
        let coinbase = sample_coinbase(1);
        let dup = coinbase.clone();
        let good_ts = chain.header_at(0).unwrap().timestamp + 10;

        // Compute the (broken) merkle root from duplicate txs, then
        // mine a valid nonce so PoW passes and we reach rule 10.
        let merkle = {
            use bitaiir_types::merkle_root;
            merkle_root(&[coinbase.txid(), dup.txid()])
        };
        let mut header = bitaiir_types::BlockHeader {
            version: 1,
            prev_block_hash: chain.tip(),
            merkle_root: merkle,
            timestamp: good_ts,
            bits: CompactTarget::INITIAL.to_bits(),
            nonce: 0,
        };
        mine_test_nonce(&mut header);
        let block = Block {
            header,
            transactions: vec![coinbase, dup],
        };
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(
            matches!(err, Error::DuplicateTransaction(_)),
            "expected DuplicateTransaction, got {err:?}",
        );
    }

    // --- Rule 11: coinbase overspend ------------------------------------- //

    #[test]
    fn coinbase_overspend_is_rejected() {
        let (chain, utxo) = setup();
        let good_ts = chain.header_at(0).unwrap().timestamp + 10;
        // Build a coinbase that claims 200 AIIR — the subsidy at
        // height 1 is only 100 AIIR, so this must be rejected.
        let mut coinbase = sample_coinbase(1);
        coinbase.outputs[0].amount = Amount::from_atomic(200 * 100_000_000);

        let block = block_with_mined_nonce(&chain, coinbase, good_ts);
        let net_time = network_time_for(&block);
        let err = validate_block(&block, &chain, &utxo, net_time).unwrap_err();
        assert!(
            matches!(err, Error::CoinbaseOverspend { .. }),
            "expected CoinbaseOverspend, got {err:?}",
        );
    }

    // --- Transaction validation standalone ------------------------------- //

    #[test]
    fn valid_tx_passes() {
        let (_, utxo) = setup();
        // The genesis coinbase created an output. Let's build a
        // transaction that spends it.
        let genesis_cb = sample_coinbase(0);
        // Re-apply to the fresh utxo (setup already applied it, but
        // let's use the returned state).
        let spend = OutPoint {
            txid: genesis_cb.txid(),
            vout: 0,
        };
        // sample_normal_tx spends 50 AIIR (< 100 AIIR in the UTXO).
        let tx = sample_normal_tx(spend, 7);
        validate_transaction(&tx, &utxo, 100).expect("should be valid");
    }

    #[test]
    fn tx_spending_more_than_inputs_is_rejected() {
        let (_, utxo) = setup();
        let genesis_cb = sample_coinbase(0);
        let spend = OutPoint {
            txid: genesis_cb.txid(),
            vout: 0,
        };
        // Craft a tx that outputs more than the input (100 AIIR).
        // We must re-sign after changing the output amount because
        // the original signature covers the old sighash (which
        // includes the outputs).
        let mut tx = sample_normal_tx(spend, 7);
        tx.outputs[0].amount = Amount::from_atomic(200 * 100_000_000);
        // Re-sign and re-mine PoW after changing outputs.
        let sighash = tx.sighash();
        tx.inputs[0].signature = test_private_key().sign_digest(sighash.as_bytes());
        crate::tx_pow::mine_tx_pow(&mut tx);
        let err = validate_transaction(&tx, &utxo, 100).unwrap_err();
        assert!(matches!(err, Error::OutputsExceedInputs { .. }));
    }

    #[test]
    fn tx_with_duplicate_input_is_rejected() {
        let (_, utxo) = setup();
        let genesis_cb = sample_coinbase(0);
        let spend = OutPoint {
            txid: genesis_cb.txid(),
            vout: 0,
        };
        let mut tx = sample_normal_tx(spend, 7);
        // Duplicate the single input, then re-mine PoW (structure changed).
        tx.inputs.push(tx.inputs[0].clone());
        crate::tx_pow::mine_tx_pow(&mut tx);
        let err = validate_transaction(&tx, &utxo, 100).unwrap_err();
        assert!(matches!(err, Error::DuplicateInput(_)));
    }

    #[test]
    fn tx_with_no_inputs_is_rejected() {
        let (_, utxo) = setup();
        let tx = bitaiir_types::Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut::p2pkh(Amount::from_atomic(1), [0; 20])],
            locktime: 0,
            pow_nonce: 0,
            pow_priority: 1,
        };
        let err = validate_transaction(&tx, &utxo, 100).unwrap_err();
        assert!(matches!(err, Error::NoInputs));
    }

    #[test]
    fn tx_with_no_outputs_is_rejected() {
        let (_, utxo) = setup();
        let genesis_cb = sample_coinbase(0);
        let spend = OutPoint {
            txid: genesis_cb.txid(),
            vout: 0,
        };
        let tx = bitaiir_types::Transaction {
            version: 1,
            inputs: vec![bitaiir_types::TxIn {
                prev_out: spend,
                signature: vec![0xaa; 64],
                pubkey: vec![0x02; 33],
                sequence: u32::MAX,
            }],
            outputs: vec![],
            locktime: 0,
            pow_nonce: 7,
            pow_priority: 1,
        };
        let err = validate_transaction(&tx, &utxo, 100).unwrap_err();
        assert!(matches!(err, Error::NoOutputs));
    }
}
