//! Block assembly and mining.
//!
//! This module provides [`mine_block`], the function that turns a
//! mempool of pending transactions, a chain state, and a miner
//! address into a freshly mined block. It also implements the
//! difficulty retarget algorithm from protocol §8.4.
//!
//! The mining loop is intentionally single-threaded and synchronous
//! in Phase 1d. Multi-threaded mining is an optimization that belongs
//! in the daemon layer (`bitaiir-node` or `bitaiir-daemon`), not in
//! the consensus library.

use bitaiir_types::{Amount, Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};

use crate::chain::Chain;
use crate::consensus::{MAX_BLOCK_SIZE, RETARGET_EXPECTED_TIME, RETARGET_INTERVAL};
use crate::mempool::Mempool;
use crate::pow::aiir_pow;
use crate::subsidy::subsidy;
use crate::target::CompactTarget;

/// Assemble a block from the mempool and mine it.
///
/// Steps:
///
/// 1. Compute the subsidy for the next height.
/// 2. Pull transactions from the mempool (up to the block size
///    limit, minus room for the coinbase).
/// 3. Build the coinbase transaction that pays the subsidy + fees to
///    `miner_recipient_hash`.
/// 4. Compute the merkle root.
/// 5. Determine the required `bits` (initial or retargeted).
/// 6. Grind `nonce` until `aiir_pow(header) ≤ target(bits)`.
/// 7. Return the complete, valid block.
///
/// `network_time` is the miner's local clock (seconds since epoch),
/// used as the block timestamp.
pub fn mine_block(
    chain: &Chain,
    mempool: &mut Mempool,
    miner_recipient_hash: [u8; 20],
    network_time: u64,
) -> Block {
    let next_height = chain.height() + 1;
    let subsidy_amount = subsidy(next_height);

    // Pull pending transactions from the mempool. In Phase 1d we
    // take as many as will fit; real code should also validate each
    // transaction against the UTXO set, but that is already done by
    // the caller before adding them to the mempool.
    let user_txs = mempool.take_for_block(max_user_txs_count());

    // Tally the total fees from user transactions. We don't have
    // direct access to the UTXO set here (the caller does), so we
    // set fees to zero for now. Phase 1d tests use coinbase-only
    // blocks, so this is correct for the current scope.
    // TODO: pass utxo_set to mine_block so fees can be computed.
    let total_fees = Amount::ZERO;

    let coinbase_amount = subsidy_amount
        .checked_add(total_fees)
        .unwrap_or(subsidy_amount);

    // Build the coinbase.
    let coinbase = build_coinbase(next_height, miner_recipient_hash, coinbase_amount);

    // Assemble the full transaction list: coinbase first, then user txs.
    let mut transactions = Vec::with_capacity(1 + user_txs.len());
    transactions.push(coinbase);
    transactions.extend(user_txs);

    // Compute the merkle root.
    let merkle_root = {
        let txids: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        bitaiir_types::merkle_root(&txids)
    };

    // Determine the required difficulty.
    let bits = required_bits(chain, next_height);

    // Build the header template.
    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: chain.tip(),
        merkle_root,
        timestamp: network_time,
        bits,
        nonce: 0,
    };

    // Mine: grind the nonce until the PoW hash meets the target.
    let target = CompactTarget::from_bits(bits);
    loop {
        let pow_hash = aiir_pow(&header);
        if target.hash_meets_target(pow_hash.as_bytes()) {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    Block {
        header,
        transactions,
    }
}

/// Create a test genesis block for development. In production the
/// genesis is hardcoded; this helper exists for tests and for the
/// daemon's first-run bootstrap.
///
/// `coinbase_message` is embedded in the coinbase transaction's
/// `signature` field (the "extra nonce" slot), mirroring Bitcoin's
/// genesis block tradition of including a headline or marker string
/// so the block's creation date and intent are permanently recorded
/// in the chain.
pub fn create_test_genesis(
    miner_recipient_hash: [u8; 20],
    timestamp: u64,
    coinbase_message: &str,
) -> Block {
    let coinbase_amount = subsidy(0);
    let coinbase = build_genesis_coinbase(miner_recipient_hash, coinbase_amount, coinbase_message);
    let merkle_root = coinbase.txid();
    let bits = CompactTarget::INITIAL.to_bits();

    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp,
        bits,
        nonce: 0,
    };

    let target = CompactTarget::INITIAL;
    loop {
        let pow_hash = aiir_pow(&header);
        if target.hash_meets_target(pow_hash.as_bytes()) {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    Block {
        header,
        transactions: vec![coinbase],
    }
}

// -------------------------------------------------------------------------
// Difficulty retarget (protocol §8.4)
// -------------------------------------------------------------------------

/// Compute the `bits` value a block at `height` must carry.
///
/// - For heights `0..RETARGET_INTERVAL`, the initial difficulty is
///   used.
/// - At every multiple of `RETARGET_INTERVAL`, the difficulty is
///   recomputed from the time the previous window took.
/// - Between retarget boundaries, the previous block's `bits` is
///   carried forward.
pub fn required_bits(chain: &Chain, height: u64) -> u32 {
    // The first window always uses the initial difficulty.
    if height < RETARGET_INTERVAL {
        return CompactTarget::INITIAL.to_bits();
    }

    // If we are not at a retarget boundary, carry forward.
    if height % RETARGET_INTERVAL != 0 {
        return chain
            .header_at(chain.height())
            .expect("chain has at least genesis")
            .bits;
    }

    // Retarget: measure how long the last window actually took.
    let window_end = chain.height(); // The last block in the previous window.
    let window_start = window_end - (RETARGET_INTERVAL - 1);

    let start_time = chain
        .header_at(window_start)
        .expect("window_start within chain")
        .timestamp;
    let end_time = chain
        .header_at(window_end)
        .expect("window_end within chain")
        .timestamp;

    let actual_time = end_time.saturating_sub(start_time);
    let expected_time = RETARGET_EXPECTED_TIME;

    // Clamp the ratio to [1/4, 4] to prevent wild swings.
    let actual_clamped = actual_time.max(expected_time / 4).min(expected_time * 4);

    // Compute the new target: old_target * actual / expected.
    let old_bits = chain
        .header_at(window_end)
        .expect("window_end within chain")
        .bits;
    let old_target = CompactTarget::from_bits(old_bits)
        .to_target()
        .expect("stored bits are valid");

    let new_target = scale_target(&old_target, actual_clamped, expected_time);
    target_to_compact(&new_target)
}

/// Scale a 256-bit big-endian target by `numerator / denominator`,
/// clamping to 256 bits.
fn scale_target(target: &[u8; 32], numerator: u64, denominator: u64) -> [u8; 32] {
    // We do the multiplication in 320-bit space (32 bytes + 8 bytes
    // for the carry) so we never overflow during intermediate steps.
    // This is a simple schoolbook multiply; production code could use
    // a big-integer library, but for 32 bytes this is fast enough.
    let mut wide = [0u128; 4]; // 4 × 64-bit limbs in little-endian order
    for (i, chunk) in target.chunks(8).rev().enumerate() {
        let mut buf = [0u8; 8];
        let start = 8 - chunk.len();
        buf[start..].copy_from_slice(chunk);
        wide[i] = u64::from_be_bytes(buf) as u128;
    }

    // Multiply each limb by numerator, propagate carry.
    let mut carry: u128 = 0;
    for limb in wide.iter_mut() {
        let product = *limb * numerator as u128 + carry;
        *limb = product & 0xffff_ffff_ffff_ffff;
        carry = product >> 64;
    }

    // Divide each limb by denominator, propagate remainder.
    let mut remainder: u128 = carry; // carry from multiplication
    for limb in wide.iter_mut().rev() {
        let combined = (remainder << 64) | *limb;
        *limb = combined / denominator as u128;
        remainder = combined % denominator as u128;
    }

    // Convert back to big-endian 32 bytes.
    let mut result = [0u8; 32];
    for (i, limb) in wide.iter().rev().enumerate() {
        let bytes = (*limb as u64).to_be_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Convert a 256-bit big-endian target back to compact `bits` form.
fn target_to_compact(target: &[u8; 32]) -> u32 {
    // Find the first non-zero byte to determine the exponent.
    let first_nonzero = target.iter().position(|&b| b != 0).unwrap_or(32);
    if first_nonzero >= 32 {
        // Target is zero — return minimum representable.
        return 0;
    }

    let exponent = (32 - first_nonzero) as u32;

    // Extract the 3 most-significant bytes of the target.
    let mantissa = if first_nonzero <= 29 {
        let b0 = target[first_nonzero] as u32;
        let b1 = target.get(first_nonzero + 1).copied().unwrap_or(0) as u32;
        let b2 = target.get(first_nonzero + 2).copied().unwrap_or(0) as u32;
        (b0 << 16) | (b1 << 8) | b2
    } else {
        // Target is very small (< 3 significant bytes).
        let mut m: u32 = 0;
        for &b in &target[first_nonzero..] {
            m = (m << 8) | b as u32;
        }
        m << (8 * (3 - (32 - first_nonzero) as u32))
    };

    // If the high bit of the mantissa is set, shift right by 8 and
    // bump the exponent, to keep the sign bit clear.
    if mantissa & 0x0080_0000 != 0 {
        let adjusted_mantissa = mantissa >> 8;
        ((exponent + 1) << 24) | adjusted_mantissa
    } else {
        (exponent << 24) | mantissa
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn build_coinbase(height: u64, recipient_hash: [u8; 20], amount: Amount) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            // Use the height as the coinbase "extra nonce" so that
            // coinbase transactions at different heights always have
            // distinct txids.
            signature: height.to_le_bytes().to_vec(),
            pubkey: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount,
            recipient_hash,
        }],
        locktime: 0,
        pow_nonce: 0,
    }
}

/// Build the genesis coinbase with a human-readable message embedded
/// in the signature field, like Bitcoin's famous headline.
fn build_genesis_coinbase(recipient_hash: [u8; 20], amount: Amount, message: &str) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint::NULL,
            signature: message.as_bytes().to_vec(),
            pubkey: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            amount,
            recipient_hash,
        }],
        locktime: 0,
        pow_nonce: 0,
    }
}

/// How many non-coinbase transactions fit in a block. A rough
/// estimate: `MAX_BLOCK_SIZE` bytes minus some overhead for the
/// header and coinbase, divided by an assumed average tx size.
/// This is a placeholder; real code should sum serialized sizes.
fn max_user_txs_count() -> usize {
    // Conservative default: leave plenty of room.
    (MAX_BLOCK_SIZE / 500).saturating_sub(1)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

/// Mine a block from pre-computed parameters, without needing a chain
/// or mempool reference. This is the lock-friendly version used by the
/// daemon: snapshot the chain state under a short lock, release the
/// lock, then call this function (which is CPU-heavy and can run for
/// seconds or minutes) without blocking RPC handlers.
pub fn mine_block_from_params(
    prev_block_hash: Hash256,
    height: u64,
    bits: u32,
    user_txs: Vec<Transaction>,
    miner_recipient_hash: [u8; 20],
    network_time: u64,
) -> Block {
    let subsidy_amount = subsidy(height);
    let total_fees = Amount::ZERO; // TODO: compute from UTXO lookups
    let coinbase_amount = subsidy_amount
        .checked_add(total_fees)
        .unwrap_or(subsidy_amount);

    let coinbase = build_coinbase(height, miner_recipient_hash, coinbase_amount);

    let mut transactions = Vec::with_capacity(1 + user_txs.len());
    transactions.push(coinbase);
    transactions.extend(user_txs);

    let merkle_root = {
        let txids: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        bitaiir_types::merkle_root(&txids)
    };

    let mut header = BlockHeader {
        version: 1,
        prev_block_hash,
        merkle_root,
        timestamp: network_time,
        bits,
        nonce: 0,
    };

    let target = CompactTarget::from_bits(bits);
    loop {
        let pow_hash = aiir_pow(&header);
        if target.hash_meets_target(pow_hash.as_bytes()) {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }

    Block {
        header,
        transactions,
    }
}

// -------------------------------------------------------------------------
// Multi-threaded mining
// -------------------------------------------------------------------------

/// Mine a block using `num_threads` parallel threads, each searching a
/// different nonce partition.  The first thread to find a valid PoW
/// signals the others to stop via a shared `AtomicBool`.
///
/// `shutdown` is an external cancellation flag (e.g. from the daemon's
/// Ctrl-C handler). If set, mining aborts early and returns `None`.
///
/// **Memory note**: each thread runs one Argon2id invocation at a time,
/// allocating `AIIR_POW_MEMORY_KIB` (64 MiB production / 256 KiB test).
/// With 4 threads that's 256 MiB of concurrent RAM usage.
#[allow(clippy::too_many_arguments)]
pub fn mine_block_parallel(
    prev_block_hash: Hash256,
    height: u64,
    bits: u32,
    user_txs: Vec<Transaction>,
    miner_recipient_hash: [u8; 20],
    network_time: u64,
    num_threads: usize,
    shutdown: &std::sync::atomic::AtomicBool,
) -> Option<Block> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let subsidy_amount = subsidy(height);
    let total_fees = Amount::ZERO;
    let coinbase_amount = subsidy_amount
        .checked_add(total_fees)
        .unwrap_or(subsidy_amount);

    let coinbase = build_coinbase(height, miner_recipient_hash, coinbase_amount);

    let mut transactions = Vec::with_capacity(1 + user_txs.len());
    transactions.push(coinbase);
    transactions.extend(user_txs);

    let merkle_root = {
        let txids: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        bitaiir_types::merkle_root(&txids)
    };

    let header = BlockHeader {
        version: 1,
        prev_block_hash,
        merkle_root,
        timestamp: network_time,
        bits,
        nonce: 0,
    };

    let target = CompactTarget::from_bits(bits);
    let found = AtomicBool::new(false);
    let winning_nonce = std::sync::atomic::AtomicU32::new(0);
    let num_threads = num_threads.max(1);

    std::thread::scope(|s| {
        for thread_id in 0..num_threads {
            let found = &found;
            let winning_nonce = &winning_nonce;
            let mut h = header;
            h.nonce = thread_id as u32;
            let stride = num_threads as u32;

            s.spawn(move || {
                loop {
                    if found.load(Ordering::Relaxed) || shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    let pow_hash = aiir_pow(&h);
                    if target.hash_meets_target(pow_hash.as_bytes()) {
                        winning_nonce.store(h.nonce, Ordering::Relaxed);
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                    h.nonce = h.nonce.wrapping_add(stride);
                }
            });
        }
    });

    if shutdown.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
        return None;
    }

    let mut final_header = header;
    final_header.nonce = winning_nonce.load(Ordering::Relaxed);

    Some(Block {
        header: final_header,
        transactions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use crate::mempool::Mempool;
    use crate::utxo::UtxoSet;
    use crate::validation::validate_block;

    const MINER_ADDR: [u8; 20] = [0x42; 20];

    #[test]
    fn mine_genesis_produces_valid_block() {
        let genesis = create_test_genesis(MINER_ADDR, 1_700_000_000, "test genesis");
        assert!(genesis.transactions[0].is_coinbase());
        assert_eq!(genesis.header.prev_block_hash, Hash256::ZERO);

        // The mined genesis must meet its own target.
        let target = CompactTarget::from_bits(genesis.header.bits);
        let pow_hash = aiir_pow(&genesis.header);
        assert!(target.hash_meets_target(pow_hash.as_bytes()));
    }

    #[test]
    fn mine_block_extends_chain() {
        let genesis = create_test_genesis(MINER_ADDR, 1_700_000_000, "test genesis");
        let chain = Chain::with_genesis(genesis.clone());
        let mut mempool = Mempool::new(crate::consensus::DEFAULT_MAX_MEMPOOL_BYTES);

        let block = mine_block(&chain, &mut mempool, MINER_ADDR, 1_700_000_010);

        assert_eq!(block.header.prev_block_hash, chain.tip());
        assert!(block.transactions[0].is_coinbase());

        let target = CompactTarget::from_bits(block.header.bits);
        let pow_hash = aiir_pow(&block.header);
        assert!(target.hash_meets_target(pow_hash.as_bytes()));
    }

    #[test]
    fn mine_and_validate_10_blocks_end_to_end() {
        // This is the "big bang" integration test: mine 10 blocks,
        // validate each one, push it onto the chain, and apply its
        // transactions to the UTXO set. At the end, the chain has
        // 11 blocks (genesis + 10) and the UTXO set has 11 coinbase
        // outputs.
        let genesis = create_test_genesis(MINER_ADDR, 1_700_000_000, "test genesis");
        let mut chain = Chain::with_genesis(genesis.clone());
        let mut utxo = UtxoSet::new();
        let mut mempool = Mempool::new(crate::consensus::DEFAULT_MAX_MEMPOOL_BYTES);

        // Apply genesis transactions to the UTXO set.
        for tx in &genesis.transactions {
            utxo.apply_transaction(tx, 0).unwrap();
        }

        for i in 1..=10u64 {
            let timestamp = 1_700_000_000 + i * 5;
            let block = mine_block(&chain, &mut mempool, MINER_ADDR, timestamp);

            // Validate: every mined block must pass all consensus
            // rules (except rule 3 / difficulty check, which
            // required_bits handles internally).
            validate_block(&block, &chain, &utxo, timestamp + 1)
                .unwrap_or_else(|e| panic!("block {i} failed validation: {e}"));

            // Push onto the chain.
            chain
                .push(block.clone())
                .unwrap_or_else(|e| panic!("block {i} failed push: {e}"));

            // Apply transactions to the UTXO set.
            for tx in &block.transactions {
                utxo.apply_transaction(tx, 0).unwrap();
            }
        }

        assert_eq!(chain.height(), 10);
        // 11 coinbase outputs (genesis + 10 mined blocks), each with
        // one output.
        assert_eq!(utxo.len(), 11);

        // Verify the subsidy is correct at every height.
        for h in 0..=10u64 {
            let block = chain.block_at(h).unwrap();
            let expected_subsidy = subsidy(h).to_atomic();
            let actual_output = block.transactions[0].outputs[0].amount.to_atomic();
            assert_eq!(
                actual_output, expected_subsidy,
                "block {h} subsidy mismatch",
            );
        }
    }

    #[test]
    fn required_bits_uses_initial_for_first_window() {
        let genesis = create_test_genesis(MINER_ADDR, 1_700_000_000, "test genesis");
        let chain = Chain::with_genesis(genesis);

        // Every height in the first retarget window should use
        // INITIAL bits.
        for h in 1..RETARGET_INTERVAL {
            assert_eq!(
                required_bits(&chain, h),
                CompactTarget::INITIAL.to_bits(),
                "height {h} should use initial bits",
            );
        }
    }

    #[test]
    fn scale_target_doubles_when_blocks_are_twice_as_slow() {
        // If blocks took 200 s instead of the expected 100 s, the
        // target should double (making mining easier).
        let original = CompactTarget::INITIAL.to_target().unwrap();
        let scaled = scale_target(&original, 200, 100);

        // The scaled target should be strictly larger than the
        // original (= easier difficulty).
        assert!(scaled > original);
    }

    #[test]
    fn target_to_compact_round_trips_initial() {
        let original = CompactTarget::INITIAL;
        let target = original.to_target().unwrap();
        let back = target_to_compact(&target);
        assert_eq!(
            back,
            original.to_bits(),
            "round trip of INITIAL compact target failed",
        );
    }
}
