//! In-memory chain state: the set of known blocks plus the linear
//! main chain from genesis to tip.
//!
//! The [`Chain`] container stores full blocks by hash, tracks which
//! of those form the main chain, and records the cumulative
//! proof-of-work ("chain work") for every known block.  Chain work
//! is the fork-choice metric: when two chains disagree on the tip,
//! the one with greater cumulative work is the main chain.  Height
//! is not a sufficient metric — two chains can be equal height with
//! different cumulative work, and in general the "most work" chain
//! is always the consensus winner.
//!
//! `push` enforces *structural* invariants only:
//!
//! 1. The new block's `prev_block_hash` must equal the current tip.
//! 2. The new block's hash must not already be known to the chain.
//!
//! It does **not** check proof of work, merkle roots, transaction
//! validity, or the coinbase subsidy cap — callers are responsible
//! for running `validate_block` first.

use std::collections::HashMap;

use bitaiir_types::{Block, BlockHeader, Hash256};
use primitive_types::U256;

use crate::error::{Error, Result};
use crate::target::CompactTarget;

/// An in-memory blockchain.
///
/// The container owns every block it has ever seen (keyed by block
/// hash) and tracks which of those blocks form the main chain, from
/// genesis at index `0` to the current tip at the last index.
pub struct Chain {
    /// Every block this instance knows about, keyed by its block
    /// hash.
    blocks: HashMap<Hash256, Block>,
    /// The ordered list of block hashes that form the main chain.
    /// `main_chain[0]` is the genesis; `main_chain.last()` is the
    /// tip. Never empty by construction — every constructor stores
    /// at least one block.
    main_chain: Vec<Hash256>,
    /// Cumulative proof of work from the genesis block up to and
    /// including the keyed block.  Populated for every entry in
    /// `blocks`.  The genesis block is assigned zero work as an
    /// arbitrary baseline — only *differences* between chain-work
    /// values matter for fork choice, not the absolute magnitude.
    chain_work: HashMap<Hash256, U256>,
}

impl Chain {
    /// Create a new `Chain` rooted at the given genesis block.
    ///
    /// The genesis block is stored both in the block map and as the
    /// only entry in the main chain. Downstream code never observes
    /// an empty chain.  The genesis block is assigned zero chain
    /// work as a baseline — only *differences* between chain-work
    /// values are meaningful for fork choice.
    pub fn with_genesis(genesis: Block) -> Self {
        let hash = genesis.block_hash();
        let mut blocks = HashMap::new();
        blocks.insert(hash, genesis);
        let mut chain_work = HashMap::new();
        chain_work.insert(hash, U256::zero());
        Self {
            blocks,
            main_chain: vec![hash],
            chain_work,
        }
    }

    /// Return the height of the current tip. The genesis block is
    /// at height `0`.
    pub fn height(&self) -> u64 {
        // main_chain is non-empty by construction, so `len() - 1`
        // never underflows.
        (self.main_chain.len() - 1) as u64
    }

    /// Return the hash of the current tip of the main chain.
    pub fn tip(&self) -> Hash256 {
        *self
            .main_chain
            .last()
            .expect("chain is non-empty by construction")
    }

    /// Return a reference to the genesis block.
    pub fn genesis(&self) -> &Block {
        self.blocks
            .get(&self.main_chain[0])
            .expect("genesis hash is present by construction")
    }

    /// Look up a block by its hash. Returns `None` if the block is
    /// not known (neither in the main chain nor any side branch,
    /// since Phase 1b does not yet track side branches).
    pub fn block(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Whether a block with this hash has already been added to the
    /// chain (as the tip of the main chain or otherwise).
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.blocks.contains_key(hash)
    }

    /// Return the block at the given main-chain height. `height = 0`
    /// is the genesis.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        let index = usize::try_from(height).ok()?;
        let hash = self.main_chain.get(index)?;
        self.blocks.get(hash)
    }

    /// Shortcut for `block_at(height).map(|b| &b.header)`.
    pub fn header_at(&self, height: u64) -> Option<&BlockHeader> {
        Some(&self.block_at(height)?.header)
    }

    /// Number of blocks in the main chain, including the genesis.
    pub fn len(&self) -> usize {
        self.main_chain.len()
    }

    /// Always `false` — see [`Self::with_genesis`]. Exists so
    /// clippy's `len_without_is_empty` lint stays quiet.
    pub fn is_empty(&self) -> bool {
        // A Chain always contains at least the genesis block.
        false
    }

    /// Cumulative chain work at the current tip.
    ///
    /// This is the fork-choice metric: the main chain is always the
    /// one with the greatest cumulative work.  Two competing chains
    /// of equal height can have different `tip_work()` values — the
    /// one with more work wins.
    pub fn tip_work(&self) -> U256 {
        *self
            .chain_work
            .get(&self.tip())
            .expect("chain_work populated for every block on the main chain")
    }

    /// Cumulative chain work up to and including the block with the
    /// given hash.  Returns `None` if the hash is unknown.
    pub fn work_of(&self, hash: &Hash256) -> Option<U256> {
        self.chain_work.get(hash).copied()
    }

    /// Append a block to the main chain.
    ///
    /// Returns [`Error::ParentMismatch`] if `block.header.prev_block_hash`
    /// does not equal the current tip, or [`Error::DuplicateBlock`]
    /// if the block hash is already known.
    ///
    /// On success the block's cumulative chain work is recorded as
    /// `parent_work + work_of(block.header.bits)`.
    ///
    /// This method assumes the caller has already validated the
    /// block under consensus rules.
    pub fn push(&mut self, block: Block) -> Result<()> {
        let block_hash = block.block_hash();

        if self.blocks.contains_key(&block_hash) {
            return Err(Error::DuplicateBlock(block_hash));
        }

        let expected_parent = self.tip();
        if block.header.prev_block_hash != expected_parent {
            return Err(Error::ParentMismatch {
                expected: expected_parent,
                got: block.header.prev_block_hash,
            });
        }

        // Chain work extends from the parent's accumulated work by
        // the proof-of-work this block represents under its declared
        // difficulty.
        let parent_work = self
            .chain_work
            .get(&expected_parent)
            .copied()
            .expect("parent is on the main chain, chain_work populated");
        let block_work = CompactTarget::from_bits(block.header.bits).work();
        let new_work = parent_work.saturating_add(block_work);

        self.blocks.insert(block_hash, block);
        self.main_chain.push(block_hash);
        self.chain_work.insert(block_hash, new_work);

        Ok(())
    }
}

// Manual Debug impl because the derived one would dump every block
// in the chain, which is useless in test output.
impl core::fmt::Debug for Chain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chain")
            .field("height", &self.height())
            .field("tip", &self.tip())
            .field("known_blocks", &self.blocks.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::sample_block;
    use bitaiir_types::Hash256;

    #[test]
    fn fresh_chain_has_height_zero() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis);
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn fresh_chain_tip_equals_genesis_hash() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let expected_tip = genesis.block_hash();
        let chain = Chain::with_genesis(genesis);
        assert_eq!(chain.tip(), expected_tip);
    }

    #[test]
    fn fresh_chain_contains_genesis() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let hash = genesis.block_hash();
        let chain = Chain::with_genesis(genesis);
        assert!(chain.contains(&hash));
        assert!(chain.block(&hash).is_some());
        assert!(chain.block_at(0).is_some());
        assert!(chain.header_at(0).is_some());
    }

    #[test]
    fn push_extends_the_main_chain() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_hash = block_1.block_hash();
        chain.push(block_1).expect("push block 1");

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip(), block_1_hash);
        assert_eq!(chain.len(), 2);

        let block_2 = sample_block(block_1_hash, 2);
        let block_2_hash = block_2.block_hash();
        chain.push(block_2).expect("push block 2");

        assert_eq!(chain.height(), 2);
        assert_eq!(chain.tip(), block_2_hash);
        assert_eq!(chain.len(), 3);

        // Genesis is still reachable after extensions.
        assert_eq!(chain.block_at(0).unwrap().block_hash(), genesis_hash);
        assert_eq!(chain.block_at(1).unwrap().block_hash(), block_1_hash);
        assert_eq!(chain.block_at(2).unwrap().block_hash(), block_2_hash);
    }

    #[test]
    fn push_rejects_block_with_wrong_parent() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let mut chain = Chain::with_genesis(genesis);

        // Build a block that claims to extend a block that is not
        // our tip.
        let wrong_parent = Hash256::from_bytes([0xde; 32]);
        let orphan = sample_block(wrong_parent, 1);

        let err = chain.push(orphan).unwrap_err();
        match err {
            Error::ParentMismatch { expected, got } => {
                assert_eq!(expected, chain.tip());
                assert_eq!(got, wrong_parent);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Chain is unchanged.
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn push_rejects_duplicate_block() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_copy = block_1.clone();
        chain.push(block_1).expect("first push");

        let err = chain.push(block_1_copy).unwrap_err();
        assert!(matches!(err, Error::DuplicateBlock(_)));
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn block_at_beyond_tip_returns_none() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis);
        assert!(chain.block_at(1).is_none());
        assert!(chain.header_at(1).is_none());
    }

    #[test]
    fn debug_summary_is_not_the_full_chain() {
        // Primarily a smoke test of the manual Debug impl — it must
        // print height, tip, and a count, not the entire block map.
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis);
        let rendered = format!("{chain:?}");
        assert!(rendered.contains("height"));
        assert!(rendered.contains("tip"));
        assert!(rendered.contains("known_blocks"));
    }

    // --- chain_work / fork-choice metric tests -------------------------- //

    #[test]
    fn fresh_chain_tip_work_is_zero() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis);
        assert!(chain.tip_work().is_zero());
    }

    #[test]
    fn work_of_unknown_hash_is_none() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let chain = Chain::with_genesis(genesis);
        let random = Hash256::from_bytes([0xab; 32]);
        assert!(chain.work_of(&random).is_none());
    }

    #[test]
    fn push_accumulates_chain_work() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let genesis_bits = genesis.header.bits;
        let mut chain = Chain::with_genesis(genesis);

        // Baseline.
        assert!(chain.tip_work().is_zero());

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_hash = block_1.block_hash();
        let block_1_bits = block_1.header.bits;
        chain.push(block_1).expect("push block 1");

        // After one push, tip work must equal a single block's
        // worth of work under its bits.
        let expected_after_1 = CompactTarget::from_bits(block_1_bits).work();
        assert_eq!(chain.tip_work(), expected_after_1);
        assert_eq!(chain.work_of(&block_1_hash).unwrap(), expected_after_1);

        // Genesis keeps zero work — we didn't touch it.
        assert!(chain.work_of(&genesis_hash).unwrap().is_zero());
        // (Just exercises `genesis_bits` so the variable isn't dead.)
        assert_eq!(genesis_bits, chain.genesis().header.bits);

        let block_2 = sample_block(block_1_hash, 2);
        let block_2_hash = block_2.block_hash();
        let block_2_bits = block_2.header.bits;
        chain.push(block_2).expect("push block 2");

        // Two blocks: cumulative work is the sum of the two
        // individual block-work values.
        let expected_after_2 = CompactTarget::from_bits(block_1_bits).work()
            + CompactTarget::from_bits(block_2_bits).work();
        assert_eq!(chain.tip_work(), expected_after_2);
        assert_eq!(chain.work_of(&block_2_hash).unwrap(), expected_after_2);
    }

    #[test]
    fn rejected_push_does_not_change_work() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        chain.push(block_1).expect("push block 1");
        let work_before = chain.tip_work();

        // Wrong parent → rejected → chain state unchanged, including
        // chain_work.
        let orphan = sample_block(Hash256::from_bytes([0xde; 32]), 2);
        assert!(chain.push(orphan).is_err());
        assert_eq!(chain.tip_work(), work_before);
    }
}
