//! In-memory chain state: the set of known blocks plus the linear
//! main chain from genesis to tip.
//!
//! Phase 1b is deliberately minimal. The [`Chain`] container stores
//! full blocks by hash and tracks a single linear main chain. It
//! supports the happy-path append (`push`) and read-only queries
//! (`tip`, `height`, `block_at`, `header_at`, `block`, `contains`),
//! and nothing else. Reorgs, fork choice, orphan tracking, and
//! consensus validation all belong to later phases.
//!
//! `push` enforces *structural* invariants only:
//!
//! 1. The new block's `prev_block_hash` must equal the current tip.
//! 2. The new block's hash must not already be known to the chain.
//!
//! It does **not** check proof of work, merkle roots, transaction
//! validity, or the coinbase subsidy cap — Phase 1c will add a
//! `validate_block` step that callers must run before handing a
//! block to `push`.

use std::collections::HashMap;

use bitaiir_types::{Block, BlockHeader, Hash256};

use crate::error::{Error, Result};

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
}

impl Chain {
    /// Create a new `Chain` rooted at the given genesis block.
    ///
    /// The genesis block is stored both in the block map and as the
    /// only entry in the main chain. Downstream code never observes
    /// an empty chain.
    pub fn with_genesis(genesis: Block) -> Self {
        let hash = genesis.block_hash();
        let mut blocks = HashMap::new();
        blocks.insert(hash, genesis);
        Self {
            blocks,
            main_chain: vec![hash],
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

    /// Append a block to the main chain.
    ///
    /// Returns [`Error::ParentMismatch`] if `block.header.prev_block_hash`
    /// does not equal the current tip, or [`Error::DuplicateBlock`]
    /// if the block hash is already known.
    ///
    /// This method assumes the caller has already validated the
    /// block under consensus rules. Phase 1b performs no such
    /// checks; a later phase will.
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

        self.blocks.insert(block_hash, block);
        self.main_chain.push(block_hash);

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
}
