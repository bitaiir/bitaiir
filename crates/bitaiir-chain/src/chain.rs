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

use std::collections::{HashMap, HashSet};

use bitaiir_types::{Block, BlockHeader, Hash256};
use primitive_types::U256;

use crate::error::{Error, Result};
use crate::target::CompactTarget;

/// The result of offering a block to [`Chain::accept_block`].
///
/// Chain state mutations happen atomically for `Connected` (main
/// chain advances by one).  For `Reorg`, the **block index and
/// `chain_work` are updated, but `main_chain` is left alone** so
/// the caller can drive the reorg block-by-block: tear down the
/// old chain's UTXO state, then validate + apply + extend the
/// new chain's blocks one at a time.  See the module docs for the
/// full orchestration pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// Block extended the current main chain.  Caller should apply
    /// UTXOs, persist, and drain mempool as usual.
    Connected,
    /// Block accepted as a side chain whose cumulative work does not
    /// exceed the current main chain.  Stored in the block index so
    /// a later block on the same branch can still cause a reorg, but
    /// no main-chain mutation has happened.
    SideChain,
    /// Accepting this block makes its branch the most-work chain.
    /// `main_chain` has not been mutated yet — the caller is
    /// expected to:
    ///
    /// 1. Undo every hash in `undone` against the UTXO set (in
    ///    the given order — newest-first), re-inserting the
    ///    non-coinbase txs back into the mempool.
    /// 2. Call [`Chain::rollback_main_chain_to`]`(common_ancestor)`.
    /// 3. For every hash in `applied` (oldest-first): validate the
    ///    block against the current chain + UTXO state, apply it
    ///    (using [`crate::UtxoSet::apply_block_with_undo`]),
    ///    persist it, drain its txs from the mempool, and call
    ///    [`Chain::extend_main_chain`]`(hash)`.
    Reorg {
        /// The last block common to the old and new chains.
        common_ancestor: Hash256,
        /// Blocks on the current main chain that must be undone,
        /// in the order they must be undone (tip-first, walking
        /// back towards `common_ancestor`).
        undone: Vec<Hash256>,
        /// Blocks on the new chain that must be applied, in the
        /// order they must be applied (oldest-first, starting from
        /// `common_ancestor.child` up to the new tip).
        applied: Vec<Hash256>,
    },
    /// The block was already in the chain index.  No-op.
    Duplicate,
}

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

    /// Height of `hash` if it is a block on the current main chain.
    /// Returns `None` for side-chain blocks and for blocks not in
    /// the index.  Linear in main-chain length — fine for sync-time
    /// lookups, not meant for hot paths.
    pub fn height_of(&self, hash: &Hash256) -> Option<u64> {
        self.main_chain
            .iter()
            .position(|h| h == hash)
            .map(|i| i as u64)
    }

    /// Take a cheap snapshot of the current main-chain hash list.
    /// Paired with [`Self::restore_main_chain`], this lets the reorg
    /// orchestrator save the pre-reorg main chain before mutating
    /// and restore it atomically if anything fails mid-reorg.
    ///
    /// Only the `main_chain` `Vec<Hash256>` is cloned — the block
    /// index and `chain_work` map are untouched, so snapshot +
    /// restore is O(chain height), not O(known blocks).
    pub fn main_chain_snapshot(&self) -> Vec<Hash256> {
        self.main_chain.clone()
    }

    /// Restore the main-chain pointer from a previous
    /// [`Self::main_chain_snapshot`] result.  Every hash in the
    /// snapshot must still be present in the block index — if the
    /// caller passes a snapshot taken from a different chain the
    /// `debug_assert!` catches the bug in debug builds.
    pub fn restore_main_chain(&mut self, snapshot: Vec<Hash256>) {
        debug_assert!(
            snapshot.iter().all(|h| self.blocks.contains_key(h)),
            "restore_main_chain: snapshot contains hashes absent from the block index",
        );
        self.main_chain = snapshot;
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

    /// Offer a block to the chain, possibly triggering a reorg.
    ///
    /// This is the general-purpose acceptance entry point.  It
    /// handles three cases:
    ///
    /// - The block extends the current tip → accepted, main chain
    ///   advances, returns [`AcceptOutcome::Connected`].
    /// - The block's parent is in the index but isn't the tip, and
    ///   this branch now has **strictly more** cumulative work than
    ///   the current main chain → returns [`AcceptOutcome::Reorg`]
    ///   with the paths to undo/apply.  `main_chain` is **not**
    ///   mutated; the caller drives the reorg block-by-block.
    /// - The block's parent is in the index but the branch has
    ///   equal-or-less work → stored in the index as a side chain,
    ///   returns [`AcceptOutcome::SideChain`].
    ///
    /// Error returns:
    /// - [`Error::UnknownParent`] if the block's parent is not in
    ///   the index at all (genuine orphan — caller may choose to
    ///   stash and retry).
    ///
    /// `accept_block` assumes the caller has validated PoW, merkle
    /// root, etc.  For `Connected` this is the same contract as
    /// [`Self::push`].  For `Reorg`, **per-block consensus
    /// validation happens during the caller's apply loop**, because
    /// the UTXO state that `validate_block` runs against isn't yet
    /// at the branch's position.
    pub fn accept_block(&mut self, block: Block) -> Result<AcceptOutcome> {
        let block_hash = block.block_hash();

        if self.blocks.contains_key(&block_hash) {
            return Ok(AcceptOutcome::Duplicate);
        }

        let parent_hash = block.header.prev_block_hash;
        let parent_work = self
            .chain_work
            .get(&parent_hash)
            .copied()
            .ok_or(Error::UnknownParent(parent_hash))?;

        // Record the block and its cumulative work.  Whether or not
        // it becomes part of the main chain, the index always knows
        // about every block it's ever seen.
        let block_work = CompactTarget::from_bits(block.header.bits).work();
        let new_work = parent_work.saturating_add(block_work);
        self.blocks.insert(block_hash, block);
        self.chain_work.insert(block_hash, new_work);

        let current_tip = self.tip();
        let current_tip_work = *self
            .chain_work
            .get(&current_tip)
            .expect("chain_work populated for every block on the main chain");

        // Simple extension: parent is our current tip.
        if parent_hash == current_tip {
            self.main_chain.push(block_hash);
            return Ok(AcceptOutcome::Connected);
        }

        // Branch has equal-or-less work than the current main chain.
        // Fork-choice keeps the current main chain; block stays
        // indexed for a potential future reorg.
        if new_work <= current_tip_work {
            return Ok(AcceptOutcome::SideChain);
        }

        // Branch has more work.  Compute the reorg paths but leave
        // `main_chain` alone — the caller drives the transition.
        let (common_ancestor, applied) = self.path_from_ancestor(block_hash)?;
        let ancestor_idx = self
            .main_chain
            .iter()
            .position(|h| *h == common_ancestor)
            .expect("common ancestor must lie on the main chain");
        let undone: Vec<Hash256> = self.main_chain[ancestor_idx + 1..]
            .iter()
            .rev()
            .copied()
            .collect();

        Ok(AcceptOutcome::Reorg {
            common_ancestor,
            undone,
            applied,
        })
    }

    /// Truncate the main chain so its new tip is the given hash.
    /// Used by the reorg orchestrator *after* the old chain's UTXO
    /// state has been undone: from that point on, `tip()` returns
    /// the common ancestor, and subsequent `extend_main_chain`
    /// calls walk the new branch forward one block at a time.
    ///
    /// Panics if `ancestor` is not on the current main chain.
    pub fn rollback_main_chain_to(&mut self, ancestor: Hash256) {
        let idx = self
            .main_chain
            .iter()
            .position(|h| *h == ancestor)
            .expect("rollback target must be on the main chain");
        self.main_chain.truncate(idx + 1);
    }

    /// Extend the main chain by one block whose hash is already in
    /// the index (typically placed there by a prior `accept_block`
    /// call).  The block must extend the current tip — otherwise
    /// [`Error::ParentMismatch`] is returned and the chain is left
    /// untouched.  Used by the reorg orchestrator to advance the
    /// main chain one step at a time while walking the new branch.
    pub fn extend_main_chain(&mut self, block_hash: Hash256) -> Result<()> {
        let block = self
            .blocks
            .get(&block_hash)
            .ok_or(Error::UnknownParent(block_hash))?;
        let expected_parent = self.tip();
        if block.header.prev_block_hash != expected_parent {
            return Err(Error::ParentMismatch {
                expected: expected_parent,
                got: block.header.prev_block_hash,
            });
        }
        self.main_chain.push(block_hash);
        Ok(())
    }

    /// Walk back from `tip` through the block index collecting
    /// hashes until hitting a block that is on the current main
    /// chain — that's the common ancestor.  Returns `(common
    /// ancestor hash, path)` where `path` is ordered
    /// oldest-first (ancestor-child → `tip`) ready to feed
    /// directly into `AcceptOutcome::Reorg::applied`.
    fn path_from_ancestor(&self, tip: Hash256) -> Result<(Hash256, Vec<Hash256>)> {
        let main_set: HashSet<Hash256> = self.main_chain.iter().copied().collect();
        let mut path: Vec<Hash256> = Vec::new();
        let mut cur = tip;
        loop {
            if main_set.contains(&cur) {
                path.reverse();
                return Ok((cur, path));
            }
            path.push(cur);
            let block = self
                .blocks
                .get(&cur)
                .ok_or(Error::BrokenChainLink { tip, at: cur })?;
            cur = block.header.prev_block_hash;
        }
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

    // --- accept_block / fork-choice tests ------------------------------- //

    /// Build a block with a specific bits field, so tests can control
    /// per-block work contribution.  `sample_block` uses the default
    /// bits, so everything comes out equal — we need non-uniform
    /// bits to simulate "this branch has more work".
    fn sample_block_with_bits(prev: Hash256, nonce: u32, bits: u32) -> bitaiir_types::Block {
        use crate::test_util::sample_coinbase;
        use bitaiir_types::{Block, BlockHeader, merkle_root};

        let coinbase = sample_coinbase(nonce as u64);
        let merkle = merkle_root(&[coinbase.txid()]);
        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: prev,
                merkle_root: merkle,
                timestamp: 0,
                bits,
                nonce,
            },
            transactions: vec![coinbase],
        }
    }

    #[test]
    fn accept_block_extending_tip_returns_connected() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_hash = block_1.block_hash();
        let outcome = chain.accept_block(block_1).expect("accept");
        assert_eq!(outcome, AcceptOutcome::Connected);
        assert_eq!(chain.tip(), block_1_hash);
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn accept_block_duplicate_is_idempotent_noop() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_copy = block_1.clone();
        chain.accept_block(block_1).expect("first accept");
        let height_before = chain.height();
        let tip_before = chain.tip();

        let outcome = chain.accept_block(block_1_copy).expect("duplicate accept");
        assert_eq!(outcome, AcceptOutcome::Duplicate);
        // No mutation.
        assert_eq!(chain.height(), height_before);
        assert_eq!(chain.tip(), tip_before);
    }

    #[test]
    fn accept_block_with_unknown_parent_errors() {
        let genesis = sample_block(Hash256::ZERO, 0);
        let mut chain = Chain::with_genesis(genesis);

        let orphan = sample_block(Hash256::from_bytes([0xde; 32]), 1);
        let err = chain.accept_block(orphan).unwrap_err();
        assert!(matches!(err, Error::UnknownParent(_)));
    }

    #[test]
    fn accept_block_sibling_with_equal_work_is_side_chain() {
        // Two siblings at height 1 (both extending genesis).  First
        // one takes the main chain; second arrives as a side branch
        // with identical work.  Fork choice keeps the incumbent
        // (strictly greater work required to reorg), so the second
        // block is accepted as `SideChain`.
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_a = sample_block(genesis_hash, 1);
        let block_a_hash = block_a.block_hash();
        chain.accept_block(block_a).expect("main");
        assert_eq!(chain.tip(), block_a_hash);

        // Nonce 2 so we get a different block_hash under the same
        // bits → same work contribution, same height, competing tip.
        let block_b = sample_block(genesis_hash, 2);
        let outcome = chain.accept_block(block_b).expect("sibling");
        assert_eq!(outcome, AcceptOutcome::SideChain);
        // Main chain unchanged.
        assert_eq!(chain.tip(), block_a_hash);
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn accept_block_reorg_when_branch_overtakes_on_work() {
        // Scenario: main chain has block A at height 1 under the
        // initial (easy) bits.  A competing branch at height 1 has
        // block B under harder bits (more work).  B's single block
        // wins immediately because its individual work beats A's.
        //
        // `sample_block` uses `CompactTarget::INITIAL.to_bits()`
        // (0x2000ffff) which contributes ~257 work per block.  We
        // use 0x1f00ffff on the competing branch, which is a
        // strictly harder target and contributes much more work.
        let genesis_bits = CompactTarget::INITIAL.to_bits();
        let genesis = sample_block_with_bits(Hash256::ZERO, 0, genesis_bits);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_a = sample_block_with_bits(genesis_hash, 1, genesis_bits);
        let _block_a_hash = block_a.block_hash();
        chain.accept_block(block_a).expect("main a");

        // Competing block B with a harder target at the same height.
        let hard_bits = 0x1f00_ffff;
        let block_b = sample_block_with_bits(genesis_hash, 2, hard_bits);
        let block_b_hash = block_b.block_hash();
        let outcome = chain.accept_block(block_b).expect("branch b");
        match outcome {
            AcceptOutcome::Reorg {
                common_ancestor,
                undone,
                applied,
            } => {
                assert_eq!(common_ancestor, genesis_hash);
                assert_eq!(undone.len(), 1);
                assert_eq!(applied, vec![block_b_hash]);
            }
            other => panic!("expected Reorg, got {other:?}"),
        }
        // accept_block does NOT mutate main_chain on reorg — the
        // caller drives the transition block by block.
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn rollback_and_extend_perform_a_full_reorg() {
        // End-to-end test of the reorg primitives: accept triggers
        // Reorg, then caller rolls back the main chain and extends
        // along the new branch, leaving the Chain consistent at the
        // new tip.
        let genesis_bits = CompactTarget::INITIAL.to_bits();
        let genesis = sample_block_with_bits(Hash256::ZERO, 0, genesis_bits);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_a = sample_block_with_bits(genesis_hash, 1, genesis_bits);
        let block_a_hash = block_a.block_hash();
        chain.accept_block(block_a).expect("main a");

        let hard_bits = 0x1f00_ffff;
        let block_b = sample_block_with_bits(genesis_hash, 2, hard_bits);
        let block_b_hash = block_b.block_hash();
        let AcceptOutcome::Reorg {
            common_ancestor,
            undone,
            applied,
        } = chain.accept_block(block_b).expect("branch b")
        else {
            panic!("expected Reorg");
        };

        assert_eq!(common_ancestor, genesis_hash);
        assert_eq!(undone, vec![block_a_hash]);
        assert_eq!(applied, vec![block_b_hash]);

        // Simulate what the caller would do — drive the reorg
        // through the Chain primitives.
        chain.rollback_main_chain_to(common_ancestor);
        assert_eq!(chain.tip(), genesis_hash);
        assert_eq!(chain.height(), 0);

        for h in &applied {
            chain.extend_main_chain(*h).expect("extend");
        }

        // Chain now sits at the new branch's tip.
        assert_eq!(chain.tip(), block_b_hash);
        assert_eq!(chain.height(), 1);
        // And both old and new blocks remain in the index (old
        // block is still reachable by hash, even though it's no
        // longer on the main chain).
        assert!(chain.contains(&block_a_hash));
        assert!(chain.contains(&block_b_hash));
    }

    #[test]
    fn main_chain_snapshot_and_restore_round_trip() {
        // The reorg orchestrator relies on `main_chain_snapshot` +
        // `restore_main_chain` being a clean round-trip so it can
        // atomically roll back a failed reorg.  Build a short
        // chain, snapshot, mutate, restore, and assert the tip and
        // height are back to the pre-mutation state.
        let genesis = sample_block(Hash256::ZERO, 0);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let block_1 = sample_block(genesis_hash, 1);
        let block_1_hash = block_1.block_hash();
        chain.push(block_1).expect("push 1");

        let block_2 = sample_block(block_1_hash, 2);
        let block_2_hash = block_2.block_hash();
        chain.push(block_2).expect("push 2");

        let snapshot = chain.main_chain_snapshot();
        assert_eq!(chain.tip(), block_2_hash);
        assert_eq!(chain.height(), 2);

        // Mutate: roll the chain back past block 2.
        chain.rollback_main_chain_to(genesis_hash);
        assert_eq!(chain.tip(), genesis_hash);
        assert_eq!(chain.height(), 0);

        // Restore snapshot — chain should look exactly like it did
        // before the rollback.
        chain.restore_main_chain(snapshot);
        assert_eq!(chain.tip(), block_2_hash);
        assert_eq!(chain.height(), 2);
        // Intermediate block is reachable by height again.
        assert_eq!(chain.block_at(1).unwrap().block_hash(), block_1_hash);
    }

    #[test]
    fn deep_reorg_computes_multi_block_paths() {
        // Main chain: genesis → A1 → A2 → A3 (three easy blocks).
        // Competing branch: genesis → B1 (one hard block).  To
        // overtake three easy blocks we need a single hard block
        // whose work exceeds the sum.  0x1f00ffff is hard enough
        // by an order of magnitude, so B1 alone wins.
        //
        // Expected Reorg: common_ancestor = genesis; undone =
        // [A3, A2, A1] (tip-first); applied = [B1].
        let easy_bits = CompactTarget::INITIAL.to_bits();
        let genesis = sample_block_with_bits(Hash256::ZERO, 0, easy_bits);
        let genesis_hash = genesis.block_hash();
        let mut chain = Chain::with_genesis(genesis);

        let a1 = sample_block_with_bits(genesis_hash, 1, easy_bits);
        let a1_hash = a1.block_hash();
        chain.accept_block(a1).expect("a1");
        let a2 = sample_block_with_bits(a1_hash, 2, easy_bits);
        let a2_hash = a2.block_hash();
        chain.accept_block(a2).expect("a2");
        let a3 = sample_block_with_bits(a2_hash, 3, easy_bits);
        let a3_hash = a3.block_hash();
        chain.accept_block(a3).expect("a3");
        assert_eq!(chain.height(), 3);

        let hard_bits = 0x1f00_ffff;
        let b1 = sample_block_with_bits(genesis_hash, 100, hard_bits);
        let b1_hash = b1.block_hash();
        let outcome = chain.accept_block(b1).expect("b1");

        match outcome {
            AcceptOutcome::Reorg {
                common_ancestor,
                undone,
                applied,
            } => {
                assert_eq!(common_ancestor, genesis_hash);
                assert_eq!(undone, vec![a3_hash, a2_hash, a1_hash]);
                assert_eq!(applied, vec![b1_hash]);
            }
            other => panic!("expected Reorg, got {other:?}"),
        }
    }
}
