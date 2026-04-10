//! Protocol consensus constants.
//!
//! Every magic number the validation and mining code needs lives here
//! in one place, with a doc comment linking to the corresponding
//! section of `docs/protocol.md`. If two modules need the same
//! constant, they import it from here — no duplicated literals.
//!
//! Subsidy-related constants (`BLOCKS_PER_HALVING`, `INITIAL_SUBSIDY`,
//! `TAIL_EMISSION`) live in [`crate::subsidy`] because they're
//! tightly coupled to the subsidy function.

/// Maximum serialized block size in bytes (protocol §7.4 rule 1).
pub const MAX_BLOCK_SIZE: usize = 1_000_000;

/// Maximum serialized transaction size in bytes (protocol §6.1).
pub const MAX_TX_SIZE: usize = 100_000;

/// Number of blocks a coinbase output must mature before it can be
/// spent (protocol §6.5).
pub const COINBASE_MATURITY: u64 = 100;

/// Number of blocks between difficulty retargets (protocol §8.4).
pub const RETARGET_INTERVAL: u64 = 144;

/// Target block time in seconds (protocol §2).
pub const TARGET_BLOCK_TIME: u64 = 5;

/// The expected wall-clock time for one retarget window, in seconds.
pub const RETARGET_EXPECTED_TIME: u64 = RETARGET_INTERVAL * TARGET_BLOCK_TIME;

/// Number of preceding blocks used to compute the median-time-past
/// (protocol §8.6).
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Maximum clock drift allowed for an incoming block's timestamp,
/// relative to the node's adjusted time, in seconds (protocol §7.4
/// rule 5). Set to two hours.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;
