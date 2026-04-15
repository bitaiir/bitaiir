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

/// Default upper bound on total serialized bytes held in the
/// mempool.  When this cap is reached, the [`crate::Mempool`] evicts
/// the lowest-priority transactions (highest tx-PoW hash, then
/// newest arrival) to make room for incoming ones.
///
/// 50 MB is conservative for a pre-mainnet chain: it caps RAM
/// exposure to a small fraction of any modern machine's memory
/// while still holding tens of thousands of typical transactions.
/// Operators can override this via the `[mempool] max_bytes` key
/// in `bitaiir.toml`.
pub const DEFAULT_MAX_MEMPOOL_BYTES: usize = 50_000_000;

/// Maximum serialized transaction size in bytes (protocol §6.1).
pub const MAX_TX_SIZE: usize = 100_000;

/// Number of blocks a coinbase output must mature before it can be
/// spent (protocol §6.5).
///
/// This constant holds the **mainnet** value. The effective maturity
/// at runtime is network-dependent — use [`coinbase_maturity`] to get
/// the value that applies to the currently-active network (testnet
/// uses a lower value for faster development turnaround).
pub const COINBASE_MATURITY: u64 = 100;

/// Runtime coinbase maturity for the currently-active network.
///
/// Reads [`bitaiir_types::Network::active`] — defaults to mainnet
/// (100 blocks) if the daemon has not explicitly selected a network.
#[inline]
pub fn coinbase_maturity() -> u64 {
    bitaiir_types::Network::active().coinbase_maturity()
}

/// Recommended minimum confirmations before a wallet treats a
/// received output as "confirmed".  This is a **client-side
/// convention**, not a consensus rule — any output in a mined block
/// is protocol-valid to spend from block 1.  Wallets, exchanges,
/// and merchants use this as a safety margin against reorgs.
///
/// 12 blocks × 5 s target = ~60 s.
pub const RECOMMENDED_CONFIRMATIONS: u64 = 12;

/// Number of blocks between difficulty retargets (protocol §8.4).
/// Set to 20 for fast adaptation in a small network (~100 s at the
/// target block time). v2 will migrate to per-block LWMA.
pub const RETARGET_INTERVAL: u64 = 20;

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

// --- Proof of Aiir (Argon2id parameters, protocol §8.2 / §8.7) ---------- //

/// Argon2id memory cost in KiB.
///
/// Production builds use 64 MiB (65 536 KiB), which forces every
/// mining attempt to allocate and sequentially traverse 64 MiB of
/// RAM. This is the anti-ASIC barrier.
///
/// Test builds use a drastically reduced 256 KiB so that `cargo test`
/// finishes in seconds rather than minutes. The code path is
/// identical; only the wall-clock time and ASIC-resistance properties
/// differ. CI should periodically run a dedicated integration test
/// with the production value to catch regressions in the real
/// algorithm.
#[cfg(not(test))]
pub const AIIR_POW_MEMORY_KIB: u32 = 65_536;

#[cfg(test)]
pub const AIIR_POW_MEMORY_KIB: u32 = 256;

/// Argon2id time cost (number of passes over the memory). One pass
/// is sufficient for our use: the memory-hardness, not the iteration
/// count, is the bottleneck for ASIC builders.
pub const AIIR_POW_TIME_COST: u32 = 1;

/// Argon2id parallelism (number of independent lanes). Set to 1 so
/// every miner uses a single thread per attempt. Multi-threaded
/// mining is achieved by running multiple independent attempts on
/// different nonces, not by parallelising a single Argon2 invocation.
pub const AIIR_POW_PARALLELISM: u32 = 1;

/// Argon2id output length in bytes.
pub const AIIR_POW_OUTPUT_LEN: usize = 32;
