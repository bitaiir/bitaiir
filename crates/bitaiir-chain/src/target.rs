//! Compact difficulty target encoding (the `bits` field of a block
//! header).
//!
//! BitAiir reuses Bitcoin's 4-byte compact format. A `u32` packs an
//! 8-bit exponent and a 24-bit mantissa; the two together encode a
//! 256-bit target value via:
//!
//! ```text
//! target = mantissa × 2 ^ (8 × (exponent − 3))
//! ```
//!
//! A block is valid when its proof-of-work hash, interpreted as a
//! big-endian 256-bit unsigned integer, is **less than or equal to**
//! the decoded target (see protocol §8.3).
//!
//! This module contains the encoding itself, not the retarget
//! algorithm; adjustment rules live in a later phase alongside the
//! chain state they depend on.
//!
//! [`CompactTarget::work`] returns the "proof of work" of a single
//! block under this target, as a 256-bit integer.  Summing `work()`
//! over every block in a chain gives that chain's cumulative work,
//! which is the fork-choice metric: when two chains disagree on the
//! main chain, the one with more total work wins.

use primitive_types::U256;

/// A compact 32-bit difficulty target, stored in block headers as
/// `bits`. Construct with [`CompactTarget::from_bits`] or the
/// [`CompactTarget::INITIAL`] constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// The hardcoded initial difficulty used by the genesis block and
    /// every block up to and including block 143, before the first
    /// retarget. See protocol §8.5.
    ///
    /// `0x2000ffff` decodes to a target equal to
    /// `0x00ffff × 2 ^ 232`, which as a big-endian 32-byte value is
    /// `00 ff ff 00 00 … 00`. Roughly one hash in 256 meets it.
    pub const INITIAL: Self = Self(0x2000_ffff);

    /// Wrap a raw `bits` value without validation. Call
    /// [`Self::to_target`] to check whether the encoding is
    /// structurally valid.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw `bits` value as stored in the header.
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// Expand the compact encoding into the full 256-bit target as a
    /// 32-byte big-endian array.
    ///
    /// Returns `None` when the encoding is structurally invalid:
    ///
    /// - The mantissa's high bit is set. Bitcoin's compact format
    ///   reserves that bit as a sign bit, and targets must be
    ///   non-negative.
    /// - The exponent is greater than 32 with a non-zero mantissa,
    ///   which would place the mantissa bytes outside the 32-byte
    ///   output (the target would exceed 256 bits).
    pub const fn to_target(self) -> Option<[u8; 32]> {
        let bits = self.0;
        let exponent = (bits >> 24) as usize;
        let mantissa = bits & 0x00ff_ffff;

        // The high bit of the mantissa is Bitcoin's sign bit. Targets
        // are never negative, so a set sign bit means the header is
        // malformed.
        if mantissa & 0x0080_0000 != 0 {
            return None;
        }

        let mut target = [0u8; 32];

        // The three mantissa bytes are placed inside the 32-byte
        // target at an offset determined by the exponent:
        //
        //   exponent ≤ 3: shift the mantissa right into the low bytes
        //                 of the target, losing precision.
        //   exponent ≤ 32: place the mantissa at offset (32 - exponent).
        //   exponent > 32 with non-zero mantissa: overflow, invalid.
        if exponent <= 3 {
            let shift = (3 - exponent) * 8;
            let value = mantissa >> shift;
            target[29] = (value >> 16) as u8;
            target[30] = (value >> 8) as u8;
            target[31] = value as u8;
        } else if exponent <= 32 {
            let offset = 32 - exponent;
            target[offset] = (mantissa >> 16) as u8;
            target[offset + 1] = (mantissa >> 8) as u8;
            target[offset + 2] = mantissa as u8;
        } else {
            return None;
        }

        Some(target)
    }

    /// Check whether a 32-byte proof-of-work hash meets this target.
    ///
    /// The hash is interpreted as a big-endian 256-bit unsigned
    /// integer. The block is valid when `hash ≤ target`. A
    /// structurally invalid target (see [`Self::to_target`]) is never
    /// met.
    pub fn hash_meets_target(self, hash: &[u8; 32]) -> bool {
        match self.to_target() {
            Some(target) => hash <= &target,
            None => false,
        }
    }

    /// Return the amount of "proof of work" a block with this target
    /// represents, as a 256-bit integer.
    ///
    /// Intuitively: how many hashes, on average, a miner has to try
    /// before producing a valid block under this target.  The lower
    /// the target, the more hashes are needed, the higher the work.
    /// Summing `work()` across every block in a chain yields the
    /// chain's **cumulative work** — the fork-choice metric.
    ///
    /// Formula (matches Bitcoin Core's `GetBlockProof`):
    ///
    /// ```text
    ///   work = floor(2^256 / (target + 1))
    ///        = (~target) / (target + 1) + 1
    /// ```
    ///
    /// The second form is used because `2^256` doesn't fit in a
    /// `U256`.  Structurally invalid targets (see [`Self::to_target`])
    /// return zero work — no work should be credited for a malformed
    /// header.
    pub fn work(self) -> U256 {
        let Some(target_bytes) = self.to_target() else {
            return U256::zero();
        };
        let target = U256::from_big_endian(&target_bytes);
        // A target of zero is unreachable in practice (the mantissa's
        // sign-bit check rejects it, and the initial target has
        // non-zero bytes) but we guard defensively so the divisor
        // `target + 1` never wraps to zero.
        if target.is_zero() {
            return U256::zero();
        }
        (!target) / (target + U256::one()) + U256::one()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_target_round_trip() {
        let ct = CompactTarget::INITIAL;
        assert_eq!(ct.to_bits(), 0x2000_ffff);
        assert_eq!(CompactTarget::from_bits(0x2000_ffff), ct);
    }

    #[test]
    fn initial_target_expands_to_leading_zero_ffff() {
        // 0x2000ffff: exponent = 0x20 = 32, mantissa = 0x00ffff
        // offset = 32 - 32 = 0, so the mantissa lands in the first
        // three bytes: [0x00, 0xff, 0xff, 0x00, 0x00, ..., 0x00]
        let target = CompactTarget::INITIAL.to_target().unwrap();
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0xff);
        assert_eq!(target[2], 0xff);
        for &byte in target[3..].iter() {
            assert_eq!(byte, 0x00);
        }
    }

    #[test]
    fn bitcoin_style_1d00ffff_expands_correctly() {
        // 0x1d00ffff: exponent = 0x1d = 29, mantissa = 0x00ffff.
        // offset = 32 - 29 = 3, so mantissa bytes land at indices
        // 3, 4, 5. Bitcoin's classic "minimum difficulty".
        let target = CompactTarget::from_bits(0x1d00_ffff).to_target().unwrap();
        let mut expected = [0u8; 32];
        expected[3] = 0x00;
        expected[4] = 0xff;
        expected[5] = 0xff;
        assert_eq!(target, expected);
    }

    #[test]
    fn low_exponent_shifts_mantissa_into_low_bytes() {
        // Exponent 2 means the mantissa is interpreted as being
        // shifted right by 8 bits before being placed in the low
        // bytes of the target:
        //   value = 0x00ffff >> 8 = 0xff
        //   target[29..32] = [0x00, 0x00, 0xff]
        let target = CompactTarget::from_bits(0x0200_ffff).to_target().unwrap();
        assert_eq!(target[29], 0x00);
        assert_eq!(target[30], 0x00);
        assert_eq!(target[31], 0xff);
        for &byte in target[..29].iter() {
            assert_eq!(byte, 0x00);
        }
    }

    #[test]
    fn all_zero_hash_meets_any_valid_target() {
        let hash = [0u8; 32];
        assert!(CompactTarget::INITIAL.hash_meets_target(&hash));
        assert!(CompactTarget::from_bits(0x1d00_ffff).hash_meets_target(&hash));
    }

    #[test]
    fn all_ones_hash_meets_no_normal_target() {
        let hash = [0xffu8; 32];
        assert!(!CompactTarget::INITIAL.hash_meets_target(&hash));
        assert!(!CompactTarget::from_bits(0x1d00_ffff).hash_meets_target(&hash));
    }

    #[test]
    fn hash_equal_to_target_is_accepted() {
        // The inequality is `hash ≤ target`, not strictly `<`, so a
        // block whose hash lands exactly on the boundary is valid.
        let target = CompactTarget::INITIAL.to_target().unwrap();
        assert!(CompactTarget::INITIAL.hash_meets_target(&target));
    }

    #[test]
    fn hash_one_greater_than_target_is_rejected() {
        // INITIAL target starts with 0x00 0xff 0xff ... 0x00. We
        // construct a hash that is numerically one greater by
        // changing the leading 0x00 to 0x01, which pushes us past
        // the target in the big-endian ordering.
        let mut hash = CompactTarget::INITIAL.to_target().unwrap();
        hash[0] = 0x01;
        assert!(!CompactTarget::INITIAL.hash_meets_target(&hash));
    }

    #[test]
    fn negative_mantissa_is_rejected() {
        // Top bit of the mantissa set — treated as a "negative"
        // target, which is nonsensical and rejected.
        let ct = CompactTarget::from_bits(0x2080_0000);
        assert!(ct.to_target().is_none());
        // And no hash can ever meet an invalid target.
        assert!(!ct.hash_meets_target(&[0u8; 32]));
    }

    #[test]
    fn exponent_greater_than_32_is_rejected() {
        // exponent = 0x21 = 33, mantissa = 0x00ffff.
        // offset = 32 - 33 = −1, which would write before the start
        // of the target buffer — invalid.
        let ct = CompactTarget::from_bits(0x2100_ffff);
        assert!(ct.to_target().is_none());
    }

    #[test]
    fn exponent_of_32_is_the_largest_valid_exponent() {
        // This is the initial difficulty value: max exponent that
        // keeps the mantissa inside the 32-byte buffer.
        assert!(CompactTarget::from_bits(0x2000_ffff).to_target().is_some());
    }

    // --- work() / cumulative chain-work tests --------------------------- //

    #[test]
    fn lower_target_means_more_work() {
        // A block with lower difficulty (easy target) takes fewer
        // hashes to mine, so carries less work than a block with a
        // higher difficulty (hard target).  0x1d00ffff is Bitcoin's
        // minimum difficulty, considerably harder than the initial
        // 0x2000ffff used in our genesis.
        let easy = CompactTarget::INITIAL.work();
        let hard = CompactTarget::from_bits(0x1d00_ffff).work();
        assert!(hard > easy, "harder target must carry more work");
    }

    #[test]
    fn invalid_target_has_zero_work() {
        // Negative mantissa → no valid target → no work credited.
        let ct = CompactTarget::from_bits(0x2080_0000);
        assert!(ct.work().is_zero());
    }

    #[test]
    fn equal_targets_produce_equal_work() {
        // Fork-choice sanity: two blocks mined under identical
        // difficulty contribute the same amount of work.
        let a = CompactTarget::from_bits(0x1d00_ffff).work();
        let b = CompactTarget::from_bits(0x1d00_ffff).work();
        assert_eq!(a, b);
    }

    #[test]
    fn initial_target_work_matches_expected_magnitude() {
        // The initial target is `0x00ffff000...00` (32 bytes) which
        // as U256 is approximately `0xffff * 2^232`.  Plugging into
        // the formula:
        //
        //   work ≈ 2^256 / (0xffff * 2^232) ≈ 2^24 / 0xffff ≈ 256
        //
        // The exact value is 257 after the `+1` adjustment.  We
        // assert a small window around it so the test is robust to
        // any rounding in the formula.
        let w = CompactTarget::INITIAL.work();
        assert!(!w.is_zero());
        assert!(
            w >= U256::from(200u32) && w <= U256::from(300u32),
            "initial-target work {w} outside expected [200, 300] window",
        );
    }
}
