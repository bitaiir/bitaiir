//! Block subsidy schedule: halvings plus tail emission.
//!
//! Per protocol §3.2, the coinbase reward starts at 100 AIIR and
//! halves every 50,000,000 blocks. When the halving curve would take
//! the reward below a floor of 10 AIIR, it stops halving and stays at
//! 10 AIIR forever (tail emission).
//!
//! All arithmetic is performed in atomic units (where 1 AIIR equals
//! 100,000,000 atomic units), which keeps every era's subsidy
//! representable exactly in a `u64` with no rounding at all. The
//! integer right-shift `initial_atoms >> halvings` lands on an exact
//! power of two every time, because the factor of `100,000,000`
//! already contains more than enough trailing zeros in binary.
//!
//! The function is `const` so that downstream consensus constants
//! (total supply caps, precomputed era boundaries, etc.) can be
//! evaluated at compile time.

use bitaiir_types::Amount;

/// Number of blocks between halvings. At the target block time of
/// five seconds this is approximately 7.9 years per halving.
pub const BLOCKS_PER_HALVING: u64 = 50_000_000;

/// Reward paid per block during era 1 (the first halving window):
/// 100 AIIR, in atomic units.
pub const INITIAL_SUBSIDY: Amount = Amount::from_atomic(100 * 100_000_000);

/// Tail emission floor: 10 AIIR per block, paid forever once the
/// halving curve would drop below this value. Anchors long-term
/// mining incentives so the network can survive a zero-fee world.
pub const TAIL_EMISSION: Amount = Amount::from_atomic(10 * 100_000_000);

/// Compute the block subsidy (coinbase reward) at a given height.
///
/// The formula is:
///
/// ```text
/// subsidy(h) = max(INITIAL_SUBSIDY >> (h / BLOCKS_PER_HALVING),
///                  TAIL_EMISSION)
/// ```
///
/// The right-shift is clamped to zero if the halving count ever
/// reaches 64, which guards against the Rust undefined-behavior of
/// shifting a `u64` by its own bit width. That branch is unreachable
/// under any realistic block height — 64 halvings is over 3 billion
/// blocks, which at five-second blocks is roughly 500 years — but
/// handling it means the function is provably total.
pub const fn subsidy(height: u64) -> Amount {
    let halvings = height / BLOCKS_PER_HALVING;

    let phase1_atoms = if halvings < 64 {
        INITIAL_SUBSIDY.to_atomic() >> halvings
    } else {
        0
    };

    let tail_atoms = TAIL_EMISSION.to_atomic();
    let effective = if phase1_atoms > tail_atoms {
        phase1_atoms
    } else {
        tail_atoms
    };

    Amount::from_atomic(effective)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One whole AIIR in atomic units, for readable assertions below.
    const AIIR: u64 = 100_000_000;

    #[test]
    fn era_1_pays_100_aiir() {
        assert_eq!(subsidy(0), Amount::from_atomic(100 * AIIR));
        assert_eq!(subsidy(1), Amount::from_atomic(100 * AIIR));
        assert_eq!(
            subsidy(BLOCKS_PER_HALVING - 1),
            Amount::from_atomic(100 * AIIR),
        );
    }

    #[test]
    fn era_2_pays_50_aiir() {
        assert_eq!(subsidy(BLOCKS_PER_HALVING), Amount::from_atomic(50 * AIIR),);
        assert_eq!(
            subsidy(2 * BLOCKS_PER_HALVING - 1),
            Amount::from_atomic(50 * AIIR),
        );
    }

    #[test]
    fn era_3_pays_25_aiir() {
        assert_eq!(
            subsidy(2 * BLOCKS_PER_HALVING),
            Amount::from_atomic(25 * AIIR),
        );
    }

    #[test]
    fn era_4_pays_exactly_12_5_aiir() {
        // 12.5 AIIR = 1_250_000_000 atomic units, which is exactly
        // representable in u64. The halving performs a right-shift on
        // the atomic-unit value, not on the human-readable AIIR
        // amount, so no rounding is required.
        assert_eq!(
            subsidy(3 * BLOCKS_PER_HALVING),
            Amount::from_atomic(1_250_000_000),
        );
    }

    #[test]
    fn tail_emission_kicks_in_at_era_5() {
        // Halving 4 would otherwise pay 100 AIIR >> 4 = 6.25 AIIR,
        // which is below the 10 AIIR tail floor, so the floor takes
        // over from block 4 * BLOCKS_PER_HALVING onward.
        assert_eq!(
            subsidy(4 * BLOCKS_PER_HALVING),
            Amount::from_atomic(10 * AIIR),
        );
        assert_eq!(
            subsidy(5 * BLOCKS_PER_HALVING),
            Amount::from_atomic(10 * AIIR),
        );
    }

    #[test]
    fn tail_emission_stays_forever() {
        // Even at absurdly high heights the subsidy sticks at the
        // floor. The phase-1 curve eventually reaches zero under the
        // right-shift, but the `max` with TAIL_EMISSION keeps the
        // effective reward at 10 AIIR for the rest of time.
        assert_eq!(subsidy(1_000_000_000), TAIL_EMISSION);
        assert_eq!(subsidy(u64::MAX), TAIL_EMISSION);
    }

    #[test]
    fn subsidy_is_monotonically_non_increasing() {
        // The schedule must never go up as height increases. It drops
        // at each halving boundary and stays constant everywhere else,
        // so iterating over a few representative heights is enough to
        // spot a regression.
        let mut previous = subsidy(0);
        let mut height: u64 = 0;
        let end = 5 * BLOCKS_PER_HALVING;
        while height <= end {
            let current = subsidy(height);
            assert!(
                current <= previous,
                "subsidy went up at height {height}: \
                 previous = {} atoms, current = {} atoms",
                previous.to_atomic(),
                current.to_atomic(),
            );
            previous = current;
            height += 10_000_000;
        }
    }

    #[test]
    fn total_emitted_at_end_of_era_4_is_9_375_billion_aiir() {
        // Sum era by era — each era emits exactly
        // BLOCKS_PER_HALVING * reward(era). The first four eras are:
        //
        //   era 1: 100   AIIR * 50M blocks = 5.000 B AIIR
        //   era 2:  50   AIIR * 50M blocks = 2.500 B AIIR
        //   era 3:  25   AIIR * 50M blocks = 1.250 B AIIR
        //   era 4:  12.5 AIIR * 50M blocks = 0.625 B AIIR
        //   ---------------------------------------------
        //   total                          = 9.375 B AIIR
        //
        // That is 937_500_000_000_000_000 atomic units, which fits
        // comfortably inside a `u64` (max ~1.84e19) but we use `u128`
        // here to make the multiplication obviously overflow-free.
        let heights = [
            0,
            BLOCKS_PER_HALVING,
            2 * BLOCKS_PER_HALVING,
            3 * BLOCKS_PER_HALVING,
        ];
        let total: u128 = heights
            .iter()
            .map(|&h| subsidy(h).to_atomic() as u128 * BLOCKS_PER_HALVING as u128)
            .sum();
        assert_eq!(total, 937_500_000_000_000_000_u128);
    }
}
