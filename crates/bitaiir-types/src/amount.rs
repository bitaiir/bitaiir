//! `Amount`: a quantity of AIIR in atomic units.
//!
//! BitAiir uses 8 decimal places of precision, matching Bitcoin's satoshi
//! model. One whole AIIR equals [`ATOMIC_UNITS_PER_AIIR`] atomic units.
//!
//! The total supply cap is 100,000,000,000 AIIR, which in atomic units is
//! `100e9 * 1e8 = 1e19`. This fits in `u64` (max ~1.84e19) but the margin
//! is tight, so every arithmetic operation on `Amount` uses checked
//! arithmetic. There is no unchecked `+` / `-` — callers must handle
//! overflow explicitly.
//!
//! `Amount` deliberately does not enforce the supply cap on construction.
//! That is a consensus-layer check performed by `bitaiir-chain` at block
//! validation time, not a type-level invariant.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Atomic units per whole AIIR. The same 8-decimal-place convention Bitcoin
/// uses.
pub const ATOMIC_UNITS_PER_AIIR: u64 = 100_000_000;

/// Total supply cap, in atomic units.
pub const MAX_SUPPLY: u64 = 100_000_000_000 * ATOMIC_UNITS_PER_AIIR;

/// A quantity of AIIR, measured in atomic units.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const MAX_SUPPLY: Self = Self(MAX_SUPPLY);

    /// Build an `Amount` from raw atomic units.
    pub const fn from_atomic(units: u64) -> Self {
        Self(units)
    }

    /// Return the raw atomic unit count.
    pub const fn to_atomic(self) -> u64 {
        self.0
    }

    /// Checked addition: returns `None` if the result would overflow.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction: returns `None` if the result would go negative.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Checked multiplication: returns `None` if the result would overflow.
    pub fn checked_mul(self, factor: u64) -> Option<Self> {
        self.0.checked_mul(factor).map(Self)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / ATOMIC_UNITS_PER_AIIR;
        let frac = self.0 % ATOMIC_UNITS_PER_AIIR;
        write!(f, "{whole}.{frac:08} AIIR")
    }
}
