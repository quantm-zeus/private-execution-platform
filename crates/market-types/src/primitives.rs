//! Lossless market primitives with explicit units.

use chain_types::AssetId;
use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct AtomicAmount(u128);

impl AtomicAmount {
    pub const ZERO: Self = Self(0);
    pub const fn new(value: u128) -> Self {
        Self(value)
    }
    pub const fn get(self) -> u128 {
        self.0
    }
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16")]
pub struct Bps(u16);

impl TryFrom<u16> for Bps {
    type Error = MarketTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Bps {
    pub const MAX: u16 = 10_000;
    pub fn new(value: u16) -> Result<Self, MarketTypeError> {
        if value > Self::MAX {
            return Err(MarketTypeError::BpsOutOfRange(value));
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u16 {
        self.0
    }
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if self.0 > Self::MAX {
            return Err(MarketTypeError::BpsOutOfRange(self.0));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPriceRatio")]
pub struct PriceRatio {
    numerator_atomic: u128,
    denominator_atomic: u128,
}

#[derive(Deserialize)]
struct UncheckedPriceRatio {
    numerator_atomic: u128,
    denominator_atomic: u128,
}

impl TryFrom<UncheckedPriceRatio> for PriceRatio {
    type Error = MarketTypeError;

    fn try_from(unchecked: UncheckedPriceRatio) -> Result<Self, Self::Error> {
        Self::new(unchecked.numerator_atomic, unchecked.denominator_atomic)
    }
}

impl PriceRatio {
    pub fn new(numerator_atomic: u128, denominator_atomic: u128) -> Result<Self, MarketTypeError> {
        if numerator_atomic == 0 {
            return Err(MarketTypeError::ZeroPriceNumerator);
        }
        if denominator_atomic == 0 {
            return Err(MarketTypeError::ZeroPriceDenominator);
        }
        Ok(Self {
            numerator_atomic,
            denominator_atomic,
        })
    }
    pub const fn numerator_atomic(self) -> u128 {
        self.numerator_atomic
    }
    pub const fn denominator_atomic(self) -> u128 {
        self.denominator_atomic
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAmount {
    pub asset: AssetId,
    pub amount: AtomicAmount,
}

impl AssetAmount {
    pub fn validate_nonzero(&self) -> Result<(), MarketTypeError> {
        if self.amount.is_zero() {
            return Err(MarketTypeError::ZeroAmount);
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Sequence(pub u64);

impl Sequence {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub const fn checked_add(self, delta: u64) -> Option<Self> {
        match self.0.checked_add(delta) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    pub const fn saturating_add(self, delta: u64) -> Self {
        Self(self.0.saturating_add(delta))
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if self.0 == 0 {
            return Err(MarketTypeError::ZeroSequence);
        }
        Ok(())
    }
}

impl std::fmt::Display for Sequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64")]
pub struct Version(u64);

impl TryFrom<u64> for Version {
    type Error = MarketTypeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Version {
    pub fn new(value: u64) -> Result<Self, MarketTypeError> {
        if value == 0 {
            return Err(MarketTypeError::ZeroVersion);
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    pub observed_at_ms: i64,
    pub chain_height: u64,
    pub sequence: Sequence,
}
