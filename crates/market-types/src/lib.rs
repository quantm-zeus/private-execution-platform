//! Lossless market primitives with explicit units.

use chain_types::AssetId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sequence(pub u64);

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MarketTypeError {
    #[error("basis points out of range: {0}")]
    BpsOutOfRange(u16),
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("price numerator must be greater than zero")]
    ZeroPriceNumerator,
    #[error("price denominator must be greater than zero")]
    ZeroPriceDenominator,
    #[error("version must be greater than zero")]
    ZeroVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_bounds_are_enforced() {
        assert_eq!(Bps::new(10_000).unwrap().get(), 10_000);
        assert_eq!(
            Bps::new(10_001),
            Err(MarketTypeError::BpsOutOfRange(10_001))
        );
    }

    #[test]
    fn price_ratio_rejects_zero_sides() {
        assert_eq!(
            PriceRatio::new(0, 1),
            Err(MarketTypeError::ZeroPriceNumerator)
        );
        assert_eq!(
            PriceRatio::new(1, 0),
            Err(MarketTypeError::ZeroPriceDenominator)
        );
    }

    #[test]
    fn price_round_trip_is_lossless() {
        let price = PriceRatio::new(u128::MAX - 7, 1_000_000_000_000_000_000).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        let decoded: PriceRatio = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, price);
    }

    #[test]
    fn bps_rejects_out_of_range_json() {
        assert!(serde_json::from_str::<Bps>("10001").is_err());
        assert!(serde_json::from_str::<Bps>("10000").is_ok());
    }

    #[test]
    fn price_ratio_rejects_zero_sides_in_json() {
        let zero_num = serde_json::from_str::<PriceRatio>(
            r#"{"numerator_atomic": 0, "denominator_atomic": 1}"#,
        );
        assert_eq!(
            zero_num.unwrap_err().to_string(),
            MarketTypeError::ZeroPriceNumerator.to_string()
        );
        let zero_den = serde_json::from_str::<PriceRatio>(
            r#"{"numerator_atomic": 1, "denominator_atomic": 0}"#,
        );
        assert_eq!(
            zero_den.unwrap_err().to_string(),
            MarketTypeError::ZeroPriceDenominator.to_string()
        );
    }

    #[test]
    fn version_rejects_zero_json() {
        assert!(serde_json::from_str::<Version>("0").is_err());
        assert!(serde_json::from_str::<Version>("1").is_ok());
    }

    #[test]
    fn bps_round_trip_is_lossless() {
        for value in [0u16, 1, 9_999, 10_000] {
            let bps = Bps::new(value).unwrap();
            let json = serde_json::to_string(&bps).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: Bps = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, bps);
        }
    }

    #[test]
    fn version_round_trip_is_lossless() {
        for value in [1u64, u64::MAX - 1, u64::MAX] {
            let version = Version::new(value).unwrap();
            let json = serde_json::to_string(&version).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: Version = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, version);
        }
    }

    #[test]
    fn atomic_amount_round_trip_is_lossless() {
        for value in [0u128, 1, u128::MAX] {
            let amount = AtomicAmount::new(value);
            let json = serde_json::to_string(&amount).unwrap();
            assert_eq!(json, value.to_string());
            let decoded: AtomicAmount = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, amount);
        }
    }

    #[test]
    fn price_ratio_json_shape_is_preserved() {
        let price = PriceRatio::new(123, 456).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        assert_eq!(json, r#"{"numerator_atomic":123,"denominator_atomic":456}"#);
    }

    #[test]
    fn high_u128_price_ratio_round_trip_is_lossless() {
        let price = PriceRatio::new(u128::MAX, u128::MAX - 1).unwrap();
        let json = serde_json::to_string(&price).unwrap();
        let decoded: PriceRatio = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.numerator_atomic(), u128::MAX);
        assert_eq!(decoded.denominator_atomic(), u128::MAX - 1);
    }
}
