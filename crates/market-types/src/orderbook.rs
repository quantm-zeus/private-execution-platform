//! Normalized order book depth levels, snapshots, and local aggregation.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::MarketTypeError;
use crate::identity::FeedTarget;
use crate::primitives::{AtomicAmount, PriceRatio, Sequence};
use crate::sequence::{DeltaClassification, SequenceRange, SnapshotClassification};

pub const MAX_DEPTH_LEVELS: usize = 5_000;

/// Normalized finite, non-negative price level.
#[derive(Clone, Copy, Debug)]
pub struct NormalizedPrice(f64);

impl NormalizedPrice {
    pub fn new(value: f64) -> Result<Self, MarketTypeError> {
        if !value.is_finite() {
            return Err(MarketTypeError::NonFinitePrice);
        }
        if value < 0.0 {
            return Err(MarketTypeError::NegativePrice);
        }
        // Normalize -0.0 to 0.0
        let val = if value == 0.0 { 0.0 } else { value };
        Ok(Self(val))
    }

    pub fn new_positive(value: f64) -> Result<Self, MarketTypeError> {
        let price = Self::new(value)?;
        if price.0 == 0.0 {
            return Err(MarketTypeError::ZeroPrice);
        }
        Ok(price)
    }

    pub const fn get(self) -> f64 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0.0
    }

    pub fn from_ratio(
        ratio: PriceRatio,
        base_decimals: u8,
        quote_decimals: u8,
    ) -> Result<Self, MarketTypeError> {
        let num = ratio.numerator_atomic() as f64 / 10f64.powi(base_decimals as i32);
        let den = ratio.denominator_atomic() as f64 / 10f64.powi(quote_decimals as i32);
        if den == 0.0 {
            return Err(MarketTypeError::ZeroPriceDenominator);
        }
        Self::new_positive(num / den)
    }
}

impl PartialEq for NormalizedPrice {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for NormalizedPrice {}

impl PartialOrd for NormalizedPrice {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NormalizedPrice {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::hash::Hash for NormalizedPrice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl Serialize for NormalizedPrice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for NormalizedPrice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PriceVisitor;

        impl<'de> serde::de::Visitor<'de> for PriceVisitor {
            type Value = NormalizedPrice;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a finite non-negative price as number or string")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NormalizedPrice::new(v).map_err(E::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v < 0 {
                    return Err(E::custom("price must be non-negative"));
                }
                NormalizedPrice::new(v as f64).map_err(E::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NormalizedPrice::new(v as f64).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parsed: f64 = v.trim().parse().map_err(E::custom)?;
                NormalizedPrice::new(parsed).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(PriceVisitor)
    }
}

/// Normalized finite, non-negative quantity.
#[derive(Clone, Copy, Debug)]
pub struct NormalizedQuantity(f64);

impl NormalizedQuantity {
    pub fn new(value: f64) -> Result<Self, MarketTypeError> {
        if !value.is_finite() {
            return Err(MarketTypeError::NonFiniteQuantity);
        }
        if value < 0.0 {
            return Err(MarketTypeError::NegativeQuantity);
        }
        let val = if value == 0.0 { 0.0 } else { value };
        Ok(Self(val))
    }

    pub fn new_positive(value: f64) -> Result<Self, MarketTypeError> {
        let qty = Self::new(value)?;
        if qty.0 == 0.0 {
            return Err(MarketTypeError::ZeroQuantity);
        }
        Ok(qty)
    }

    pub const fn get(self) -> f64 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0.0
    }

    pub fn from_atomic(amount: AtomicAmount, decimals: u8) -> Result<Self, MarketTypeError> {
        let val = amount.get() as f64 / 10f64.powi(decimals as i32);
        Self::new(val)
    }
}

impl PartialEq for NormalizedQuantity {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for NormalizedQuantity {}

impl PartialOrd for NormalizedQuantity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NormalizedQuantity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::hash::Hash for NormalizedQuantity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl Serialize for NormalizedQuantity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for NormalizedQuantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct QtyVisitor;

        impl<'de> serde::de::Visitor<'de> for QtyVisitor {
            type Value = NormalizedQuantity;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a finite non-negative quantity as number or string")
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NormalizedQuantity::new(v).map_err(E::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v < 0 {
                    return Err(E::custom("quantity must be non-negative"));
                }
                NormalizedQuantity::new(v as f64).map_err(E::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NormalizedQuantity::new(v as f64).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parsed: f64 = v.trim().parse().map_err(E::custom)?;
                NormalizedQuantity::new(parsed).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(QtyVisitor)
    }
}

/// Single price level in an order book depth representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthLevel {
    pub price: NormalizedPrice,
    pub quantity: NormalizedQuantity,
}

impl DepthLevel {
    pub fn new(price: NormalizedPrice, quantity: NormalizedQuantity) -> Self {
        Self { price, quantity }
    }

    pub fn validate_snapshot(&self) -> Result<(), MarketTypeError> {
        if self.price.is_zero() {
            return Err(MarketTypeError::ZeroPrice);
        }
        if self.quantity.is_zero() {
            return Err(MarketTypeError::ZeroQuantity);
        }
        Ok(())
    }

    pub fn validate_delta(&self) -> Result<(), MarketTypeError> {
        if self.price.is_zero() {
            return Err(MarketTypeError::ZeroPrice);
        }
        Ok(())
    }
}

/// Validated order book depth snapshot at a specific sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthSnapshot {
    pub target: FeedTarget,
    pub sequence: Sequence,
    pub timestamp_ms: i64,
    pub bids: Vec<DepthLevel>,
    pub asks: Vec<DepthLevel>,
}

impl DepthSnapshot {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.target.validate()?;
        self.sequence.validate()?;
        if self.timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.timestamp_ms));
        }
        if self.bids.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: self.bids.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }
        if self.asks.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: self.asks.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }

        // Validate bids ordering: strictly descending by price
        for i in 0..self.bids.len() {
            self.bids[i].validate_snapshot()?;
            if i > 0 {
                if self.bids[i].price == self.bids[i - 1].price {
                    return Err(MarketTypeError::DuplicateDepthPriceLevel { side: "bids" });
                }
                if self.bids[i].price > self.bids[i - 1].price {
                    return Err(MarketTypeError::UnsortedDepthLevels { side: "bids" });
                }
            }
        }

        // Validate asks ordering: strictly ascending by price
        for i in 0..self.asks.len() {
            self.asks[i].validate_snapshot()?;
            if i > 0 {
                if self.asks[i].price == self.asks[i - 1].price {
                    return Err(MarketTypeError::DuplicateDepthPriceLevel { side: "asks" });
                }
                if self.asks[i].price < self.asks[i - 1].price {
                    return Err(MarketTypeError::UnsortedDepthLevels { side: "asks" });
                }
            }
        }

        // Validate crossed book
        if let (Some(best_bid), Some(best_ask)) = (self.bids.first(), self.asks.first()) {
            if best_bid.price >= best_ask.price {
                return Err(MarketTypeError::CrossedOrderBook);
            }
        }

        Ok(())
    }
}

/// Validated order book depth delta for an incremental update range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthDelta {
    pub target: FeedTarget,
    pub sequence_range: SequenceRange,
    pub timestamp_ms: i64,
    pub bids: Vec<DepthLevel>,
    pub asks: Vec<DepthLevel>,
}

impl DepthDelta {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.target.validate()?;
        self.sequence_range.validate()?;
        if self.timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.timestamp_ms));
        }
        if self.bids.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: self.bids.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }
        if self.asks.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: self.asks.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }

        for bid in &self.bids {
            bid.validate_delta()?;
        }
        for ask in &self.asks {
            ask.validate_delta()?;
        }

        Ok(())
    }
}

/// Maintained local order book depth suitable for local aggregation and rendering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderBookDepth {
    target: FeedTarget,
    sequence: Sequence,
    timestamp_ms: i64,
    bids: Vec<DepthLevel>,
    asks: Vec<DepthLevel>,
    max_levels: usize,
    #[serde(default)]
    resync_required: bool,
}

impl OrderBookDepth {
    pub fn new(snapshot: DepthSnapshot, max_levels: usize) -> Result<Self, MarketTypeError> {
        snapshot.validate()?;
        if max_levels == 0 || max_levels > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: max_levels,
                max: MAX_DEPTH_LEVELS,
            });
        }

        let mut bids = snapshot.bids;
        bids.truncate(max_levels);
        let mut asks = snapshot.asks;
        asks.truncate(max_levels);

        Ok(Self {
            target: snapshot.target,
            sequence: snapshot.sequence,
            timestamp_ms: snapshot.timestamp_ms,
            bids,
            asks,
            max_levels,
            resync_required: false,
        })
    }

    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }

    pub fn bids(&self) -> &[DepthLevel] {
        &self.bids
    }

    pub fn asks(&self) -> &[DepthLevel] {
        &self.asks
    }

    pub fn best_bid(&self) -> Option<&DepthLevel> {
        self.bids.first()
    }

    pub fn best_ask(&self) -> Option<&DepthLevel> {
        self.asks.first()
    }

    pub fn spread(&self) -> Option<f64> {
        match (self.best_bid(), self.best_ask()) {
            (Some(bid), Some(ask)) => Some(ask.price.get() - bid.price.get()),
            _ => None,
        }
    }

    pub fn mid_price(&self) -> Option<NormalizedPrice> {
        match (self.best_bid(), self.best_ask()) {
            (Some(bid), Some(ask)) => {
                let mid = (bid.price.get() + ask.price.get()) / 2.0;
                NormalizedPrice::new(mid).ok()
            }
            _ => None,
        }
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    /// Clears the resync latch and resets book state from a validated fresh snapshot.
    pub fn reset_with_snapshot(&mut self, snapshot: DepthSnapshot) -> Result<(), MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        let mut bids = snapshot.bids;
        bids.truncate(self.max_levels);
        let mut asks = snapshot.asks;
        asks.truncate(self.max_levels);

        self.sequence = snapshot.sequence;
        self.timestamp_ms = snapshot.timestamp_ms;
        self.bids = bids;
        self.asks = asks;
        self.resync_required = false;

        Ok(())
    }

    /// Applies a fresh snapshot to establish or advance book baseline and clear the resync latch.
    pub fn apply_snapshot(
        &mut self,
        snapshot: DepthSnapshot,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        if snapshot.sequence < self.sequence {
            return Ok(SnapshotClassification::Stale {
                sequence: snapshot.sequence,
                current: self.sequence,
            });
        }
        if snapshot.sequence == self.sequence {
            return Ok(SnapshotClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        let mut bids = snapshot.bids;
        bids.truncate(self.max_levels);
        let mut asks = snapshot.asks;
        asks.truncate(self.max_levels);

        self.sequence = snapshot.sequence;
        self.timestamp_ms = snapshot.timestamp_ms;
        self.bids = bids;
        self.asks = asks;
        self.resync_required = false;

        Ok(SnapshotClassification::Accepted {
            new_sequence: self.sequence,
        })
    }

    /// Applies an incremental depth delta to update local book state.
    /// Returns DeltaClassification representing contiguous advancement, duplicate/stale idempotency,
    /// or fail-closed ResyncRequired if a sequence gap or overlap occurs.
    pub fn apply_delta(
        &mut self,
        delta: &DepthDelta,
    ) -> Result<DeltaClassification, MarketTypeError> {
        // Sticky resync latch: fail-closed until a validated fresh snapshot / reset clears it
        if self.resync_required {
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: delta.sequence_range.start,
            });
        }

        delta.validate()?;
        if delta.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        // Stale delta: range is entirely behind current sequence
        if delta.sequence_range.end < self.sequence {
            return Ok(DeltaClassification::Stale {
                sequence: delta.sequence_range.end,
                current: self.sequence,
            });
        }

        // Duplicate delta: range ends exactly at current sequence
        if delta.sequence_range.end == self.sequence {
            return Ok(DeltaClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        // Non-contiguous delta: gap (start > current.next()) or unaligned overlap (start <= current && end > current).
        // Both fail closed, latch resync_required = true, and leave state sequence/timestamp/levels unchanged.
        if delta.sequence_range.start != self.sequence.next() {
            self.resync_required = true;
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: delta.sequence_range.start,
            });
        }

        // Stage mutation on temporary vectors to ensure atomic commit and full rollback on error
        let mut new_bids = self.bids.clone();
        let mut new_asks = self.asks.clone();

        // Apply bids: update, delete, or insert maintaining descending order
        for update in &delta.bids {
            if update.quantity.is_zero() {
                if let Some(pos) = new_bids.iter().position(|l| l.price == update.price) {
                    new_bids.remove(pos);
                }
            } else if let Some(pos) = new_bids.iter().position(|l| l.price == update.price) {
                new_bids[pos].quantity = update.quantity;
            } else {
                let pos = new_bids
                    .iter()
                    .position(|l| l.price < update.price)
                    .unwrap_or(new_bids.len());
                new_bids.insert(pos, *update);
            }
        }

        // Apply asks: update, delete, or insert maintaining ascending order
        for update in &delta.asks {
            if update.quantity.is_zero() {
                if let Some(pos) = new_asks.iter().position(|l| l.price == update.price) {
                    new_asks.remove(pos);
                }
            } else if let Some(pos) = new_asks.iter().position(|l| l.price == update.price) {
                new_asks[pos].quantity = update.quantity;
            } else {
                let pos = new_asks
                    .iter()
                    .position(|l| l.price > update.price)
                    .unwrap_or(new_asks.len());
                new_asks.insert(pos, *update);
            }
        }

        new_bids.truncate(self.max_levels);
        new_asks.truncate(self.max_levels);

        // Check crossed book on staged state BEFORE mutating self
        if let (Some(b), Some(a)) = (new_bids.first(), new_asks.first()) {
            if b.price >= a.price {
                return Err(MarketTypeError::CrossedOrderBook);
            }
        }

        // Atomic commit after all validations succeed
        self.bids = new_bids;
        self.asks = new_asks;
        self.sequence = delta.sequence_range.end;
        self.timestamp_ms = delta.timestamp_ms;

        Ok(DeltaClassification::Contiguous {
            new_sequence: self.sequence,
        })
    }

    pub fn to_snapshot(&self) -> DepthSnapshot {
        DepthSnapshot {
            target: self.target.clone(),
            sequence: self.sequence,
            timestamp_ms: self.timestamp_ms,
            bids: self.bids.clone(),
            asks: self.asks.clone(),
        }
    }
}
