//! Pure, bounded deterministic OHLCV and order book depth aggregation.
//!
//! Provides deterministic window rollup and depth maintenance over normalized
//! task-20/21 contracts (`Candle`, `DepthSnapshot`, `DepthDelta`, `CanonicalFeedEnvelope`).
//!
//! Features:
//! - Pure local aggregation with deterministic caller-supplied timestamps and window parameters.
//! - Explicit sequence tracking, monotonic contiguous enforcement, and fail-closed gap/overlap latching.
//! - Explicit deterministic freshness propagation using `SafeFreshnessMeta` and `FreshnessPolicy`.
//! - Strictly bounded retained windows (`MAX_RETAINED_WINDOWS`) and depth levels (`MAX_DEPTH_LEVELS`).
//! - Checked arithmetic on volumes, quote volumes, trade counts, and cumulative depth quantities.
//! - Full atomic rollback on malformed input, target mismatch, crossed book, or arithmetic overflow.
//! - Sticky resync latching with validated recovery requiring a newer snapshot or baseline.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::feed::{CanonicalFeedEnvelope, CanonicalFeedPayload};
use crate::freshness::{evaluate_freshness, FreshnessPolicy, SafeFreshnessMeta};
use crate::identity::{FeedTarget, InstrumentId};
use crate::ohlcv::{Candle, CandleTimeframe};
use crate::orderbook::{
    DepthDelta, DepthLevel, DepthSnapshot, NormalizedPrice, NormalizedQuantity, MAX_DEPTH_LEVELS,
};
use crate::primitives::Sequence;
use crate::sequence::{DeltaClassification, SnapshotClassification};

/// Maximum allowed retained completed windows for OHLCV aggregation.
pub const MAX_RETAINED_WINDOWS: usize = 10_000;

/// Maximum allowed price aggregation buckets for depth level grouping.
pub const MAX_AGGREGATED_BUCKETS: usize = 1_000;

// =========================================================================
// OHLCV Window Rollup Types
// =========================================================================

/// Active in-progress candle window undergoing local deterministic rollup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveCandleWindow {
    pub open_time_ms: i64,
    pub close_time_ms: i64,
    pub open: NormalizedPrice,
    pub high: NormalizedPrice,
    pub low: NormalizedPrice,
    pub close: NormalizedPrice,
    pub volume: NormalizedQuantity,
    pub quote_volume: Option<NormalizedQuantity>,
    pub trades_count: Option<u64>,
    pub last_sequence: Option<Sequence>,
    pub update_count: u64,
}

impl ActiveCandleWindow {
    /// Validates and constructs an active candle window.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        open_time_ms: i64,
        close_time_ms: i64,
        open: NormalizedPrice,
        high: NormalizedPrice,
        low: NormalizedPrice,
        close: NormalizedPrice,
        volume: NormalizedQuantity,
        quote_volume: Option<NormalizedQuantity>,
        trades_count: Option<u64>,
        last_sequence: Option<Sequence>,
    ) -> Result<Self, MarketTypeError> {
        if open_time_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(open_time_ms));
        }
        if close_time_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(close_time_ms));
        }
        if open_time_ms >= close_time_ms {
            return Err(MarketTypeError::InvalidCandleWindow {
                open_ms: open_time_ms,
                close_ms: close_time_ms,
            });
        }
        if open.is_zero() || high.is_zero() || low.is_zero() || close.is_zero() {
            return Err(MarketTypeError::ZeroPrice);
        }
        if low > open {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "low price exceeds open price",
            });
        }
        if low > close {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "low price exceeds close price",
            });
        }
        if open > high {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "open price exceeds high price",
            });
        }
        if close > high {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "close price exceeds high price",
            });
        }
        if let Some(seq) = last_sequence {
            seq.validate()?;
        }

        Ok(Self {
            open_time_ms,
            close_time_ms,
            open,
            high,
            low,
            close,
            volume,
            quote_volume,
            trades_count,
            last_sequence,
            update_count: 1,
        })
    }

    /// Converts this active window into a finalized canonical `Candle`.
    pub fn to_candle(
        &self,
        instrument: &InstrumentId,
        timeframe: CandleTimeframe,
    ) -> Result<Candle, MarketTypeError> {
        let candle = Candle {
            instrument: instrument.clone(),
            timeframe,
            open_time_ms: self.open_time_ms,
            close_time_ms: self.close_time_ms,
            open: self.open,
            high: self.high,
            low: self.low,
            close: self.close,
            volume: self.volume,
            quote_volume: self.quote_volume,
            trades_count: self.trades_count,
        };
        candle.validate()?;
        Ok(candle)
    }
}

/// Bounded deterministic OHLCV accumulator and window rollup engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OhlcvAggregator {
    instrument: InstrumentId,
    timeframe: CandleTimeframe,
    max_retained_windows: usize,
    freshness_policy: FreshnessPolicy,
    current_sequence: Option<Sequence>,
    last_timestamp_ms: Option<i64>,
    resync_required: bool,
    active_window: Option<ActiveCandleWindow>,
    retained_candles: VecDeque<Candle>,
}

impl OhlcvAggregator {
    /// Creates a new OHLCV accumulator bounded by `max_retained_windows`.
    pub fn new(
        instrument: InstrumentId,
        timeframe: CandleTimeframe,
        max_retained_windows: usize,
    ) -> Result<Self, MarketTypeError> {
        instrument.validate()?;
        if max_retained_windows == 0 || max_retained_windows > MAX_RETAINED_WINDOWS {
            return Err(MarketTypeError::RetainedWindowsExceeded {
                count: max_retained_windows,
                max: MAX_RETAINED_WINDOWS,
            });
        }
        if timeframe.duration_ms() == 0 {
            return Err(MarketTypeError::InvalidCandleTimeframe(
                "zero duration".to_string(),
            ));
        }

        Ok(Self {
            instrument,
            timeframe,
            max_retained_windows,
            freshness_policy: FreshnessPolicy::default(),
            current_sequence: None,
            last_timestamp_ms: None,
            resync_required: false,
            active_window: None,
            retained_candles: VecDeque::with_capacity(max_retained_windows.min(128)),
        })
    }

    /// Sets the deterministic freshness policy.
    pub fn with_freshness_policy(
        mut self,
        policy: FreshnessPolicy,
    ) -> Result<Self, MarketTypeError> {
        policy.validate()?;
        self.freshness_policy = policy;
        Ok(self)
    }

    pub fn instrument(&self) -> &InstrumentId {
        &self.instrument
    }

    pub fn timeframe(&self) -> CandleTimeframe {
        self.timeframe
    }

    pub fn max_retained_windows(&self) -> usize {
        self.max_retained_windows
    }

    pub fn current_sequence(&self) -> Option<Sequence> {
        self.current_sequence
    }

    pub fn last_timestamp_ms(&self) -> Option<i64> {
        self.last_timestamp_ms
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    pub fn active_window(&self) -> Option<&ActiveCandleWindow> {
        self.active_window.as_ref()
    }

    pub fn retained_candles(&self) -> &VecDeque<Candle> {
        &self.retained_candles
    }

    pub fn retained_count(&self) -> usize {
        self.retained_candles.len()
    }

    /// Evaluates data freshness against a caller-supplied deterministic timestamp.
    pub fn evaluate_freshness(
        &self,
        evaluated_at_ms: i64,
    ) -> Result<SafeFreshnessMeta, MarketTypeError> {
        let obs = self
            .last_timestamp_ms
            .ok_or(MarketTypeError::MissingBaselineSnapshot)?;
        let seq = self.current_sequence.unwrap_or(Sequence(1));
        evaluate_freshness(
            &self.freshness_policy,
            obs,
            evaluated_at_ms,
            seq,
            self.resync_required,
        )
    }

    /// Resets aggregator baseline with a validated candle and sequence, clearing sticky resync.
    pub fn reset_with_baseline(
        &mut self,
        sequence: Sequence,
        candle: &Candle,
    ) -> Result<(), MarketTypeError> {
        candle.validate()?;
        sequence.validate()?;
        if candle.instrument != self.instrument {
            return Err(MarketTypeError::TargetMismatch);
        }

        if let Some(curr) = self.current_sequence {
            if sequence <= curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: sequence.0,
                    current: curr.0,
                });
            }
        }

        let w = self.timeframe.duration_ms() as i64;
        let win_open = (candle.open_time_ms / w) * w;
        let win_close = win_open + w;

        let active = ActiveCandleWindow {
            open_time_ms: win_open,
            close_time_ms: win_close,
            open: candle.open,
            high: candle.high,
            low: candle.low,
            close: candle.close,
            volume: candle.volume,
            quote_volume: candle.quote_volume,
            trades_count: candle.trades_count,
            last_sequence: Some(sequence),
            update_count: 1,
        };

        self.active_window = Some(active);
        self.current_sequence = Some(sequence);
        self.last_timestamp_ms = Some(candle.close_time_ms);
        self.resync_required = false;

        Ok(())
    }

    /// Ingests an incoming normalized `Candle`, performing deterministic window rollup.
    ///
    /// Evaluates monotonic sequencing if `sequence` is provided.
    /// On failure (e.g. arithmetic overflow, sequence gap/overlap, malformed candle),
    /// fails closed with atomic rollback and latches sticky resync when appropriate.
    pub fn apply_candle(
        &mut self,
        candle: &Candle,
        sequence: Option<Sequence>,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.resync_required {
            let expected = self
                .current_sequence
                .map(|s| s.next())
                .unwrap_or(Sequence(1));
            let received = sequence.unwrap_or(expected);
            return Ok(DeltaClassification::ResyncRequired { expected, received });
        }

        candle.validate()?;
        if candle.instrument != self.instrument {
            return Err(MarketTypeError::TargetMismatch);
        }

        let win_duration_ms = self.timeframe.duration_ms();
        let candle_duration_ms = (candle.close_time_ms - candle.open_time_ms) as u64;
        if candle_duration_ms > win_duration_ms {
            return Err(MarketTypeError::CandleWindowExceeded {
                duration_ms: candle_duration_ms,
                max_ms: win_duration_ms,
            });
        }

        // Evaluate monotonic sequencing if sequence is provided
        if let (Some(curr), Some(seq)) = (self.current_sequence, sequence) {
            seq.validate()?;
            if seq < curr {
                return Ok(DeltaClassification::Stale {
                    sequence: seq,
                    current: curr,
                });
            }
            if seq == curr {
                return Ok(DeltaClassification::Duplicate { sequence: curr });
            }
            if seq != curr.next() {
                // Sequence gap detected: latch sticky resync and preserve state atomically
                self.resync_required = true;
                return Ok(DeltaClassification::ResyncRequired {
                    expected: curr.next(),
                    received: seq,
                });
            }
        }

        let w = win_duration_ms as i64;
        let target_open = (candle.open_time_ms / w) * w;
        let target_close = target_open + w;

        if candle.close_time_ms > target_close {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "candle window crosses aggregation timeframe boundary",
            });
        }

        // Stage the entire update on a local clone to guarantee 100% atomic rollback
        let mut staged_active = self.active_window.clone();
        let mut staged_retained = self.retained_candles.clone();

        match staged_active.as_mut() {
            Some(active) => {
                if target_open < active.open_time_ms {
                    return Err(MarketTypeError::StaleCandleWindow {
                        candle_open_ms: candle.open_time_ms,
                        current_close_ms: active.close_time_ms,
                    });
                } else if target_open == active.open_time_ms {
                    // Intra-window rollup with checked arithmetic
                    let new_vol_val = active.volume.get() + candle.volume.get();
                    if !new_vol_val.is_finite() {
                        return Err(MarketTypeError::ArithmeticOverflow(
                            "candle volume accumulation overflow",
                        ));
                    }
                    let new_vol = NormalizedQuantity::new(new_vol_val)?;

                    let new_quote_vol = match (active.quote_volume, candle.quote_volume) {
                        (Some(q1), Some(q2)) => {
                            let sum = q1.get() + q2.get();
                            if !sum.is_finite() {
                                return Err(MarketTypeError::ArithmeticOverflow(
                                    "candle quote volume accumulation overflow",
                                ));
                            }
                            Some(NormalizedQuantity::new(sum)?)
                        }
                        (Some(q), None) | (None, Some(q)) => Some(q),
                        (None, None) => None,
                    };

                    let new_trades =
                        match (active.trades_count, candle.trades_count) {
                            (Some(t1), Some(t2)) => Some(t1.checked_add(t2).ok_or(
                                MarketTypeError::ArithmeticOverflow("trades count overflow"),
                            )?),
                            (Some(t), None) | (None, Some(t)) => Some(t),
                            (None, None) => None,
                        };

                    active.high = active.high.max(candle.high);
                    active.low = active.low.min(candle.low);
                    active.close = candle.close;
                    active.volume = new_vol;
                    active.quote_volume = new_quote_vol;
                    active.trades_count = new_trades;
                    active.last_sequence = sequence.or(active.last_sequence);
                    active.update_count = active
                        .update_count
                        .checked_add(1)
                        .ok_or(MarketTypeError::ArithmeticOverflow("update count overflow"))?;
                } else {
                    // Window rollover: finalize current active window and push to bounded retained deque
                    let finalized = active.to_candle(&self.instrument, self.timeframe)?;
                    staged_retained.push_back(finalized);
                    if staged_retained.len() > self.max_retained_windows {
                        staged_retained.pop_front();
                    }

                    // Open new window
                    let new_active = ActiveCandleWindow {
                        open_time_ms: target_open,
                        close_time_ms: target_close,
                        open: candle.open,
                        high: candle.high,
                        low: candle.low,
                        close: candle.close,
                        volume: candle.volume,
                        quote_volume: candle.quote_volume,
                        trades_count: candle.trades_count,
                        last_sequence: sequence,
                        update_count: 1,
                    };
                    staged_active = Some(new_active);
                }
            }
            None => {
                if let Some(last_ts) = self.last_timestamp_ms {
                    if candle.open_time_ms < last_ts {
                        return Err(MarketTypeError::StaleCandleWindow {
                            candle_open_ms: candle.open_time_ms,
                            current_close_ms: last_ts,
                        });
                    }
                }

                let new_active = ActiveCandleWindow {
                    open_time_ms: target_open,
                    close_time_ms: target_close,
                    open: candle.open,
                    high: candle.high,
                    low: candle.low,
                    close: candle.close,
                    volume: candle.volume,
                    quote_volume: candle.quote_volume,
                    trades_count: candle.trades_count,
                    last_sequence: sequence,
                    update_count: 1,
                };
                staged_active = Some(new_active);
            }
        }

        // Atomic commit
        self.active_window = staged_active;
        self.retained_candles = staged_retained;
        if let Some(seq) = sequence {
            self.current_sequence = Some(seq);
        }
        self.last_timestamp_ms = Some(candle.close_time_ms);

        let new_seq = self.current_sequence.unwrap_or(Sequence(1));
        Ok(DeltaClassification::Contiguous {
            new_sequence: new_seq,
        })
    }

    /// Applies a single price tick or trade observation into the OHLCV window.
    pub fn apply_tick(
        &mut self,
        price: NormalizedPrice,
        quantity: NormalizedQuantity,
        timestamp_ms: i64,
        sequence: Option<Sequence>,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        if price.is_zero() {
            return Err(MarketTypeError::ZeroPrice);
        }

        let candle = Candle {
            instrument: self.instrument.clone(),
            timeframe: self.timeframe,
            open_time_ms: timestamp_ms,
            close_time_ms: timestamp_ms.checked_add(1).ok_or(
                MarketTypeError::ArithmeticOverflow("timestamp overflow on tick close"),
            )?,
            open: price,
            high: price,
            low: price,
            close: price,
            volume: quantity,
            quote_volume: None,
            trades_count: Some(1),
        };

        self.apply_candle(&candle, sequence)
    }

    /// Dispatches a canonical feed envelope to OHLCV rollup.
    pub fn apply_envelope(
        &mut self,
        envelope: &CanonicalFeedEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        match &envelope.payload {
            CanonicalFeedPayload::Candle(candle) => {
                let seq = envelope.freshness.sequence;
                self.apply_candle(candle, Some(seq))
            }
            CanonicalFeedPayload::OrderBookSnapshot(snap) => {
                let snap_target = match &snap.target {
                    FeedTarget::Instrument(inst) => inst,
                    FeedTarget::Pool(_) => {
                        return Err(MarketTypeError::UnsupportedPayloadForTarget(
                            "pool snapshot for instrument ohlcv",
                        ));
                    }
                };
                if *snap_target != self.instrument {
                    return Err(MarketTypeError::TargetMismatch);
                }
                if let (Some(bid), Some(ask)) = (snap.bids.first(), snap.asks.first()) {
                    let mid = (bid.price.get() + ask.price.get()) / 2.0;
                    let mid_price = NormalizedPrice::new(mid)?;
                    let qty = NormalizedQuantity::new(0.0)?;
                    self.apply_tick(mid_price, qty, snap.timestamp_ms, Some(snap.sequence))
                } else {
                    Ok(DeltaClassification::Duplicate {
                        sequence: snap.sequence,
                    })
                }
            }
            CanonicalFeedPayload::OrderBookDelta(delta) => {
                let delta_target = match &delta.target {
                    FeedTarget::Instrument(inst) => inst,
                    FeedTarget::Pool(_) => {
                        return Err(MarketTypeError::UnsupportedPayloadForTarget(
                            "pool delta for instrument ohlcv",
                        ));
                    }
                };
                if *delta_target != self.instrument {
                    return Err(MarketTypeError::TargetMismatch);
                }
                if let (Some(bid), Some(ask)) = (delta.bids.first(), delta.asks.first()) {
                    let mid = (bid.price.get() + ask.price.get()) / 2.0;
                    let mid_price = NormalizedPrice::new(mid)?;
                    let qty = NormalizedQuantity::new(0.0)?;
                    self.apply_tick(
                        mid_price,
                        qty,
                        delta.timestamp_ms,
                        Some(delta.sequence_range.end),
                    )
                } else {
                    Ok(DeltaClassification::Duplicate {
                        sequence: delta.sequence_range.end,
                    })
                }
            }
            CanonicalFeedPayload::PoolState(_) => {
                Err(MarketTypeError::UnsupportedPayloadForTarget("pool state"))
            }
        }
    }

    /// Deterministically flushes the current active window into the retained candles deque.
    pub fn flush_active_window(&mut self) -> Result<Option<Candle>, MarketTypeError> {
        if let Some(active) = self.active_window.take() {
            let candle = active.to_candle(&self.instrument, self.timeframe)?;
            self.retained_candles.push_back(candle.clone());
            if self.retained_candles.len() > self.max_retained_windows {
                self.retained_candles.pop_front();
            }
            Ok(Some(candle))
        } else {
            Ok(None)
        }
    }
}

// =========================================================================
// Depth Aggregation Types
// =========================================================================

/// Cumulative depth level with verified checked arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CumulativeDepthLevel {
    pub price: NormalizedPrice,
    pub quantity: NormalizedQuantity,
    pub cumulative_quantity: NormalizedQuantity,
    pub cumulative_notional: f64,
}

/// Aggregated depth level grouped into tick/price bucket.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregatedDepthLevel {
    pub price: NormalizedPrice,
    pub quantity: NormalizedQuantity,
    pub orders_or_levels_count: usize,
}

/// Aggregated order book depth snapshot bundle preserving sequence, freshness, and metrics.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregatedDepthSnapshot {
    pub target: FeedTarget,
    pub sequence: Sequence,
    pub timestamp_ms: i64,
    pub freshness: SafeFreshnessMeta,
    pub resync_required: bool,
    pub bids: Vec<DepthLevel>,
    pub asks: Vec<DepthLevel>,
    pub cumulative_bids: Vec<CumulativeDepthLevel>,
    pub cumulative_asks: Vec<CumulativeDepthLevel>,
    pub total_bid_quantity: NormalizedQuantity,
    pub total_ask_quantity: NormalizedQuantity,
    pub best_bid: Option<DepthLevel>,
    pub best_ask: Option<DepthLevel>,
    pub spread: Option<f64>,
    pub mid_price: Option<NormalizedPrice>,
    pub weighted_mid_price: Option<NormalizedPrice>,
}

/// Aggregated depth book bucketed by tick size.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AggregatedDepthBook {
    pub target: FeedTarget,
    pub sequence: Sequence,
    pub timestamp_ms: i64,
    pub tick_size: NormalizedPrice,
    pub bids: Vec<AggregatedDepthLevel>,
    pub asks: Vec<AggregatedDepthLevel>,
    pub spread: Option<f64>,
    pub mid_price: Option<NormalizedPrice>,
    pub total_bid_quantity: NormalizedQuantity,
    pub total_ask_quantity: NormalizedQuantity,
}

/// Bounded deterministic order book depth accumulator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthAggregator {
    target: FeedTarget,
    sequence: Option<Sequence>,
    timestamp_ms: Option<i64>,
    bids: Vec<DepthLevel>,
    asks: Vec<DepthLevel>,
    max_levels: usize,
    freshness_policy: FreshnessPolicy,
    resync_required: bool,
}

impl DepthAggregator {
    /// Creates a new depth accumulator for `target` bounded by `max_levels`.
    pub fn new(target: FeedTarget, max_levels: usize) -> Result<Self, MarketTypeError> {
        target.validate()?;
        if max_levels == 0 || max_levels > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: max_levels,
                max: MAX_DEPTH_LEVELS,
            });
        }

        Ok(Self {
            target,
            sequence: None,
            timestamp_ms: None,
            bids: Vec::new(),
            asks: Vec::new(),
            max_levels,
            freshness_policy: FreshnessPolicy::default(),
            resync_required: false,
        })
    }

    /// Initializes accumulator baseline directly from a validated `DepthSnapshot`.
    pub fn from_snapshot(
        snapshot: &DepthSnapshot,
        max_levels: usize,
    ) -> Result<Self, MarketTypeError> {
        let mut agg = Self::new(snapshot.target.clone(), max_levels)?;
        agg.apply_snapshot(snapshot)?;
        Ok(agg)
    }

    /// Sets the deterministic freshness policy.
    pub fn with_freshness_policy(
        mut self,
        policy: FreshnessPolicy,
    ) -> Result<Self, MarketTypeError> {
        policy.validate()?;
        self.freshness_policy = policy;
        Ok(self)
    }

    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    pub fn sequence(&self) -> Option<Sequence> {
        self.sequence
    }

    pub fn timestamp_ms(&self) -> Option<i64> {
        self.timestamp_ms
    }

    pub fn max_levels(&self) -> usize {
        self.max_levels
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
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

    /// Volume-weighted mid-price (microprice) calculated using top-of-book liquidity:
    /// `(P_bid * Q_ask + P_ask * Q_bid) / (Q_bid + Q_ask)`
    pub fn weighted_mid_price(&self) -> Option<NormalizedPrice> {
        match (self.best_bid(), self.best_ask()) {
            (Some(bid), Some(ask)) => {
                let q_bid = bid.quantity.get();
                let q_ask = ask.quantity.get();
                let denom = q_bid + q_ask;
                if denom == 0.0 || !denom.is_finite() {
                    return None;
                }
                let num = (bid.price.get() * q_ask) + (ask.price.get() * q_bid);
                if !num.is_finite() {
                    return None;
                }
                NormalizedPrice::new(num / denom).ok()
            }
            _ => None,
        }
    }

    /// Computes total bid depth liquidity with checked arithmetic.
    pub fn total_bid_quantity(&self) -> Result<NormalizedQuantity, MarketTypeError> {
        let mut total = 0.0f64;
        for b in &self.bids {
            total += b.quantity.get();
            if !total.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "bid total quantity overflow",
                ));
            }
        }
        NormalizedQuantity::new(total)
    }

    /// Computes total ask depth liquidity with checked arithmetic.
    pub fn total_ask_quantity(&self) -> Result<NormalizedQuantity, MarketTypeError> {
        let mut total = 0.0f64;
        for a in &self.asks {
            total += a.quantity.get();
            if !total.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "ask total quantity overflow",
                ));
            }
        }
        NormalizedQuantity::new(total)
    }

    /// Computes cumulative bid depth with checked arithmetic for quantity and notional value.
    pub fn cumulative_bids(&self) -> Result<Vec<CumulativeDepthLevel>, MarketTypeError> {
        let mut cum_qty = 0.0f64;
        let mut cum_notional = 0.0f64;
        let mut result = Vec::with_capacity(self.bids.len());

        for level in &self.bids {
            cum_qty += level.quantity.get();
            if !cum_qty.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "cumulative bid quantity overflow",
                ));
            }
            let notional = level.price.get() * level.quantity.get();
            if !notional.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "level notional overflow",
                ));
            }
            cum_notional += notional;
            if !cum_notional.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "cumulative bid notional overflow",
                ));
            }

            result.push(CumulativeDepthLevel {
                price: level.price,
                quantity: level.quantity,
                cumulative_quantity: NormalizedQuantity::new(cum_qty)?,
                cumulative_notional: cum_notional,
            });
        }

        Ok(result)
    }

    /// Computes cumulative ask depth with checked arithmetic for quantity and notional value.
    pub fn cumulative_asks(&self) -> Result<Vec<CumulativeDepthLevel>, MarketTypeError> {
        let mut cum_qty = 0.0f64;
        let mut cum_notional = 0.0f64;
        let mut result = Vec::with_capacity(self.asks.len());

        for level in &self.asks {
            cum_qty += level.quantity.get();
            if !cum_qty.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "cumulative ask quantity overflow",
                ));
            }
            let notional = level.price.get() * level.quantity.get();
            if !notional.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "level notional overflow",
                ));
            }
            cum_notional += notional;
            if !cum_notional.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "cumulative ask notional overflow",
                ));
            }

            result.push(CumulativeDepthLevel {
                price: level.price,
                quantity: level.quantity,
                cumulative_quantity: NormalizedQuantity::new(cum_qty)?,
                cumulative_notional: cum_notional,
            });
        }

        Ok(result)
    }

    /// Aggregates order book depth levels into price buckets aligned to `tick_size`.
    pub fn aggregate_by_tick_size(
        &self,
        tick_size: NormalizedPrice,
        max_buckets: usize,
    ) -> Result<AggregatedDepthBook, MarketTypeError> {
        if tick_size.is_zero() {
            return Err(MarketTypeError::ZeroPrice);
        }
        if max_buckets == 0 || max_buckets > MAX_AGGREGATED_BUCKETS {
            return Err(MarketTypeError::AggregatedBucketsExceeded {
                count: max_buckets,
                max: MAX_AGGREGATED_BUCKETS,
            });
        }

        let step = tick_size.get();

        // Aggregate bids (grouping down to bucket floor)
        let mut bid_buckets: Vec<AggregatedDepthLevel> = Vec::new();
        for level in &self.bids {
            let bucket_price_val = (level.price.get() / step).floor() * step;
            let bucket_price = NormalizedPrice::new(bucket_price_val)?;

            if let Some(last) = bid_buckets.last_mut() {
                if last.price == bucket_price {
                    let new_qty = last.quantity.get() + level.quantity.get();
                    if !new_qty.is_finite() {
                        return Err(MarketTypeError::ArithmeticOverflow(
                            "bucket quantity accumulation overflow",
                        ));
                    }
                    last.quantity = NormalizedQuantity::new(new_qty)?;
                    last.orders_or_levels_count += 1;
                    continue;
                }
            }

            if bid_buckets.len() >= max_buckets {
                break;
            }

            bid_buckets.push(AggregatedDepthLevel {
                price: bucket_price,
                quantity: level.quantity,
                orders_or_levels_count: 1,
            });
        }

        // Aggregate asks (grouping up to bucket ceiling)
        let mut ask_buckets: Vec<AggregatedDepthLevel> = Vec::new();
        for level in &self.asks {
            let bucket_price_val = (level.price.get() / step).ceil() * step;
            let bucket_price = NormalizedPrice::new(bucket_price_val)?;

            if let Some(last) = ask_buckets.last_mut() {
                if last.price == bucket_price {
                    let new_qty = last.quantity.get() + level.quantity.get();
                    if !new_qty.is_finite() {
                        return Err(MarketTypeError::ArithmeticOverflow(
                            "bucket quantity accumulation overflow",
                        ));
                    }
                    last.quantity = NormalizedQuantity::new(new_qty)?;
                    last.orders_or_levels_count += 1;
                    continue;
                }
            }

            if ask_buckets.len() >= max_buckets {
                break;
            }

            ask_buckets.push(AggregatedDepthLevel {
                price: bucket_price,
                quantity: level.quantity,
                orders_or_levels_count: 1,
            });
        }

        let total_bids = self.total_bid_quantity()?;
        let total_asks = self.total_ask_quantity()?;

        Ok(AggregatedDepthBook {
            target: self.target.clone(),
            sequence: self.sequence.unwrap_or(Sequence(1)),
            timestamp_ms: self.timestamp_ms.unwrap_or(0),
            tick_size,
            bids: bid_buckets,
            asks: ask_buckets,
            spread: self.spread(),
            mid_price: self.mid_price(),
            total_bid_quantity: total_bids,
            total_ask_quantity: total_asks,
        })
    }

    /// Evaluates freshness metadata against a caller-supplied timestamp.
    pub fn evaluate_freshness(
        &self,
        evaluated_at_ms: i64,
    ) -> Result<SafeFreshnessMeta, MarketTypeError> {
        let obs = self
            .timestamp_ms
            .ok_or(MarketTypeError::MissingBaselineSnapshot)?;
        let seq = self.sequence.unwrap_or(Sequence(1));
        evaluate_freshness(
            &self.freshness_policy,
            obs,
            evaluated_at_ms,
            seq,
            self.resync_required,
        )
    }

    /// Generates a comprehensive aggregated snapshot bundle.
    pub fn to_aggregated_snapshot(
        &self,
        evaluated_at_ms: i64,
    ) -> Result<AggregatedDepthSnapshot, MarketTypeError> {
        let freshness = self.evaluate_freshness(evaluated_at_ms)?;
        let cumulative_bids = self.cumulative_bids()?;
        let cumulative_asks = self.cumulative_asks()?;
        let total_bid_quantity = self.total_bid_quantity()?;
        let total_ask_quantity = self.total_ask_quantity()?;

        Ok(AggregatedDepthSnapshot {
            target: self.target.clone(),
            sequence: self.sequence.unwrap_or(Sequence(1)),
            timestamp_ms: self.timestamp_ms.unwrap_or(0),
            freshness,
            resync_required: self.resync_required,
            bids: self.bids.clone(),
            asks: self.asks.clone(),
            cumulative_bids,
            cumulative_asks,
            total_bid_quantity,
            total_ask_quantity,
            best_bid: self.best_bid().copied(),
            best_ask: self.best_ask().copied(),
            spread: self.spread(),
            mid_price: self.mid_price(),
            weighted_mid_price: self.weighted_mid_price(),
        })
    }

    /// Explicitly resets book state from a validated fresh snapshot, clearing sticky resync.
    pub fn reset_with_snapshot(&mut self, snapshot: &DepthSnapshot) -> Result<(), MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        let mut bids = snapshot.bids.clone();
        bids.truncate(self.max_levels);
        let mut asks = snapshot.asks.clone();
        asks.truncate(self.max_levels);

        self.sequence = Some(snapshot.sequence);
        self.timestamp_ms = Some(snapshot.timestamp_ms);
        self.bids = bids;
        self.asks = asks;
        self.resync_required = false;

        Ok(())
    }

    /// Applies a snapshot to establish or advance depth baseline.
    /// A strictly newer snapshot clears sticky resync.
    pub fn apply_snapshot(
        &mut self,
        snapshot: &DepthSnapshot,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        if let Some(curr) = self.sequence {
            if snapshot.sequence < curr {
                return Ok(SnapshotClassification::Stale {
                    sequence: snapshot.sequence,
                    current: curr,
                });
            }
            if snapshot.sequence == curr {
                return Ok(SnapshotClassification::Duplicate { sequence: curr });
            }
        }

        let mut bids = snapshot.bids.clone();
        bids.truncate(self.max_levels);
        let mut asks = snapshot.asks.clone();
        asks.truncate(self.max_levels);

        // Verify checked arithmetic on staged snapshot
        let mut b_sum = 0.0f64;
        for b in &bids {
            b_sum += b.quantity.get();
            if !b_sum.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "snapshot bid quantity overflow",
                ));
            }
        }
        let mut a_sum = 0.0f64;
        for a in &asks {
            a_sum += a.quantity.get();
            if !a_sum.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "snapshot ask quantity overflow",
                ));
            }
        }

        self.sequence = Some(snapshot.sequence);
        self.timestamp_ms = Some(snapshot.timestamp_ms);
        self.bids = bids;
        self.asks = asks;
        self.resync_required = false;

        Ok(SnapshotClassification::Accepted {
            new_sequence: snapshot.sequence,
        })
    }

    /// Applies an incremental depth delta.
    ///
    /// Monotonic contiguous sequencing is enforced. Gaps and unaligned overlaps fail closed,
    /// latching sticky resync with atomic rollback (preserving pre-delta state).
    pub fn apply_delta(
        &mut self,
        delta: &DepthDelta,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.resync_required {
            let expected = self.sequence.map(|s| s.next()).unwrap_or(Sequence(1));
            return Ok(DeltaClassification::ResyncRequired {
                expected,
                received: delta.sequence_range.start,
            });
        }

        delta.validate()?;
        if delta.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        let curr = match self.sequence {
            Some(c) => c,
            None => {
                // Delta cannot be applied without an established baseline snapshot!
                self.resync_required = true;
                return Ok(DeltaClassification::ResyncRequired {
                    expected: Sequence(1),
                    received: delta.sequence_range.start,
                });
            }
        };

        if delta.sequence_range.end < curr {
            return Ok(DeltaClassification::Stale {
                sequence: delta.sequence_range.end,
                current: curr,
            });
        }
        if delta.sequence_range.end == curr {
            return Ok(DeltaClassification::Duplicate { sequence: curr });
        }
        if delta.sequence_range.start != curr.next() {
            // Sequence gap or unaligned overlap: fail closed, latch sticky resync, rollback state
            self.resync_required = true;
            return Ok(DeltaClassification::ResyncRequired {
                expected: curr.next(),
                received: delta.sequence_range.start,
            });
        }

        // Stage mutations on temporary copies to guarantee atomic rollback on any failure
        let mut new_bids = self.bids.clone();
        let mut new_asks = self.asks.clone();

        // Apply bids
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

        // Apply asks
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

        // Check crossed order book on staged state
        if let (Some(b), Some(a)) = (new_bids.first(), new_asks.first()) {
            if b.price >= a.price {
                return Err(MarketTypeError::CrossedOrderBook);
            }
        }

        // Checked arithmetic verification on staged state
        let mut b_sum = 0.0f64;
        for b in &new_bids {
            b_sum += b.quantity.get();
            if !b_sum.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "staged bid quantity overflow",
                ));
            }
        }
        let mut a_sum = 0.0f64;
        for a in &new_asks {
            a_sum += a.quantity.get();
            if !a_sum.is_finite() {
                return Err(MarketTypeError::ArithmeticOverflow(
                    "staged ask quantity overflow",
                ));
            }
        }

        // Commit atomically
        self.bids = new_bids;
        self.asks = new_asks;
        self.sequence = Some(delta.sequence_range.end);
        self.timestamp_ms = Some(delta.timestamp_ms);

        Ok(DeltaClassification::Contiguous {
            new_sequence: delta.sequence_range.end,
        })
    }

    /// Dispatches a canonical feed envelope to depth aggregation.
    pub fn apply_envelope(
        &mut self,
        envelope: &CanonicalFeedEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        match &envelope.payload {
            CanonicalFeedPayload::OrderBookSnapshot(snap) => {
                let class = self.apply_snapshot(snap)?;
                match class {
                    SnapshotClassification::Accepted { new_sequence } => {
                        Ok(DeltaClassification::Contiguous { new_sequence })
                    }
                    SnapshotClassification::Duplicate { sequence } => {
                        Ok(DeltaClassification::Duplicate { sequence })
                    }
                    SnapshotClassification::Stale { sequence, current } => {
                        Ok(DeltaClassification::Stale { sequence, current })
                    }
                }
            }
            CanonicalFeedPayload::OrderBookDelta(delta) => self.apply_delta(delta),
            CanonicalFeedPayload::Candle(_) => Err(MarketTypeError::UnsupportedPayloadForTarget(
                "candle payload for depth aggregator",
            )),
            CanonicalFeedPayload::PoolState(_) => {
                Err(MarketTypeError::UnsupportedPayloadForTarget(
                    "pool state payload for depth aggregator",
                ))
            }
        }
    }
}

// =========================================================================
// Unified Market Aggregator
// =========================================================================

/// Unified bounded aggregator coordinating local depth and OHLCV rollup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketAggregator {
    target: FeedTarget,
    depth: DepthAggregator,
    ohlcv: Option<OhlcvAggregator>,
}

impl MarketAggregator {
    /// Creates a unified aggregator for an instrument target with depth and OHLCV rollup.
    pub fn for_instrument(
        instrument: InstrumentId,
        timeframe: CandleTimeframe,
        max_depth_levels: usize,
        max_retained_windows: usize,
    ) -> Result<Self, MarketTypeError> {
        let target = FeedTarget::Instrument(instrument.clone());
        let depth = DepthAggregator::new(target.clone(), max_depth_levels)?;
        let ohlcv = OhlcvAggregator::new(instrument, timeframe, max_retained_windows)?;

        Ok(Self {
            target,
            depth,
            ohlcv: Some(ohlcv),
        })
    }

    /// Creates a unified aggregator for a pool target with depth aggregation.
    pub fn for_pool(
        pool_target: FeedTarget,
        max_depth_levels: usize,
    ) -> Result<Self, MarketTypeError> {
        pool_target.validate()?;
        let depth = DepthAggregator::new(pool_target.clone(), max_depth_levels)?;

        Ok(Self {
            target: pool_target,
            depth,
            ohlcv: None,
        })
    }

    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    pub fn depth(&self) -> &DepthAggregator {
        &self.depth
    }

    pub fn depth_mut(&mut self) -> &mut DepthAggregator {
        &mut self.depth
    }

    pub fn ohlcv(&self) -> Option<&OhlcvAggregator> {
        self.ohlcv.as_ref()
    }

    pub fn ohlcv_mut(&mut self) -> Option<&mut OhlcvAggregator> {
        self.ohlcv.as_mut()
    }

    pub fn is_resync_required(&self) -> bool {
        self.depth.is_resync_required()
            || self.ohlcv.as_ref().is_some_and(|o| o.is_resync_required())
    }

    pub fn trigger_resync(&mut self) {
        self.depth.trigger_resync();
        if let Some(ref mut o) = self.ohlcv {
            o.trigger_resync();
        }
    }

    /// Evaluates freshness for the unified market stream.
    pub fn evaluate_freshness(
        &self,
        evaluated_at_ms: i64,
    ) -> Result<SafeFreshnessMeta, MarketTypeError> {
        self.depth.evaluate_freshness(evaluated_at_ms)
    }

    /// Explicitly resets unified book and OHLCV state from a validated fresh snapshot, clearing sticky resync.
    pub fn reset_with_snapshot(&mut self, snapshot: &DepthSnapshot) -> Result<(), MarketTypeError> {
        let mut staged_depth = self.depth.clone();
        let mut staged_ohlcv = self.ohlcv.clone();

        staged_depth.reset_with_snapshot(snapshot)?;

        if let Some(ref mut ohlcv) = staged_ohlcv {
            let mid = staged_depth
                .mid_price()
                .ok_or(MarketTypeError::EmptyDepthLevels)?;
            let candle = Candle {
                instrument: ohlcv.instrument().clone(),
                timeframe: ohlcv.timeframe(),
                open_time_ms: snapshot.timestamp_ms,
                close_time_ms: snapshot.timestamp_ms.checked_add(1).ok_or(
                    MarketTypeError::ArithmeticOverflow("timestamp overflow on tick close"),
                )?,
                open: mid,
                high: mid,
                low: mid,
                close: mid,
                volume: NormalizedQuantity::new(0.0)?,
                quote_volume: None,
                trades_count: Some(1),
            };
            ohlcv.reset_with_baseline(snapshot.sequence, &candle)?;
        }

        self.depth = staged_depth;
        self.ohlcv = staged_ohlcv;
        Ok(())
    }

    /// Ingests a canonical feed envelope, routing to depth and/or OHLCV aggregators.
    ///
    /// Unified depth and OHLCV mutations are atomic and fail-closed: any failure in depth or
    /// OHLCV (such as arithmetic overflow, window violation, malformed input, or sequence gap)
    /// leaves both components completely unchanged, and never returns a successful classification
    /// after partial mutation. Sticky resync semantics and recovery behavior are consistently
    /// maintained across both components.
    pub fn apply_envelope(
        &mut self,
        envelope: &CanonicalFeedEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        match &envelope.payload {
            CanonicalFeedPayload::OrderBookSnapshot(snap) => {
                let mut staged_depth = self.depth.clone();
                let mut staged_ohlcv = self.ohlcv.clone();

                let class = staged_depth.apply_snapshot(snap)?;
                match class {
                    SnapshotClassification::Accepted { new_sequence } => {
                        if let Some(ref mut ohlcv) = staged_ohlcv {
                            let mid = staged_depth
                                .mid_price()
                                .ok_or(MarketTypeError::EmptyDepthLevels)?;

                            let is_recovery = self.is_resync_required()
                                || ohlcv.is_resync_required()
                                || ohlcv.current_sequence().is_none()
                                || ohlcv
                                    .current_sequence()
                                    .map(|s| snap.sequence > s.next())
                                    .unwrap_or(false);

                            if is_recovery {
                                let candle = Candle {
                                    instrument: ohlcv.instrument().clone(),
                                    timeframe: ohlcv.timeframe(),
                                    open_time_ms: snap.timestamp_ms,
                                    close_time_ms: snap.timestamp_ms.checked_add(1).ok_or(
                                        MarketTypeError::ArithmeticOverflow(
                                            "timestamp overflow on tick close",
                                        ),
                                    )?,
                                    open: mid,
                                    high: mid,
                                    low: mid,
                                    close: mid,
                                    volume: NormalizedQuantity::new(0.0)?,
                                    quote_volume: None,
                                    trades_count: Some(1),
                                };
                                ohlcv.reset_with_baseline(snap.sequence, &candle)?;
                            } else {
                                let tick_class = ohlcv.apply_tick(
                                    mid,
                                    NormalizedQuantity::new(0.0)?,
                                    snap.timestamp_ms,
                                    Some(snap.sequence),
                                )?;
                                if matches!(tick_class, DeltaClassification::ResyncRequired { .. })
                                {
                                    return Ok(tick_class);
                                }
                            }
                        }

                        // Atomic commit: only commit when both depth and OHLCV succeed
                        self.depth = staged_depth;
                        self.ohlcv = staged_ohlcv;
                        Ok(DeltaClassification::Contiguous { new_sequence })
                    }
                    SnapshotClassification::Duplicate { sequence } => {
                        Ok(DeltaClassification::Duplicate { sequence })
                    }
                    SnapshotClassification::Stale { sequence, current } => {
                        Ok(DeltaClassification::Stale { sequence, current })
                    }
                }
            }
            CanonicalFeedPayload::OrderBookDelta(delta) => {
                if self.is_resync_required() {
                    let expected = self
                        .depth
                        .sequence()
                        .map(|s| s.next())
                        .unwrap_or(Sequence(1));
                    return Ok(DeltaClassification::ResyncRequired {
                        expected,
                        received: delta.sequence_range.start,
                    });
                }

                let mut staged_depth = self.depth.clone();
                let mut staged_ohlcv = self.ohlcv.clone();

                let class = staged_depth.apply_delta(delta)?;
                match class {
                    DeltaClassification::Contiguous { .. } => {
                        if let Some(ref mut ohlcv) = staged_ohlcv {
                            let mid = staged_depth
                                .mid_price()
                                .ok_or(MarketTypeError::EmptyDepthLevels)?;
                            let tick_class = ohlcv.apply_tick(
                                mid,
                                NormalizedQuantity::new(0.0)?,
                                delta.timestamp_ms,
                                Some(delta.sequence_range.end),
                            )?;
                            if matches!(tick_class, DeltaClassification::ResyncRequired { .. }) {
                                return Ok(tick_class);
                            }
                        }

                        // Atomic commit: only commit when both depth and OHLCV succeed
                        self.depth = staged_depth;
                        self.ohlcv = staged_ohlcv;
                        Ok(class)
                    }
                    DeltaClassification::ResyncRequired { expected, received } => {
                        // Depth encountered sequence gap/overlap: latch resync across both components
                        if let Some(ref mut ohlcv) = staged_ohlcv {
                            ohlcv.trigger_resync();
                        }
                        self.depth = staged_depth;
                        self.ohlcv = staged_ohlcv;
                        Ok(DeltaClassification::ResyncRequired { expected, received })
                    }
                    DeltaClassification::Duplicate { .. } | DeltaClassification::Stale { .. } => {
                        Ok(class)
                    }
                }
            }
            CanonicalFeedPayload::Candle(candle) => {
                if self.is_resync_required() {
                    let expected = self
                        .ohlcv
                        .as_ref()
                        .and_then(|o| o.current_sequence().map(|s| s.next()))
                        .unwrap_or(Sequence(1));
                    let received = envelope.freshness.sequence;
                    return Ok(DeltaClassification::ResyncRequired { expected, received });
                }

                if let Some(ref mut ohlcv) = self.ohlcv {
                    let mut staged_ohlcv = ohlcv.clone();
                    let class =
                        staged_ohlcv.apply_candle(candle, Some(envelope.freshness.sequence))?;
                    if let DeltaClassification::ResyncRequired { .. } = class {
                        self.trigger_resync();
                    } else {
                        *ohlcv = staged_ohlcv;
                    }
                    Ok(class)
                } else {
                    Err(MarketTypeError::UnsupportedPayloadForTarget(
                        "candle payload on aggregator without ohlcv configured",
                    ))
                }
            }
            CanonicalFeedPayload::PoolState(_) => {
                Err(MarketTypeError::UnsupportedPayloadForTarget("pool state"))
            }
        }
    }
}
