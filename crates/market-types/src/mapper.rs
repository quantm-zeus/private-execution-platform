//! Canonical market feed mapper.
//!
//! Deterministically maps bounded raw feed envelopes into canonical task-20 market contracts.
//! Enforces strict fail-closed validation, source and finality metadata preservation, and
//! sticky sequence gap/overlap resync latches without partial state advancement.

use chain_types::ChainId;

use crate::error::MarketTypeError;
use crate::feed::{
    CanonicalFeedEnvelope, CanonicalFeedPayload, MarketFeedSource, RawBinState, RawCandle,
    RawClmmState, RawCpmmState, RawDepthDelta, RawDepthSnapshot, RawFeedEnvelope, RawFeedPayload,
    RawPoolKindState, RawPoolState, MAX_FEED_BATCH_SIZE,
};
use crate::freshness::{evaluate_freshness, FreshnessPolicy};
use crate::identity::FeedTarget;
use crate::ohlcv::Candle;
use crate::orderbook::{
    DepthDelta, DepthLevel, DepthSnapshot, NormalizedPrice, NormalizedQuantity, OrderBookDepth,
    MAX_DEPTH_LEVELS,
};
use crate::pool::{
    BinPoolState, ClmmPoolState, ClmmTick, CpmmPoolState, LiquidityBin, PoolKindState,
    PoolStateEnvelope,
};
use crate::primitives::{AtomicAmount, Bps, Sequence};
use crate::sequence::{DeltaClassification, SequenceRange, SequencedStreamTracker};

/// Deterministic canonical market feed mapper.
///
/// Converts injected raw market feed envelopes into canonical `market-types` contracts.
/// All rejected inputs (malformed, non-finite, over-bound, wrong-target, sequence-gap,
/// sequence-overlap) fail closed with structured errors leaving mapper state untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalMarketFeedMapper {
    target: FeedTarget,
    freshness_policy: FreshnessPolicy,
    max_depth_levels: usize,
    stream_tracker: SequencedStreamTracker,
    order_book: Option<OrderBookDepth>,
    last_pool_state: Option<PoolStateEnvelope>,
}

impl CanonicalMarketFeedMapper {
    /// Creates a new mapper for the given target with default freshness policy.
    pub fn new(target: FeedTarget) -> Result<Self, MarketTypeError> {
        target.validate()?;
        Ok(Self {
            target: target.clone(),
            freshness_policy: FreshnessPolicy::default(),
            max_depth_levels: 500,
            stream_tracker: SequencedStreamTracker::new(target),
            order_book: None,
            last_pool_state: None,
        })
    }

    /// Creates a new mapper with explicit target, freshness policy, and maximum depth levels.
    pub fn with_policy(
        target: FeedTarget,
        freshness_policy: FreshnessPolicy,
        max_depth_levels: usize,
    ) -> Result<Self, MarketTypeError> {
        target.validate()?;
        if max_depth_levels == 0 || max_depth_levels > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: max_depth_levels,
                max: MAX_DEPTH_LEVELS,
            });
        }
        Ok(Self {
            target: target.clone(),
            freshness_policy,
            max_depth_levels,
            stream_tracker: SequencedStreamTracker::new(target),
            order_book: None,
            last_pool_state: None,
        })
    }

    pub fn target(&self) -> &FeedTarget {
        &self.target
    }

    pub fn freshness_policy(&self) -> &FreshnessPolicy {
        &self.freshness_policy
    }

    pub fn max_depth_levels(&self) -> usize {
        self.max_depth_levels
    }

    pub fn current_sequence(&self) -> Option<Sequence> {
        self.stream_tracker.current_sequence()
    }

    pub fn is_resync_required(&self) -> bool {
        self.stream_tracker.is_resync_required()
    }

    pub fn last_timestamp_ms(&self) -> Option<i64> {
        self.stream_tracker.last_timestamp_ms()
    }

    pub fn order_book(&self) -> Option<&OrderBookDepth> {
        self.order_book.as_ref()
    }

    pub fn last_pool_state(&self) -> Option<&PoolStateEnvelope> {
        self.last_pool_state.as_ref()
    }

    pub fn trigger_resync(&mut self) {
        self.stream_tracker.trigger_resync();
        if let Some(book) = &mut self.order_book {
            book.trigger_resync();
        }
    }

    /// Explicitly resets the mapper and clears the resync latch using a validated depth snapshot.
    pub fn reset_with_snapshot(&mut self, snapshot: DepthSnapshot) -> Result<(), MarketTypeError> {
        snapshot.validate()?;
        if snapshot.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }

        self.stream_tracker
            .apply_snapshot_sequence(snapshot.sequence, snapshot.timestamp_ms);

        let book = OrderBookDepth::new(snapshot, self.max_depth_levels)?;
        self.order_book = Some(book);

        Ok(())
    }

    /// Process the next envelope yielded by an injected market feed source using a deterministic reference timestamp.
    pub fn process_from_source(
        &mut self,
        source: &mut dyn MarketFeedSource,
        evaluated_at_ms: i64,
    ) -> Result<Option<CanonicalFeedEnvelope>, MarketTypeError> {
        match source.next_envelope()? {
            Some(envelope) => self.map_envelope(envelope, evaluated_at_ms).map(Some),
            None => Ok(None),
        }
    }

    /// Process and map all remaining envelopes yielded by an injected market feed source up to `MAX_FEED_BATCH_SIZE`.
    pub fn process_all_from_source(
        &mut self,
        source: &mut dyn MarketFeedSource,
        evaluated_at_ms: i64,
    ) -> Result<Vec<CanonicalFeedEnvelope>, MarketTypeError> {
        let mut results = Vec::new();
        while let Some(envelope) = source.next_envelope()? {
            if results.len() >= MAX_FEED_BATCH_SIZE {
                return Err(MarketTypeError::FeedBatchExceeded {
                    count: results.len() + 1,
                    max: MAX_FEED_BATCH_SIZE,
                });
            }
            let event = self.map_envelope(envelope, evaluated_at_ms)?;
            results.push(event);
        }
        Ok(results)
    }

    /// Maps a raw feed envelope into a canonical task-20 contract envelope using a deterministic reference timestamp.
    ///
    /// Fails closed on malformed, non-finite, over-bound, wrong-target, invalid timestamp, or sequence-gap/overlap input.
    /// Mapper state NEVER advances on rejected input.
    pub fn map_envelope(
        &mut self,
        envelope: RawFeedEnvelope,
        evaluated_at_ms: i64,
    ) -> Result<CanonicalFeedEnvelope, MarketTypeError> {
        // Validate evaluation timestamp immediately before any state mutation
        if evaluated_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(evaluated_at_ms));
        }

        // 1. Target check
        if envelope.target != self.target {
            return Err(MarketTypeError::TargetMismatch);
        }
        envelope.target.validate()?;

        // 2. Context validation & chain family match
        envelope.context.validate()?;
        let target_chain = self.target.chain();
        if !envelope
            .context
            .source_family
            .matches_chain_id(target_chain)
        {
            return Err(MarketTypeError::SourceChainFamilyMismatch {
                source_family: envelope.context.source_family.as_str(),
                target_chain: chain_name(target_chain),
            });
        }

        // 3. Payload-specific normalization and sequence validation
        match envelope.payload {
            RawFeedPayload::OrderBookSnapshot(raw_snap) => {
                self.map_order_book_snapshot(envelope.context, raw_snap, evaluated_at_ms)
            }
            RawFeedPayload::OrderBookDelta(raw_delta) => {
                self.map_order_book_delta(envelope.context, raw_delta, evaluated_at_ms)
            }
            RawFeedPayload::PoolState(raw_pool) => {
                self.map_pool_state(envelope.context, raw_pool, evaluated_at_ms)
            }
            RawFeedPayload::Candle(raw_candle) => {
                self.map_candle(envelope.context, raw_candle, evaluated_at_ms)
            }
        }
    }

    fn map_order_book_snapshot(
        &mut self,
        context: crate::feed::FeedObservationContext,
        raw_snap: RawDepthSnapshot,
        evaluated_at_ms: i64,
    ) -> Result<CanonicalFeedEnvelope, MarketTypeError> {
        let seq = Sequence::new(raw_snap.sequence);
        seq.validate()?;

        if raw_snap.bids.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: raw_snap.bids.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }
        if raw_snap.asks.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: raw_snap.asks.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }

        let mut bids = Vec::with_capacity(raw_snap.bids.len());
        for level in &raw_snap.bids {
            let price = NormalizedPrice::new(level.price)?;
            let quantity = NormalizedQuantity::new(level.quantity)?;
            let dl = DepthLevel::new(price, quantity);
            dl.validate_snapshot()?;
            bids.push(dl);
        }

        let mut asks = Vec::with_capacity(raw_snap.asks.len());
        for level in &raw_snap.asks {
            let price = NormalizedPrice::new(level.price)?;
            let quantity = NormalizedQuantity::new(level.quantity)?;
            let dl = DepthLevel::new(price, quantity);
            dl.validate_snapshot()?;
            asks.push(dl);
        }

        let canonical_snapshot = DepthSnapshot {
            target: self.target.clone(),
            sequence: seq,
            timestamp_ms: context.observed_at_ms,
            bids,
            asks,
        };
        canonical_snapshot.validate()?;

        // Sequence progression check: stale/duplicate snapshots are rejected without mutating state
        if let Some(curr) = self.stream_tracker.current_sequence() {
            if seq < curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: seq.0,
                    current: curr.0,
                });
            }
            if seq == curr {
                return Err(MarketTypeError::DuplicateSequence(curr.0));
            }
        }

        // Validate book construction before modifying state
        let book = OrderBookDepth::new(canonical_snapshot.clone(), self.max_depth_levels)?;

        let freshness = evaluate_freshness(
            &self.freshness_policy,
            context.observed_at_ms,
            evaluated_at_ms,
            seq,
            false,
        )?;

        // If future skew beyond policy yields ResyncRequired, remain fail-closed without advancing baseline
        if freshness.is_resync_required() {
            self.trigger_resync();
        } else {
            // Fresh or stale snapshot baseline advance (clears resync latch)
            self.stream_tracker
                .apply_snapshot_sequence(seq, context.observed_at_ms);
            self.order_book = Some(book);
        }

        Ok(CanonicalFeedEnvelope {
            context,
            freshness,
            payload: CanonicalFeedPayload::OrderBookSnapshot(canonical_snapshot),
        })
    }

    fn map_order_book_delta(
        &mut self,
        context: crate::feed::FeedObservationContext,
        raw_delta: RawDepthDelta,
        evaluated_at_ms: i64,
    ) -> Result<CanonicalFeedEnvelope, MarketTypeError> {
        // Fail-closed if resync is latched
        if self.stream_tracker.is_resync_required() {
            return Err(MarketTypeError::ResyncRequired {
                reason: "stream resync latched: valid snapshot required",
            });
        }

        // Require established baseline before deltas
        let curr = match self.stream_tracker.current_sequence() {
            Some(s) => s,
            None => {
                self.stream_tracker.trigger_resync();
                return Err(MarketTypeError::MissingBaselineSnapshot);
            }
        };

        let start_seq = Sequence::new(raw_delta.start_sequence);
        start_seq.validate()?;
        let end_seq = Sequence::new(raw_delta.end_sequence);
        end_seq.validate()?;
        let range = SequenceRange::new(start_seq, end_seq)?;

        let expected = curr.next();

        // Sequence Gap detection
        if range.start > expected {
            self.stream_tracker.trigger_resync();
            if let Some(book) = &mut self.order_book {
                book.trigger_resync();
            }
            return Err(MarketTypeError::SequenceGap {
                expected: expected.0,
                received: range.start.0,
            });
        }

        // Stale or Overlapping delta detection
        if range.start <= curr {
            if range.end < curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: range.end.0,
                    current: curr.0,
                });
            }
            if range.end == curr {
                return Err(MarketTypeError::DuplicateSequence(curr.0));
            }
            // Unaligned overlap: start <= curr < end
            self.stream_tracker.trigger_resync();
            if let Some(book) = &mut self.order_book {
                book.trigger_resync();
            }
            return Err(MarketTypeError::SequenceOverlap {
                start: range.start.0,
                end: range.end.0,
                current: curr.0,
            });
        }

        // Contiguous delta: validate contents BEFORE applying to state
        if raw_delta.bids.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: raw_delta.bids.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }
        if raw_delta.asks.len() > MAX_DEPTH_LEVELS {
            return Err(MarketTypeError::DepthLevelsExceeded {
                count: raw_delta.asks.len(),
                max: MAX_DEPTH_LEVELS,
            });
        }

        let mut bids = Vec::with_capacity(raw_delta.bids.len());
        for level in &raw_delta.bids {
            let price = NormalizedPrice::new(level.price)?;
            let quantity = NormalizedQuantity::new(level.quantity)?;
            let dl = DepthLevel::new(price, quantity);
            dl.validate_delta()?;
            bids.push(dl);
        }

        let mut asks = Vec::with_capacity(raw_delta.asks.len());
        for level in &raw_delta.asks {
            let price = NormalizedPrice::new(level.price)?;
            let quantity = NormalizedQuantity::new(level.quantity)?;
            let dl = DepthLevel::new(price, quantity);
            dl.validate_delta()?;
            asks.push(dl);
        }

        let canonical_delta = DepthDelta {
            target: self.target.clone(),
            sequence_range: range,
            timestamp_ms: context.observed_at_ms,
            bids,
            asks,
        };
        canonical_delta.validate()?;

        // Stage delta on order book if present (rolls back completely on CrossedOrderBook)
        let mut staged_book = None;
        if let Some(book) = &self.order_book {
            let mut staged = book.clone();
            let outcome = staged.apply_delta(&canonical_delta)?;
            match outcome {
                DeltaClassification::Contiguous { .. } => {
                    staged_book = Some(staged);
                }
                DeltaClassification::ResyncRequired { expected, received } => {
                    self.stream_tracker.trigger_resync();
                    if let Some(b) = &mut self.order_book {
                        b.trigger_resync();
                    }
                    return Err(MarketTypeError::SequenceGap {
                        expected: expected.0,
                        received: received.0,
                    });
                }
                DeltaClassification::Duplicate { .. } | DeltaClassification::Stale { .. } => {}
            }
        }

        let freshness = evaluate_freshness(
            &self.freshness_policy,
            context.observed_at_ms,
            evaluated_at_ms,
            range.end,
            false,
        )?;

        // If future skew beyond policy yields ResyncRequired, remain fail-closed without applying delta
        if freshness.is_resync_required() {
            self.trigger_resync();
        } else {
            if let Some(staged) = staged_book {
                self.order_book = Some(staged);
            }
            self.stream_tracker
                .apply_delta_range(range, context.observed_at_ms);
        }

        Ok(CanonicalFeedEnvelope {
            context,
            freshness,
            payload: CanonicalFeedPayload::OrderBookDelta(canonical_delta),
        })
    }

    fn map_pool_state(
        &mut self,
        context: crate::feed::FeedObservationContext,
        raw_pool: RawPoolState,
        evaluated_at_ms: i64,
    ) -> Result<CanonicalFeedEnvelope, MarketTypeError> {
        let pool_id = match &self.target {
            FeedTarget::Pool(p) => p.clone(),
            FeedTarget::Instrument(_) => {
                return Err(MarketTypeError::UnsupportedPayloadForTarget(
                    "pool state payload requires a pool feed target",
                ))
            }
        };

        let seq = Sequence::new(raw_pool.sequence);
        seq.validate()?;

        if let Some(curr) = self.stream_tracker.current_sequence() {
            if seq < curr {
                return Err(MarketTypeError::StaleSequence {
                    sequence: seq.0,
                    current: curr.0,
                });
            }
            if seq == curr {
                return Err(MarketTypeError::DuplicateSequence(curr.0));
            }
        }

        let kind_state = match raw_pool.kind {
            RawPoolKindState::Cpmm(raw_cpmm) => PoolKindState::Cpmm(convert_cpmm_state(raw_cpmm)?),
            RawPoolKindState::Clmm(raw_clmm) => PoolKindState::Clmm(convert_clmm_state(raw_clmm)?),
            RawPoolKindState::Bin(raw_bin) => PoolKindState::Bin(convert_bin_state(raw_bin)?),
        };

        let envelope_pool = PoolStateEnvelope {
            pool_id,
            sequence: seq,
            observed_at_ms: context.observed_at_ms,
            state: kind_state,
        };
        envelope_pool.validate()?;

        let freshness = evaluate_freshness(
            &self.freshness_policy,
            context.observed_at_ms,
            evaluated_at_ms,
            seq,
            false,
        )?;

        if freshness.is_resync_required() {
            self.trigger_resync();
        } else {
            self.stream_tracker
                .apply_snapshot_sequence(seq, context.observed_at_ms);
            self.last_pool_state = Some(envelope_pool.clone());
        }

        Ok(CanonicalFeedEnvelope {
            context,
            freshness,
            payload: CanonicalFeedPayload::PoolState(envelope_pool),
        })
    }

    fn map_candle(
        &mut self,
        context: crate::feed::FeedObservationContext,
        raw_candle: RawCandle,
        evaluated_at_ms: i64,
    ) -> Result<CanonicalFeedEnvelope, MarketTypeError> {
        let instrument = match &self.target {
            FeedTarget::Instrument(i) => i.clone(),
            FeedTarget::Pool(_) => {
                return Err(MarketTypeError::UnsupportedPayloadForTarget(
                    "candle payload requires an instrument feed target",
                ))
            }
        };

        let quote_volume = match raw_candle.quote_volume {
            Some(v) => Some(NormalizedQuantity::new(v)?),
            None => None,
        };

        let candle = Candle {
            instrument,
            timeframe: raw_candle.timeframe,
            open_time_ms: raw_candle.open_time_ms,
            close_time_ms: raw_candle.close_time_ms,
            open: NormalizedPrice::new(raw_candle.open)?,
            high: NormalizedPrice::new(raw_candle.high)?,
            low: NormalizedPrice::new(raw_candle.low)?,
            close: NormalizedPrice::new(raw_candle.close)?,
            volume: NormalizedQuantity::new(raw_candle.volume)?,
            quote_volume,
            trades_count: raw_candle.trades_count,
        };
        candle.validate()?;

        let seq = match raw_candle.sequence {
            Some(s) => {
                let seq = Sequence::new(s);
                seq.validate()?;
                seq
            }
            None => self
                .stream_tracker
                .current_sequence()
                .unwrap_or(Sequence(1)),
        };

        let freshness = evaluate_freshness(
            &self.freshness_policy,
            context.observed_at_ms,
            evaluated_at_ms,
            seq,
            false,
        )?;

        if freshness.is_resync_required() {
            self.trigger_resync();
        }

        Ok(CanonicalFeedEnvelope {
            context,
            freshness,
            payload: CanonicalFeedPayload::Candle(candle),
        })
    }
}

fn convert_cpmm_state(raw: RawCpmmState) -> Result<CpmmPoolState, MarketTypeError> {
    let fee_bps = Bps::new(raw.fee_bps)?;
    let total_lp_supply = raw.total_lp_supply.map(AtomicAmount::new);
    let cpmm = CpmmPoolState {
        token_0: raw.token_0,
        token_1: raw.token_1,
        decimals_0: raw.decimals_0,
        decimals_1: raw.decimals_1,
        reserve_0: AtomicAmount::new(raw.reserve_0),
        reserve_1: AtomicAmount::new(raw.reserve_1),
        total_lp_supply,
        fee_bps,
    };
    cpmm.validate()?;
    Ok(cpmm)
}

fn convert_clmm_state(raw: RawClmmState) -> Result<ClmmPoolState, MarketTypeError> {
    let fee_bps = Bps::new(raw.fee_bps)?;
    let mut ticks = Vec::with_capacity(raw.ticks.len());
    for tick in raw.ticks {
        ticks.push(ClmmTick {
            index: tick.index,
            liquidity_gross: tick.liquidity_gross,
            liquidity_net: tick.liquidity_net,
        });
    }
    let clmm = ClmmPoolState {
        token_0: raw.token_0,
        token_1: raw.token_1,
        decimals_0: raw.decimals_0,
        decimals_1: raw.decimals_1,
        tick_spacing: raw.tick_spacing,
        current_tick: raw.current_tick,
        sqrt_price_x64: raw.sqrt_price_x64,
        liquidity: raw.liquidity,
        fee_bps,
        ticks,
    };
    clmm.validate()?;
    Ok(clmm)
}

fn convert_bin_state(raw: RawBinState) -> Result<BinPoolState, MarketTypeError> {
    let fee_bps = Bps::new(raw.fee_bps)?;
    let mut bins = Vec::with_capacity(raw.bins.len());
    for bin in raw.bins {
        bins.push(LiquidityBin {
            id: bin.id,
            reserve_0: AtomicAmount::new(bin.reserve_0),
            reserve_1: AtomicAmount::new(bin.reserve_1),
        });
    }
    let bin_pool = BinPoolState {
        token_0: raw.token_0,
        token_1: raw.token_1,
        decimals_0: raw.decimals_0,
        decimals_1: raw.decimals_1,
        active_bin_id: raw.active_bin_id,
        bin_step: raw.bin_step,
        fee_bps,
        bins,
    };
    bin_pool.validate()?;
    Ok(bin_pool)
}

fn chain_name(chain: &ChainId) -> &'static str {
    match chain {
        ChainId::Solana => "solana",
        ChainId::Base => "base",
        ChainId::BnbChain => "bnb_chain",
        ChainId::Ethereum => "ethereum",
        ChainId::RobinhoodAssociated => "robinhood_associated",
        ChainId::Other(_) => "other",
    }
}
