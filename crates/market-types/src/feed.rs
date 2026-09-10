//! Bounded market feed boundaries, source metadata, and raw envelope contracts.
//!
//! This module defines an injected-only, deterministic source boundary for market feed input.
//! It contains NO network/RPC/provider clients, endpoints, credentials, background loops,
//! retry policies, or trading/execution capabilities.

use std::collections::VecDeque;
use std::fmt;
use std::ops::Deref;

use chain_types::{AssetId, ChainId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::MarketTypeError;
use crate::freshness::SafeFreshnessMeta;
use crate::identity::FeedTarget;
use crate::ohlcv::{Candle, CandleTimeframe};
use crate::orderbook::{DepthDelta, DepthSnapshot};
use crate::pool::PoolStateEnvelope;

/// Maximum allowed length in bytes for a feed source label.
pub const MAX_SOURCE_LABEL_LEN: usize = 64;

/// Maximum allowed number of envelopes in an injected feed source or batch ingestion helper.
pub const MAX_FEED_BATCH_SIZE: usize = 1_000;

/// Strongly typed, bounded identifier for a feed source (e.g. "yellowstone-primary", "reth-ws-local").
///
/// Disallows blank strings, excessively long strings, URL protocol schemes, and credential keywords.
/// Safe for inclusion in logs and error messages without secret leakage.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeedSourceLabel(String);

impl FeedSourceLabel {
    pub fn new(label: impl AsRef<str>) -> Result<Self, MarketTypeError> {
        let s = label.as_ref().trim();
        if s.is_empty() {
            return Err(MarketTypeError::EmptySourceLabel);
        }
        if s.len() > MAX_SOURCE_LABEL_LEN {
            return Err(MarketTypeError::SourceLabelTooLong {
                len: s.len(),
                max: MAX_SOURCE_LABEL_LEN,
            });
        }
        for b in s.bytes() {
            if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' && b != b'.' && b != b':' {
                return Err(MarketTypeError::InvalidSourceLabel(
                    "source label contains invalid characters: only alphanumeric, '-', '_', '.', and ':' are permitted",
                ));
            }
        }
        let lower = s.to_ascii_lowercase();
        if lower.contains("http:")
            || lower.contains("https:")
            || lower.contains("ws:")
            || lower.contains("wss:")
            || lower.contains("token")
            || lower.contains("secret")
            || lower.contains("key")
            || lower.contains("pass")
            || lower.contains("cred")
        {
            return Err(MarketTypeError::InvalidSourceLabel(
                "source label must not contain protocol schemes or credential keywords",
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for FeedSourceLabel {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for FeedSourceLabel {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FeedSourceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FeedSourceLabel({})", self.0)
    }
}

impl fmt::Display for FeedSourceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for FeedSourceLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for FeedSourceLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// Source chain family identifying the underlying blockchain architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainFamily {
    Solana,
    Evm,
    Other,
}

impl ChainFamily {
    pub fn from_chain_id(chain: &ChainId) -> Self {
        match chain {
            ChainId::Solana => Self::Solana,
            ChainId::Base
            | ChainId::BnbChain
            | ChainId::Ethereum
            | ChainId::RobinhoodAssociated => Self::Evm,
            ChainId::Other(_) => Self::Other,
        }
    }

    pub fn matches_chain_id(&self, chain: &ChainId) -> bool {
        matches!(
            (self, chain),
            (Self::Solana, ChainId::Solana)
                | (
                    Self::Evm,
                    ChainId::Base
                        | ChainId::BnbChain
                        | ChainId::Ethereum
                        | ChainId::RobinhoodAssociated,
                )
                | (Self::Other, ChainId::Other(_))
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Solana => "solana",
            Self::Evm => "evm",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for ChainFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Observation finality or commitment level for feed data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFinality {
    /// Unconfirmed / tentative observation (e.g. Solana processed, EVM mempool/pending).
    Processed,
    /// Confirmed by cluster or quorum (e.g. Solana confirmed, EVM latest).
    Confirmed,
    /// Irreversible finality (e.g. Solana finalized, EVM finalized post-merge).
    Finalized,
    /// Safe head (e.g. EVM safe head).
    Safe,
}

impl FeedFinality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Processed => "processed",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
            Self::Safe => "safe",
        }
    }

    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized)
    }

    pub fn is_confirmed_or_better(&self) -> bool {
        matches!(self, Self::Confirmed | Self::Safe | Self::Finalized)
    }
}

impl fmt::Display for FeedFinality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Serializable observation context preserving source origin, finality, and observation timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FeedObservationContext {
    pub source_family: ChainFamily,
    pub source_label: FeedSourceLabel,
    pub finality: FeedFinality,
    pub slot_or_block: Option<u64>,
    pub observed_at_ms: i64,
}

impl FeedObservationContext {
    pub fn new(
        source_family: ChainFamily,
        source_label: FeedSourceLabel,
        finality: FeedFinality,
        slot_or_block: Option<u64>,
        observed_at_ms: i64,
    ) -> Result<Self, MarketTypeError> {
        let ctx = Self {
            source_family,
            source_label,
            finality,
            slot_or_block,
            observed_at_ms,
        };
        ctx.validate()?;
        Ok(ctx)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        Ok(())
    }
}

/// Raw depth level with unbounded floating point values prior to canonical normalization.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawDepthLevel {
    pub price: f64,
    pub quantity: f64,
}

impl RawDepthLevel {
    pub const fn new(price: f64, quantity: f64) -> Self {
        Self { price, quantity }
    }
}

impl From<(f64, f64)> for RawDepthLevel {
    fn from((price, quantity): (f64, f64)) -> Self {
        Self { price, quantity }
    }
}

/// Raw order book depth snapshot prior to normalization and validation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawDepthSnapshot {
    pub sequence: u64,
    pub bids: Vec<RawDepthLevel>,
    pub asks: Vec<RawDepthLevel>,
}

/// Raw order book depth delta for an incremental update sequence range.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawDepthDelta {
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub bids: Vec<RawDepthLevel>,
    pub asks: Vec<RawDepthLevel>,
}

/// Raw tick boundary for concentrated liquidity pools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawClmmTick {
    pub index: i32,
    pub liquidity_gross: u128,
    pub liquidity_net: i128,
}

/// Raw constant product AMM pool state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawCpmmState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub reserve_0: u128,
    pub reserve_1: u128,
    pub total_lp_supply: Option<u128>,
    pub fee_bps: u16,
}

/// Raw concentrated liquidity pool state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawClmmState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub tick_spacing: u32,
    pub current_tick: i32,
    pub sqrt_price_x64: u128,
    pub liquidity: u128,
    pub fee_bps: u16,
    pub ticks: Vec<RawClmmTick>,
}

/// Raw bin level for discretized liquidity pools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawLiquidityBin {
    pub id: i32,
    pub reserve_0: u128,
    pub reserve_1: u128,
}

/// Raw bin/DLMM pool state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawBinState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub active_bin_id: i32,
    pub bin_step: u16,
    pub fee_bps: u16,
    pub bins: Vec<RawLiquidityBin>,
}

/// Raw pool state variants.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "pool_type")]
pub enum RawPoolKindState {
    Cpmm(RawCpmmState),
    Clmm(RawClmmState),
    Bin(RawBinState),
}

/// Raw pool state update with sequence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawPoolState {
    pub sequence: u64,
    pub kind: RawPoolKindState,
}

/// Raw candle representation prior to normalization.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawCandle {
    pub timeframe: CandleTimeframe,
    pub open_time_ms: i64,
    pub close_time_ms: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
    pub quote_volume: Option<f64>,
    pub trades_count: Option<u64>,
    pub sequence: Option<u64>,
}

/// Raw feed payload variants.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "payload_type")]
pub enum RawFeedPayload {
    OrderBookSnapshot(RawDepthSnapshot),
    OrderBookDelta(RawDepthDelta),
    PoolState(RawPoolState),
    Candle(RawCandle),
}

/// Injected raw feed envelope bundling observation metadata, target, and payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawFeedEnvelope {
    pub context: FeedObservationContext,
    pub target: FeedTarget,
    pub payload: RawFeedPayload,
}

impl RawFeedEnvelope {
    pub fn new(
        context: FeedObservationContext,
        target: FeedTarget,
        payload: RawFeedPayload,
    ) -> Result<Self, MarketTypeError> {
        context.validate()?;
        target.validate()?;
        Ok(Self {
            context,
            target,
            payload,
        })
    }
}

/// Canonical mapped feed payload wrapping existing task-20 contracts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "payload_type")]
pub enum CanonicalFeedPayload {
    OrderBookSnapshot(DepthSnapshot),
    OrderBookDelta(DepthDelta),
    PoolState(PoolStateEnvelope),
    Candle(Candle),
}

/// Canonical mapped envelope preserving source origin context, evaluated freshness, and task-20 contract payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalFeedEnvelope {
    pub context: FeedObservationContext,
    pub freshness: SafeFreshnessMeta,
    pub payload: CanonicalFeedPayload,
}

/// Trait defining the injected-only market feed source boundary.
///
/// This is a pure local contract layer with NO network/RPC/provider client, endpoint,
/// credential, background loop, retry, or mutation/trading capability.
pub trait MarketFeedSource {
    /// Pull the next deterministic raw envelope from this source.
    ///
    /// Returns:
    /// - `Ok(Some(envelope))` when an envelope is yielded.
    /// - `Ok(None)` when the input source has been exhausted.
    /// - `Err(e)` when the source encounters an injected error.
    fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError>;
}

/// FIFO in-memory injected feed source for deterministic testing and playback.
#[derive(Clone, Debug, Default)]
pub struct InjectedFeedSource {
    envelopes: VecDeque<RawFeedEnvelope>,
}

impl InjectedFeedSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an injected feed source from a bounded batch of envelopes.
    ///
    /// Fails closed with `MarketTypeError::FeedBatchExceeded` if the input batch exceeds `MAX_FEED_BATCH_SIZE`.
    pub fn from_envelopes(
        envelopes: impl IntoIterator<Item = RawFeedEnvelope>,
    ) -> Result<Self, MarketTypeError> {
        let iter = envelopes.into_iter();
        let (lower, _) = iter.size_hint();
        if lower > MAX_FEED_BATCH_SIZE {
            return Err(MarketTypeError::FeedBatchExceeded {
                count: lower,
                max: MAX_FEED_BATCH_SIZE,
            });
        }
        let mut queue = VecDeque::new();
        for envelope in iter {
            if queue.len() >= MAX_FEED_BATCH_SIZE {
                return Err(MarketTypeError::FeedBatchExceeded {
                    count: queue.len() + 1,
                    max: MAX_FEED_BATCH_SIZE,
                });
            }
            queue.push_back(envelope);
        }
        Ok(Self { envelopes: queue })
    }

    /// Pushes an envelope to the back of the queue, rejecting if `MAX_FEED_BATCH_SIZE` is reached.
    pub fn push_back(&mut self, envelope: RawFeedEnvelope) -> Result<(), MarketTypeError> {
        if self.envelopes.len() >= MAX_FEED_BATCH_SIZE {
            return Err(MarketTypeError::FeedBatchExceeded {
                count: self.envelopes.len() + 1,
                max: MAX_FEED_BATCH_SIZE,
            });
        }
        self.envelopes.push_back(envelope);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }
}

impl MarketFeedSource for InjectedFeedSource {
    fn next_envelope(&mut self) -> Result<Option<RawFeedEnvelope>, MarketTypeError> {
        Ok(self.envelopes.pop_front())
    }
}
