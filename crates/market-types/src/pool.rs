//! Adapter-neutral pool state representations for CPMM, CLMM, and bin-based pools.

use chain_types::AssetId;
use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::identity::PoolId;
use crate::primitives::{AtomicAmount, Bps, Sequence};
use crate::sequence::{DeltaClassification, SequenceRange, SnapshotClassification};

pub const MAX_DECIMALS: u8 = 30;
pub const MIN_TICK: i32 = -887_272;
pub const MAX_TICK: i32 = 887_272;
pub const MAX_CLMM_TICKS: usize = 10_000;
pub const MIN_BIN_ID: i32 = -8_388_608;
pub const MAX_BIN_ID: i32 = 8_388_608;
pub const MAX_BIN_COUNT: usize = 10_000;
pub const MAX_BIN_STEP_BPS: u16 = 1_000; // 10%

/// Canonical envelope holding adapter-neutral local pool state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStateEnvelope {
    pub pool_id: PoolId,
    pub sequence: Sequence,
    pub observed_at_ms: i64,
    pub state: PoolKindState,
}

impl PoolStateEnvelope {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.pool_id.validate()?;
        self.sequence.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        self.state.validate()?;
        if self.state.token_0().chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        Ok(())
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    pub fn state(&self) -> &PoolKindState {
        &self.state
    }

    pub fn token_0(&self) -> &AssetId {
        self.state.token_0()
    }

    pub fn token_1(&self) -> &AssetId {
        self.state.token_1()
    }
}

/// Explicit pool structure types supported by the canonical domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum PoolKindState {
    Cpmm(CpmmPoolState),
    Clmm(ClmmPoolState),
    Bin(BinPoolState),
}

impl PoolKindState {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        match self {
            Self::Cpmm(p) => p.validate(),
            Self::Clmm(p) => p.validate(),
            Self::Bin(p) => p.validate(),
        }
    }

    pub fn token_0(&self) -> &AssetId {
        match self {
            Self::Cpmm(p) => &p.token_0,
            Self::Clmm(p) => &p.token_0,
            Self::Bin(p) => &p.token_0,
        }
    }

    pub fn token_1(&self) -> &AssetId {
        match self {
            Self::Cpmm(p) => &p.token_1,
            Self::Clmm(p) => &p.token_1,
            Self::Bin(p) => &p.token_1,
        }
    }

    pub fn decimals_0(&self) -> u8 {
        match self {
            Self::Cpmm(p) => p.decimals_0,
            Self::Clmm(p) => p.decimals_0,
            Self::Bin(p) => p.decimals_0,
        }
    }

    pub fn decimals_1(&self) -> u8 {
        match self {
            Self::Cpmm(p) => p.decimals_1,
            Self::Clmm(p) => p.decimals_1,
            Self::Bin(p) => p.decimals_1,
        }
    }

    pub fn fee_bps(&self) -> Bps {
        match self {
            Self::Cpmm(p) => p.fee_bps,
            Self::Clmm(p) => p.fee_bps,
            Self::Bin(p) => p.fee_bps,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Cpmm(_) => "cpmm",
            Self::Clmm(_) => "clmm",
            Self::Bin(_) => "bin",
        }
    }
}

/// Constant Product Market Maker (CPMM, e.g. Uniswap v2, Raydium Standard).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmPoolState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub reserve_0: AtomicAmount,
    pub reserve_1: AtomicAmount,
    pub total_lp_supply: Option<AtomicAmount>,
    pub fee_bps: Bps,
}

impl CpmmPoolState {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.token_0
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;
        self.token_1
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;

        if self.token_0 == self.token_1 {
            return Err(MarketTypeError::SamePoolTokens);
        }
        if self.token_0.chain != self.token_1.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if self.decimals_0 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_0,
                max: MAX_DECIMALS,
            });
        }
        if self.decimals_1 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_1,
                max: MAX_DECIMALS,
            });
        }

        Ok(())
    }
}

/// Single tick boundary in a concentrated liquidity pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmTick {
    pub index: i32,
    pub liquidity_gross: u128,
    pub liquidity_net: i128,
}

impl ClmmTick {
    pub const fn new(index: i32, liquidity_gross: u128, liquidity_net: i128) -> Self {
        Self {
            index,
            liquidity_gross,
            liquidity_net,
        }
    }
}

/// Concentrated Liquidity Market Maker (CLMM, e.g. Uniswap v3, Orca Whirlpools, Raydium CLMM).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmPoolState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub tick_spacing: u32,
    pub current_tick: i32,
    pub sqrt_price_x64: u128,
    pub liquidity: u128,
    pub fee_bps: Bps,
    pub ticks: Vec<ClmmTick>,
}

impl ClmmPoolState {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.token_0
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;
        self.token_1
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;

        if self.token_0 == self.token_1 {
            return Err(MarketTypeError::SamePoolTokens);
        }
        if self.token_0.chain != self.token_1.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if self.decimals_0 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_0,
                max: MAX_DECIMALS,
            });
        }
        if self.decimals_1 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_1,
                max: MAX_DECIMALS,
            });
        }
        if self.tick_spacing == 0 {
            return Err(MarketTypeError::InvalidTickSpacing(0));
        }
        if !(MIN_TICK..=MAX_TICK).contains(&self.current_tick) {
            return Err(MarketTypeError::TickOutOfRange {
                tick: self.current_tick,
                min: MIN_TICK,
                max: MAX_TICK,
            });
        }
        if self.ticks.len() > MAX_CLMM_TICKS {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: self.ticks.len(),
                max: MAX_CLMM_TICKS,
            });
        }

        for i in 0..self.ticks.len() {
            let tick = &self.ticks[i];
            if !(MIN_TICK..=MAX_TICK).contains(&tick.index) {
                return Err(MarketTypeError::TickOutOfRange {
                    tick: tick.index,
                    min: MIN_TICK,
                    max: MAX_TICK,
                });
            }
            if tick.index % (self.tick_spacing as i32) != 0 {
                return Err(MarketTypeError::TickSpacingMismatch {
                    tick: tick.index,
                    spacing: self.tick_spacing,
                });
            }
            if tick.liquidity_net.unsigned_abs() > tick.liquidity_gross {
                return Err(MarketTypeError::InvalidTickLiquidity(tick.index));
            }
            if i > 0 {
                let prev_tick = &self.ticks[i - 1];
                if tick.index == prev_tick.index {
                    return Err(MarketTypeError::DuplicateClmmTick(tick.index));
                }
                if tick.index < prev_tick.index {
                    return Err(MarketTypeError::UnsortedClmmTicks);
                }
            }
        }

        Ok(())
    }
}

/// Discrete liquidity bin (e.g. Trader Joe Liquidity Book, Meteora DLMM).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityBin {
    pub id: i32,
    pub reserve_0: AtomicAmount,
    pub reserve_1: AtomicAmount,
}

impl LiquidityBin {
    pub const fn new(id: i32, reserve_0: AtomicAmount, reserve_1: AtomicAmount) -> Self {
        Self {
            id,
            reserve_0,
            reserve_1,
        }
    }
}

/// Bin-based pool state (DLMM / Liquidity Book).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinPoolState {
    pub token_0: AssetId,
    pub token_1: AssetId,
    pub decimals_0: u8,
    pub decimals_1: u8,
    pub active_bin_id: i32,
    pub bin_step: u16,
    pub fee_bps: Bps,
    pub bins: Vec<LiquidityBin>,
}

impl BinPoolState {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.token_0
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;
        self.token_1
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;

        if self.token_0 == self.token_1 {
            return Err(MarketTypeError::SamePoolTokens);
        }
        if self.token_0.chain != self.token_1.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if self.decimals_0 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_0,
                max: MAX_DECIMALS,
            });
        }
        if self.decimals_1 > MAX_DECIMALS {
            return Err(MarketTypeError::DecimalsExceeded {
                decimals: self.decimals_1,
                max: MAX_DECIMALS,
            });
        }
        if self.bin_step == 0 || self.bin_step > MAX_BIN_STEP_BPS {
            return Err(MarketTypeError::InvalidBinStep(self.bin_step));
        }
        if !(MIN_BIN_ID..=MAX_BIN_ID).contains(&self.active_bin_id) {
            return Err(MarketTypeError::BinOutOfRange {
                bin_id: self.active_bin_id,
                min: MIN_BIN_ID,
                max: MAX_BIN_ID,
            });
        }
        if self.bins.len() > MAX_BIN_COUNT {
            return Err(MarketTypeError::BinsExceeded {
                count: self.bins.len(),
                max: MAX_BIN_COUNT,
            });
        }

        for i in 0..self.bins.len() {
            let bin = &self.bins[i];
            if !(MIN_BIN_ID..=MAX_BIN_ID).contains(&bin.id) {
                return Err(MarketTypeError::BinOutOfRange {
                    bin_id: bin.id,
                    min: MIN_BIN_ID,
                    max: MAX_BIN_ID,
                });
            }
            if i > 0 {
                let prev_bin = &self.bins[i - 1];
                if bin.id == prev_bin.id {
                    return Err(MarketTypeError::DuplicateBin(bin.id));
                }
                if bin.id < prev_bin.id {
                    return Err(MarketTypeError::UnsortedBins);
                }
            }
            if bin.reserve_0.is_zero() && bin.reserve_1.is_zero() {
                return Err(MarketTypeError::EmptyBin(bin.id));
            }

            // In DLMM / Liquidity Book architecture:
            // Bins strictly below active_bin_id contain only quote asset (reserve_1).
            if bin.id < self.active_bin_id && !bin.reserve_0.is_zero() {
                return Err(MarketTypeError::BinReserveSideViolation {
                    bin_id: bin.id,
                    active_bin_id: self.active_bin_id,
                });
            }
            // Bins strictly above active_bin_id contain only base asset (reserve_0).
            if bin.id > self.active_bin_id && !bin.reserve_1.is_zero() {
                return Err(MarketTypeError::BinReserveSideViolation {
                    bin_id: bin.id,
                    active_bin_id: self.active_bin_id,
                });
            }
        }

        Ok(())
    }
}

/// Maximum allowed tick updates in a single CLMM delta update.
pub const MAX_CLMM_DELTA_TICKS: usize = 1_000;

/// Maximum allowed bin updates in a single Bin/DLMM delta update.
pub const MAX_BIN_DELTA_BINS: usize = 1_000;

/// Incremental delta update for CPMM pool state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CpmmPoolDelta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_0: Option<AtomicAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_1: Option<AtomicAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_lp_supply: Option<AtomicAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_bps: Option<Bps>,
}

impl CpmmPoolDelta {
    pub const fn new(
        reserve_0: Option<AtomicAmount>,
        reserve_1: Option<AtomicAmount>,
        total_lp_supply: Option<AtomicAmount>,
        fee_bps: Option<Bps>,
    ) -> Self {
        Self {
            reserve_0,
            reserve_1,
            total_lp_supply,
            fee_bps,
        }
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if let Some(fee) = self.fee_bps {
            fee.validate()?;
        }
        Ok(())
    }
}

/// Incremental delta update for CLMM pool state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClmmPoolDelta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_tick: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqrt_price_x64: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liquidity: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_bps: Option<Bps>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ticks: Vec<ClmmTick>,
}

impl ClmmPoolDelta {
    pub const fn new(
        current_tick: Option<i32>,
        sqrt_price_x64: Option<u128>,
        liquidity: Option<u128>,
        fee_bps: Option<Bps>,
        ticks: Vec<ClmmTick>,
    ) -> Self {
        Self {
            current_tick,
            sqrt_price_x64,
            liquidity,
            fee_bps,
            ticks,
        }
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if let Some(ct) = self.current_tick {
            if !(MIN_TICK..=MAX_TICK).contains(&ct) {
                return Err(MarketTypeError::TickOutOfRange {
                    tick: ct,
                    min: MIN_TICK,
                    max: MAX_TICK,
                });
            }
        }
        if let Some(sq) = self.sqrt_price_x64 {
            if sq == 0 {
                return Err(MarketTypeError::ZeroPrice);
            }
        }
        if let Some(fee) = self.fee_bps {
            fee.validate()?;
        }
        if self.ticks.len() > MAX_CLMM_DELTA_TICKS {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: self.ticks.len(),
                max: MAX_CLMM_DELTA_TICKS,
            });
        }
        for (i, tick) in self.ticks.iter().enumerate() {
            if !(MIN_TICK..=MAX_TICK).contains(&tick.index) {
                return Err(MarketTypeError::TickOutOfRange {
                    tick: tick.index,
                    min: MIN_TICK,
                    max: MAX_TICK,
                });
            }
            if tick.liquidity_net.unsigned_abs() > tick.liquidity_gross {
                return Err(MarketTypeError::InvalidTickLiquidity(tick.index));
            }
            if tick.liquidity_gross == 0 && tick.liquidity_net != 0 {
                return Err(MarketTypeError::InvalidTickLiquidity(tick.index));
            }
            for other in &self.ticks[i + 1..] {
                if tick.index == other.index {
                    return Err(MarketTypeError::DuplicateClmmTick(tick.index));
                }
            }
        }
        Ok(())
    }
}

/// Incremental delta update for Bin/DLMM pool state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BinPoolDelta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_bin_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_step: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_bps: Option<Bps>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bins: Vec<LiquidityBin>,
}

impl BinPoolDelta {
    pub const fn new(
        active_bin_id: Option<i32>,
        bin_step: Option<u16>,
        fee_bps: Option<Bps>,
        bins: Vec<LiquidityBin>,
    ) -> Self {
        Self {
            active_bin_id,
            bin_step,
            fee_bps,
            bins,
        }
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        if let Some(id) = self.active_bin_id {
            if !(MIN_BIN_ID..=MAX_BIN_ID).contains(&id) {
                return Err(MarketTypeError::BinOutOfRange {
                    bin_id: id,
                    min: MIN_BIN_ID,
                    max: MAX_BIN_ID,
                });
            }
        }
        if let Some(step) = self.bin_step {
            if step == 0 || step > MAX_BIN_STEP_BPS {
                return Err(MarketTypeError::InvalidBinStep(step));
            }
        }
        if let Some(fee) = self.fee_bps {
            fee.validate()?;
        }
        if self.bins.len() > MAX_BIN_DELTA_BINS {
            return Err(MarketTypeError::BinsExceeded {
                count: self.bins.len(),
                max: MAX_BIN_DELTA_BINS,
            });
        }
        for (i, bin) in self.bins.iter().enumerate() {
            if !(MIN_BIN_ID..=MAX_BIN_ID).contains(&bin.id) {
                return Err(MarketTypeError::BinOutOfRange {
                    bin_id: bin.id,
                    min: MIN_BIN_ID,
                    max: MAX_BIN_ID,
                });
            }
            for other in &self.bins[i + 1..] {
                if bin.id == other.id {
                    return Err(MarketTypeError::DuplicateBin(bin.id));
                }
            }
        }
        Ok(())
    }
}

/// Explicit pool delta update variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "delta", rename_all = "snake_case")]
pub enum PoolKindDelta {
    Cpmm(CpmmPoolDelta),
    Clmm(ClmmPoolDelta),
    Bin(BinPoolDelta),
}

impl PoolKindDelta {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        match self {
            Self::Cpmm(d) => d.validate(),
            Self::Clmm(d) => d.validate(),
            Self::Bin(d) => d.validate(),
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Cpmm(_) => "cpmm",
            Self::Clmm(_) => "clmm",
            Self::Bin(_) => "bin",
        }
    }
}

/// Bounded canonical envelope for pool-state delta updates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolDeltaEnvelope {
    pub pool_id: PoolId,
    pub sequence_range: SequenceRange,
    pub observed_at_ms: i64,
    pub delta: PoolKindDelta,
}

pub type PoolDelta = PoolDeltaEnvelope;

impl PoolDeltaEnvelope {
    pub fn new(
        pool_id: PoolId,
        sequence_range: SequenceRange,
        observed_at_ms: i64,
        delta: PoolKindDelta,
    ) -> Result<Self, MarketTypeError> {
        let env = Self {
            pool_id,
            sequence_range,
            observed_at_ms,
            delta,
        };
        env.validate()?;
        Ok(env)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.pool_id.validate()?;
        self.sequence_range.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        self.delta.validate()?;
        Ok(())
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn sequence_range(&self) -> SequenceRange {
        self.sequence_range
    }

    pub fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    pub fn delta(&self) -> &PoolKindDelta {
        &self.delta
    }
}

/// Typed envelope for CPMM pool delta update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmPoolDeltaEnvelope {
    pub pool_id: PoolId,
    pub sequence_range: SequenceRange,
    pub observed_at_ms: i64,
    pub delta: CpmmPoolDelta,
}

impl CpmmPoolDeltaEnvelope {
    pub fn new(
        pool_id: PoolId,
        sequence_range: SequenceRange,
        observed_at_ms: i64,
        delta: CpmmPoolDelta,
    ) -> Result<Self, MarketTypeError> {
        let env = Self {
            pool_id,
            sequence_range,
            observed_at_ms,
            delta,
        };
        env.validate()?;
        Ok(env)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.pool_id.validate()?;
        self.sequence_range.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        self.delta.validate()?;
        Ok(())
    }

    pub fn to_envelope(&self) -> PoolDeltaEnvelope {
        PoolDeltaEnvelope {
            pool_id: self.pool_id.clone(),
            sequence_range: self.sequence_range,
            observed_at_ms: self.observed_at_ms,
            delta: PoolKindDelta::Cpmm(self.delta.clone()),
        }
    }
}

/// Typed envelope for CLMM pool delta update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmPoolDeltaEnvelope {
    pub pool_id: PoolId,
    pub sequence_range: SequenceRange,
    pub observed_at_ms: i64,
    pub delta: ClmmPoolDelta,
}

impl ClmmPoolDeltaEnvelope {
    pub fn new(
        pool_id: PoolId,
        sequence_range: SequenceRange,
        observed_at_ms: i64,
        delta: ClmmPoolDelta,
    ) -> Result<Self, MarketTypeError> {
        let env = Self {
            pool_id,
            sequence_range,
            observed_at_ms,
            delta,
        };
        env.validate()?;
        Ok(env)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.pool_id.validate()?;
        self.sequence_range.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        self.delta.validate()?;
        Ok(())
    }

    pub fn to_envelope(&self) -> PoolDeltaEnvelope {
        PoolDeltaEnvelope {
            pool_id: self.pool_id.clone(),
            sequence_range: self.sequence_range,
            observed_at_ms: self.observed_at_ms,
            delta: PoolKindDelta::Clmm(self.delta.clone()),
        }
    }
}

/// Typed envelope for Bin/DLMM pool delta update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinPoolDeltaEnvelope {
    pub pool_id: PoolId,
    pub sequence_range: SequenceRange,
    pub observed_at_ms: i64,
    pub delta: BinPoolDelta,
}

impl BinPoolDeltaEnvelope {
    pub fn new(
        pool_id: PoolId,
        sequence_range: SequenceRange,
        observed_at_ms: i64,
        delta: BinPoolDelta,
    ) -> Result<Self, MarketTypeError> {
        let env = Self {
            pool_id,
            sequence_range,
            observed_at_ms,
            delta,
        };
        env.validate()?;
        Ok(env)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.pool_id.validate()?;
        self.sequence_range.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.observed_at_ms));
        }
        self.delta.validate()?;
        Ok(())
    }

    pub fn to_envelope(&self) -> PoolDeltaEnvelope {
        PoolDeltaEnvelope {
            pool_id: self.pool_id.clone(),
            sequence_range: self.sequence_range,
            observed_at_ms: self.observed_at_ms,
            delta: PoolKindDelta::Bin(self.delta.clone()),
        }
    }
}

/// Maintained local CPMM pool state reducer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpmmPoolReducer {
    pool_id: PoolId,
    sequence: Sequence,
    timestamp_ms: i64,
    state: CpmmPoolState,
    #[serde(default)]
    resync_required: bool,
}

impl CpmmPoolReducer {
    pub fn new(
        pool_id: PoolId,
        sequence: Sequence,
        timestamp_ms: i64,
        state: CpmmPoolState,
    ) -> Result<Self, MarketTypeError> {
        pool_id.validate()?;
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.reserve_0.is_zero() || state.reserve_1.is_zero() {
            return Err(MarketTypeError::ZeroAmount);
        }
        Ok(Self {
            pool_id,
            sequence,
            timestamp_ms,
            state,
            resync_required: false,
        })
    }

    pub fn from_envelope(envelope: PoolStateEnvelope) -> Result<Self, MarketTypeError> {
        envelope.validate()?;
        match envelope.state {
            PoolKindState::Cpmm(cpmm) => Self::new(
                envelope.pool_id,
                envelope.sequence,
                envelope.observed_at_ms,
                cpmm,
            ),
            other => Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: other.kind_str(),
            }),
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }

    pub fn state(&self) -> &CpmmPoolState {
        &self.state
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    pub fn reset_with_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: CpmmPoolState,
    ) -> Result<(), MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.reserve_0.is_zero() || state.reserve_1.is_zero() {
            return Err(MarketTypeError::ZeroAmount);
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(())
    }

    pub fn reset_with_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<(), MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let cpmm = match envelope.state {
            PoolKindState::Cpmm(c) => c,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "cpmm",
                    received: other.kind_str(),
                })
            }
        };
        self.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, cpmm)
    }

    pub fn apply_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: CpmmPoolState,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.reserve_0.is_zero() || state.reserve_1.is_zero() {
            return Err(MarketTypeError::ZeroAmount);
        }

        if sequence < self.sequence {
            return Ok(SnapshotClassification::Stale {
                sequence,
                current: self.sequence,
            });
        }
        if sequence == self.sequence {
            return Ok(SnapshotClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(SnapshotClassification::Accepted {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_snapshot_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let cpmm = match envelope.state {
            PoolKindState::Cpmm(c) => c,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "cpmm",
                    received: other.kind_str(),
                })
            }
        };
        self.apply_snapshot(envelope.sequence, envelope.observed_at_ms, cpmm)
    }

    pub fn apply_delta(
        &mut self,
        sequence_range: SequenceRange,
        timestamp_ms: i64,
        delta: &CpmmPoolDelta,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.resync_required {
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        sequence_range.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        delta.validate()?;

        if sequence_range.end < self.sequence {
            return Ok(DeltaClassification::Stale {
                sequence: sequence_range.end,
                current: self.sequence,
            });
        }

        if sequence_range.end == self.sequence {
            return Ok(DeltaClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        if sequence_range.start != self.sequence.next() {
            self.resync_required = true;
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        // Stage mutation atomically
        let mut staged = self.state.clone();
        if let Some(r0) = delta.reserve_0 {
            if r0.is_zero() {
                return Err(MarketTypeError::ZeroAmount);
            }
            staged.reserve_0 = r0;
        }
        if let Some(r1) = delta.reserve_1 {
            if r1.is_zero() {
                return Err(MarketTypeError::ZeroAmount);
            }
            staged.reserve_1 = r1;
        }
        if let Some(total_lp) = delta.total_lp_supply {
            staged.total_lp_supply = Some(total_lp);
        }
        if let Some(fee) = delta.fee_bps {
            staged.fee_bps = fee;
        }

        if staged.reserve_0.is_zero() || staged.reserve_1.is_zero() {
            return Err(MarketTypeError::ZeroAmount);
        }
        staged.validate()?;

        self.state = staged;
        self.sequence = sequence_range.end;
        self.timestamp_ms = timestamp_ms;

        Ok(DeltaClassification::Contiguous {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_delta_envelope(
        &mut self,
        envelope: &CpmmPoolDeltaEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        self.apply_delta(
            envelope.sequence_range,
            envelope.observed_at_ms,
            &envelope.delta,
        )
    }

    pub fn to_envelope(&self) -> PoolStateEnvelope {
        PoolStateEnvelope {
            pool_id: self.pool_id.clone(),
            sequence: self.sequence,
            observed_at_ms: self.timestamp_ms,
            state: PoolKindState::Cpmm(self.state.clone()),
        }
    }
}

/// Maintained local CLMM pool state reducer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClmmPoolReducer {
    pool_id: PoolId,
    sequence: Sequence,
    timestamp_ms: i64,
    state: ClmmPoolState,
    max_ticks: usize,
    #[serde(default)]
    resync_required: bool,
}

impl ClmmPoolReducer {
    pub fn new(
        pool_id: PoolId,
        sequence: Sequence,
        timestamp_ms: i64,
        state: ClmmPoolState,
        max_ticks: usize,
    ) -> Result<Self, MarketTypeError> {
        pool_id.validate()?;
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        if max_ticks == 0 || max_ticks > MAX_CLMM_TICKS {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: max_ticks,
                max: MAX_CLMM_TICKS,
            });
        }
        state.validate()?;
        if state.token_0.chain != pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.sqrt_price_x64 == 0 {
            return Err(MarketTypeError::ZeroPrice);
        }
        if state.ticks.len() > max_ticks {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: state.ticks.len(),
                max: max_ticks,
            });
        }
        Ok(Self {
            pool_id,
            sequence,
            timestamp_ms,
            state,
            max_ticks,
            resync_required: false,
        })
    }

    pub fn from_envelope(
        envelope: PoolStateEnvelope,
        max_ticks: usize,
    ) -> Result<Self, MarketTypeError> {
        envelope.validate()?;
        match envelope.state {
            PoolKindState::Clmm(clmm) => Self::new(
                envelope.pool_id,
                envelope.sequence,
                envelope.observed_at_ms,
                clmm,
                max_ticks,
            ),
            other => Err(MarketTypeError::PoolKindMismatch {
                expected: "clmm",
                received: other.kind_str(),
            }),
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }

    pub fn state(&self) -> &ClmmPoolState {
        &self.state
    }

    pub fn max_ticks(&self) -> usize {
        self.max_ticks
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    pub fn reset_with_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: ClmmPoolState,
    ) -> Result<(), MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.tick_spacing != self.state.tick_spacing {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.sqrt_price_x64 == 0 {
            return Err(MarketTypeError::ZeroPrice);
        }
        if state.ticks.len() > self.max_ticks {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: state.ticks.len(),
                max: self.max_ticks,
            });
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(())
    }

    pub fn reset_with_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<(), MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let clmm = match envelope.state {
            PoolKindState::Clmm(c) => c,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "clmm",
                    received: other.kind_str(),
                })
            }
        };
        self.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, clmm)
    }

    pub fn apply_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: ClmmPoolState,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.tick_spacing != self.state.tick_spacing {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.sqrt_price_x64 == 0 {
            return Err(MarketTypeError::ZeroPrice);
        }
        if state.ticks.len() > self.max_ticks {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: state.ticks.len(),
                max: self.max_ticks,
            });
        }

        if sequence < self.sequence {
            return Ok(SnapshotClassification::Stale {
                sequence,
                current: self.sequence,
            });
        }
        if sequence == self.sequence {
            return Ok(SnapshotClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(SnapshotClassification::Accepted {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_snapshot_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let clmm = match envelope.state {
            PoolKindState::Clmm(c) => c,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "clmm",
                    received: other.kind_str(),
                })
            }
        };
        self.apply_snapshot(envelope.sequence, envelope.observed_at_ms, clmm)
    }

    pub fn apply_delta(
        &mut self,
        sequence_range: SequenceRange,
        timestamp_ms: i64,
        delta: &ClmmPoolDelta,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.resync_required {
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        sequence_range.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        delta.validate()?;

        if sequence_range.end < self.sequence {
            return Ok(DeltaClassification::Stale {
                sequence: sequence_range.end,
                current: self.sequence,
            });
        }

        if sequence_range.end == self.sequence {
            return Ok(DeltaClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        if sequence_range.start != self.sequence.next() {
            self.resync_required = true;
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        // Validate tick alignment with pool's tick_spacing
        for tick in &delta.ticks {
            if tick.index % (self.state.tick_spacing as i32) != 0 {
                return Err(MarketTypeError::TickSpacingMismatch {
                    tick: tick.index,
                    spacing: self.state.tick_spacing,
                });
            }
        }

        // Stage mutation atomically
        let mut staged = self.state.clone();
        if let Some(ct) = delta.current_tick {
            staged.current_tick = ct;
        }
        if let Some(sq) = delta.sqrt_price_x64 {
            if sq == 0 {
                return Err(MarketTypeError::ZeroPrice);
            }
            staged.sqrt_price_x64 = sq;
        }
        if let Some(liq) = delta.liquidity {
            staged.liquidity = liq;
        }
        if let Some(fee) = delta.fee_bps {
            staged.fee_bps = fee;
        }

        for tick in &delta.ticks {
            if tick.liquidity_gross == 0 {
                if let Some(pos) = staged.ticks.iter().position(|t| t.index == tick.index) {
                    staged.ticks.remove(pos);
                }
            } else if let Some(pos) = staged.ticks.iter().position(|t| t.index == tick.index) {
                staged.ticks[pos] = *tick;
            } else {
                let pos = staged
                    .ticks
                    .iter()
                    .position(|t| t.index > tick.index)
                    .unwrap_or(staged.ticks.len());
                staged.ticks.insert(pos, *tick);
            }
        }

        if staged.ticks.len() > self.max_ticks {
            return Err(MarketTypeError::ClmmTicksExceeded {
                count: staged.ticks.len(),
                max: self.max_ticks,
            });
        }
        staged.validate()?;

        self.state = staged;
        self.sequence = sequence_range.end;
        self.timestamp_ms = timestamp_ms;

        Ok(DeltaClassification::Contiguous {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_delta_envelope(
        &mut self,
        envelope: &ClmmPoolDeltaEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        self.apply_delta(
            envelope.sequence_range,
            envelope.observed_at_ms,
            &envelope.delta,
        )
    }

    pub fn to_envelope(&self) -> PoolStateEnvelope {
        PoolStateEnvelope {
            pool_id: self.pool_id.clone(),
            sequence: self.sequence,
            observed_at_ms: self.timestamp_ms,
            state: PoolKindState::Clmm(self.state.clone()),
        }
    }

    pub fn tick_spacing(&self) -> u32 {
        self.state.tick_spacing
    }

    pub fn current_tick(&self) -> i32 {
        self.state.current_tick
    }

    pub fn sqrt_price_x64(&self) -> u128 {
        self.state.sqrt_price_x64
    }

    pub fn liquidity(&self) -> u128 {
        self.state.liquidity
    }

    pub fn ticks(&self) -> &[ClmmTick] {
        &self.state.ticks
    }
}

/// Maintained local Bin/DLMM pool state reducer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinPoolReducer {
    pool_id: PoolId,
    sequence: Sequence,
    timestamp_ms: i64,
    state: BinPoolState,
    max_bins: usize,
    #[serde(default)]
    resync_required: bool,
}

impl BinPoolReducer {
    pub fn new(
        pool_id: PoolId,
        sequence: Sequence,
        timestamp_ms: i64,
        state: BinPoolState,
        max_bins: usize,
    ) -> Result<Self, MarketTypeError> {
        pool_id.validate()?;
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        if max_bins == 0 || max_bins > MAX_BIN_COUNT {
            return Err(MarketTypeError::BinsExceeded {
                count: max_bins,
                max: MAX_BIN_COUNT,
            });
        }
        state.validate()?;
        if state.token_0.chain != pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.bins.len() > max_bins {
            return Err(MarketTypeError::BinsExceeded {
                count: state.bins.len(),
                max: max_bins,
            });
        }
        Ok(Self {
            pool_id,
            sequence,
            timestamp_ms,
            state,
            max_bins,
            resync_required: false,
        })
    }

    pub fn from_envelope(
        envelope: PoolStateEnvelope,
        max_bins: usize,
    ) -> Result<Self, MarketTypeError> {
        envelope.validate()?;
        match envelope.state {
            PoolKindState::Bin(bin) => Self::new(
                envelope.pool_id,
                envelope.sequence,
                envelope.observed_at_ms,
                bin,
                max_bins,
            ),
            other => Err(MarketTypeError::PoolKindMismatch {
                expected: "bin",
                received: other.kind_str(),
            }),
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }

    pub fn state(&self) -> &BinPoolState {
        &self.state
    }

    pub fn max_bins(&self) -> usize {
        self.max_bins
    }

    pub fn is_resync_required(&self) -> bool {
        self.resync_required
    }

    pub fn trigger_resync(&mut self) {
        self.resync_required = true;
    }

    pub fn reset_with_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: BinPoolState,
    ) -> Result<(), MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.bins.len() > self.max_bins {
            return Err(MarketTypeError::BinsExceeded {
                count: state.bins.len(),
                max: self.max_bins,
            });
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(())
    }

    pub fn reset_with_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<(), MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let bin = match envelope.state {
            PoolKindState::Bin(b) => b,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "bin",
                    received: other.kind_str(),
                })
            }
        };
        self.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, bin)
    }

    pub fn apply_snapshot(
        &mut self,
        sequence: Sequence,
        timestamp_ms: i64,
        state: BinPoolState,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        sequence.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        state.validate()?;
        if state.token_0.chain != self.pool_id.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if state.token_0 != self.state.token_0 || state.token_1 != self.state.token_1 {
            return Err(MarketTypeError::TargetMismatch);
        }
        if state.bins.len() > self.max_bins {
            return Err(MarketTypeError::BinsExceeded {
                count: state.bins.len(),
                max: self.max_bins,
            });
        }

        if sequence < self.sequence {
            return Ok(SnapshotClassification::Stale {
                sequence,
                current: self.sequence,
            });
        }
        if sequence == self.sequence {
            return Ok(SnapshotClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        self.sequence = sequence;
        self.timestamp_ms = timestamp_ms;
        self.state = state;
        self.resync_required = false;

        Ok(SnapshotClassification::Accepted {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_snapshot_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        let bin = match envelope.state {
            PoolKindState::Bin(b) => b,
            other => {
                return Err(MarketTypeError::PoolKindMismatch {
                    expected: "bin",
                    received: other.kind_str(),
                })
            }
        };
        self.apply_snapshot(envelope.sequence, envelope.observed_at_ms, bin)
    }

    pub fn apply_delta(
        &mut self,
        sequence_range: SequenceRange,
        timestamp_ms: i64,
        delta: &BinPoolDelta,
    ) -> Result<DeltaClassification, MarketTypeError> {
        if self.resync_required {
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        sequence_range.validate()?;
        if timestamp_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(timestamp_ms));
        }
        delta.validate()?;

        if sequence_range.end < self.sequence {
            return Ok(DeltaClassification::Stale {
                sequence: sequence_range.end,
                current: self.sequence,
            });
        }

        if sequence_range.end == self.sequence {
            return Ok(DeltaClassification::Duplicate {
                sequence: self.sequence,
            });
        }

        if sequence_range.start != self.sequence.next() {
            self.resync_required = true;
            return Ok(DeltaClassification::ResyncRequired {
                expected: self.sequence.next(),
                received: sequence_range.start,
            });
        }

        // Stage mutation atomically
        let mut staged = self.state.clone();
        if let Some(active_id) = delta.active_bin_id {
            staged.active_bin_id = active_id;
        }
        if let Some(step) = delta.bin_step {
            staged.bin_step = step;
        }
        if let Some(fee) = delta.fee_bps {
            staged.fee_bps = fee;
        }

        for bin in &delta.bins {
            if bin.reserve_0.is_zero() && bin.reserve_1.is_zero() {
                if let Some(pos) = staged.bins.iter().position(|b| b.id == bin.id) {
                    staged.bins.remove(pos);
                }
            } else if let Some(pos) = staged.bins.iter().position(|b| b.id == bin.id) {
                staged.bins[pos] = *bin;
            } else {
                let pos = staged
                    .bins
                    .iter()
                    .position(|b| b.id > bin.id)
                    .unwrap_or(staged.bins.len());
                staged.bins.insert(pos, *bin);
            }
        }

        if staged.bins.len() > self.max_bins {
            return Err(MarketTypeError::BinsExceeded {
                count: staged.bins.len(),
                max: self.max_bins,
            });
        }
        staged.validate()?;

        self.state = staged;
        self.sequence = sequence_range.end;
        self.timestamp_ms = timestamp_ms;

        Ok(DeltaClassification::Contiguous {
            new_sequence: self.sequence,
        })
    }

    pub fn apply_delta_envelope(
        &mut self,
        envelope: &BinPoolDeltaEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != self.pool_id {
            return Err(MarketTypeError::TargetMismatch);
        }
        self.apply_delta(
            envelope.sequence_range,
            envelope.observed_at_ms,
            &envelope.delta,
        )
    }

    pub fn to_envelope(&self) -> PoolStateEnvelope {
        PoolStateEnvelope {
            pool_id: self.pool_id.clone(),
            sequence: self.sequence,
            observed_at_ms: self.timestamp_ms,
            state: PoolKindState::Bin(self.state.clone()),
        }
    }

    pub fn active_bin_id(&self) -> i32 {
        self.state.active_bin_id
    }

    pub fn bin_step(&self) -> u16 {
        self.state.bin_step
    }

    pub fn bins(&self) -> &[LiquidityBin] {
        &self.state.bins
    }
}

/// Unified polymorphic local pool state reducer dispatching across CPMM, CLMM, and Bin/DLMM models.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reducer", rename_all = "snake_case")]
pub enum PoolReducer {
    Cpmm(CpmmPoolReducer),
    Clmm(ClmmPoolReducer),
    Bin(BinPoolReducer),
}

impl PoolReducer {
    pub fn new(envelope: PoolStateEnvelope) -> Result<Self, MarketTypeError> {
        Self::with_bounds(envelope, MAX_CLMM_TICKS, MAX_BIN_COUNT)
    }

    pub fn with_bounds(
        envelope: PoolStateEnvelope,
        max_ticks: usize,
        max_bins: usize,
    ) -> Result<Self, MarketTypeError> {
        envelope.validate()?;
        match envelope.state {
            PoolKindState::Cpmm(cpmm) => {
                let r = CpmmPoolReducer::new(
                    envelope.pool_id,
                    envelope.sequence,
                    envelope.observed_at_ms,
                    cpmm,
                )?;
                Ok(Self::Cpmm(r))
            }
            PoolKindState::Clmm(clmm) => {
                let r = ClmmPoolReducer::new(
                    envelope.pool_id,
                    envelope.sequence,
                    envelope.observed_at_ms,
                    clmm,
                    max_ticks,
                )?;
                Ok(Self::Clmm(r))
            }
            PoolKindState::Bin(bin) => {
                let r = BinPoolReducer::new(
                    envelope.pool_id,
                    envelope.sequence,
                    envelope.observed_at_ms,
                    bin,
                    max_bins,
                )?;
                Ok(Self::Bin(r))
            }
        }
    }

    pub fn pool_id(&self) -> &PoolId {
        match self {
            Self::Cpmm(r) => r.pool_id(),
            Self::Clmm(r) => r.pool_id(),
            Self::Bin(r) => r.pool_id(),
        }
    }

    pub fn sequence(&self) -> Sequence {
        match self {
            Self::Cpmm(r) => r.sequence(),
            Self::Clmm(r) => r.sequence(),
            Self::Bin(r) => r.sequence(),
        }
    }

    pub fn timestamp_ms(&self) -> i64 {
        match self {
            Self::Cpmm(r) => r.timestamp_ms(),
            Self::Clmm(r) => r.timestamp_ms(),
            Self::Bin(r) => r.timestamp_ms(),
        }
    }

    pub fn is_resync_required(&self) -> bool {
        match self {
            Self::Cpmm(r) => r.is_resync_required(),
            Self::Clmm(r) => r.is_resync_required(),
            Self::Bin(r) => r.is_resync_required(),
        }
    }

    pub fn trigger_resync(&mut self) {
        match self {
            Self::Cpmm(r) => r.trigger_resync(),
            Self::Clmm(r) => r.trigger_resync(),
            Self::Bin(r) => r.trigger_resync(),
        }
    }

    pub fn state(&self) -> PoolKindState {
        match self {
            Self::Cpmm(r) => PoolKindState::Cpmm(r.state().clone()),
            Self::Clmm(r) => PoolKindState::Clmm(r.state().clone()),
            Self::Bin(r) => PoolKindState::Bin(r.state().clone()),
        }
    }

    pub fn to_envelope(&self) -> PoolStateEnvelope {
        match self {
            Self::Cpmm(r) => r.to_envelope(),
            Self::Clmm(r) => r.to_envelope(),
            Self::Bin(r) => r.to_envelope(),
        }
    }

    pub fn reset_with_envelope(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<(), MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != *self.pool_id() {
            return Err(MarketTypeError::TargetMismatch);
        }
        match (self, envelope.state) {
            (Self::Cpmm(r), PoolKindState::Cpmm(c)) => {
                r.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, c)
            }
            (Self::Clmm(r), PoolKindState::Clmm(c)) => {
                r.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, c)
            }
            (Self::Bin(r), PoolKindState::Bin(b)) => {
                r.reset_with_snapshot(envelope.sequence, envelope.observed_at_ms, b)
            }
            (Self::Cpmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: other.kind_str(),
            }),
            (Self::Clmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "clmm",
                received: other.kind_str(),
            }),
            (Self::Bin(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "bin",
                received: other.kind_str(),
            }),
        }
    }

    pub fn apply_snapshot(
        &mut self,
        envelope: PoolStateEnvelope,
    ) -> Result<SnapshotClassification, MarketTypeError> {
        envelope.validate()?;
        if envelope.pool_id != *self.pool_id() {
            return Err(MarketTypeError::TargetMismatch);
        }
        match (self, envelope.state) {
            (Self::Cpmm(r), PoolKindState::Cpmm(c)) => {
                r.apply_snapshot(envelope.sequence, envelope.observed_at_ms, c)
            }
            (Self::Clmm(r), PoolKindState::Clmm(c)) => {
                r.apply_snapshot(envelope.sequence, envelope.observed_at_ms, c)
            }
            (Self::Bin(r), PoolKindState::Bin(b)) => {
                r.apply_snapshot(envelope.sequence, envelope.observed_at_ms, b)
            }
            (Self::Cpmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: other.kind_str(),
            }),
            (Self::Clmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "clmm",
                received: other.kind_str(),
            }),
            (Self::Bin(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "bin",
                received: other.kind_str(),
            }),
        }
    }

    pub fn apply_delta(
        &mut self,
        delta: &PoolDeltaEnvelope,
    ) -> Result<DeltaClassification, MarketTypeError> {
        delta.validate()?;
        if delta.pool_id != *self.pool_id() {
            return Err(MarketTypeError::TargetMismatch);
        }
        match (self, &delta.delta) {
            (Self::Cpmm(r), PoolKindDelta::Cpmm(d)) => {
                r.apply_delta(delta.sequence_range, delta.observed_at_ms, d)
            }
            (Self::Clmm(r), PoolKindDelta::Clmm(d)) => {
                r.apply_delta(delta.sequence_range, delta.observed_at_ms, d)
            }
            (Self::Bin(r), PoolKindDelta::Bin(d)) => {
                r.apply_delta(delta.sequence_range, delta.observed_at_ms, d)
            }
            (Self::Cpmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "cpmm",
                received: other.kind_str(),
            }),
            (Self::Clmm(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "clmm",
                received: other.kind_str(),
            }),
            (Self::Bin(_), other) => Err(MarketTypeError::PoolKindMismatch {
                expected: "bin",
                received: other.kind_str(),
            }),
        }
    }

    pub fn as_cpmm(&self) -> Option<&CpmmPoolReducer> {
        match self {
            Self::Cpmm(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_cpmm_mut(&mut self) -> Option<&mut CpmmPoolReducer> {
        match self {
            Self::Cpmm(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_clmm(&self) -> Option<&ClmmPoolReducer> {
        match self {
            Self::Clmm(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_clmm_mut(&mut self) -> Option<&mut ClmmPoolReducer> {
        match self {
            Self::Clmm(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_bin(&self) -> Option<&BinPoolReducer> {
        match self {
            Self::Bin(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_bin_mut(&mut self) -> Option<&mut BinPoolReducer> {
        match self {
            Self::Bin(r) => Some(r),
            _ => None,
        }
    }
}
