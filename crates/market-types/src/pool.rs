//! Adapter-neutral pool state representations for CPMM, CLMM, and bin-based pools.

use chain_types::AssetId;
use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::identity::PoolId;
use crate::primitives::{AtomicAmount, Bps, Sequence};

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
