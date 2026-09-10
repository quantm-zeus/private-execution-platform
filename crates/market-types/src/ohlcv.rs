//! Normalized bounded candle (OHLCV) representations.

use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;
use crate::identity::InstrumentId;
use crate::orderbook::{NormalizedPrice, NormalizedQuantity};

pub const MAX_CANDLE_WINDOW_MS: u64 = 366 * 86_400 * 1_000; // 366 days

/// Standard and custom timeframes for OHLCV aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandleTimeframe {
    S1,
    S5,
    S15,
    M1,
    M5,
    M15,
    M30,
    H1,
    H4,
    D1,
    W1,
    Custom(u64),
}

impl CandleTimeframe {
    pub const fn duration_ms(&self) -> u64 {
        match self {
            Self::S1 => 1_000,
            Self::S5 => 5_000,
            Self::S15 => 15_000,
            Self::M1 => 60_000,
            Self::M5 => 300_000,
            Self::M15 => 900_000,
            Self::M30 => 1_800_000,
            Self::H1 => 3_600_000,
            Self::H4 => 14_400_000,
            Self::D1 => 86_400_000,
            Self::W1 => 604_800_000,
            Self::Custom(ms) => *ms,
        }
    }

    pub fn parse_str(s: &str) -> Result<Self, MarketTypeError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "1s" => Ok(Self::S1),
            "5s" => Ok(Self::S5),
            "15s" => Ok(Self::S15),
            "1m" => Ok(Self::M1),
            "5m" => Ok(Self::M5),
            "15m" => Ok(Self::M15),
            "30m" => Ok(Self::M30),
            "1h" => Ok(Self::H1),
            "4h" => Ok(Self::H4),
            "1d" => Ok(Self::D1),
            "1w" => Ok(Self::W1),
            other => Err(MarketTypeError::InvalidCandleTimeframe(other.to_string())),
        }
    }
}

/// Normalized bounded candle representing OHLCV data for an instrument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candle {
    pub instrument: InstrumentId,
    pub timeframe: CandleTimeframe,
    pub open_time_ms: i64,
    pub close_time_ms: i64,
    pub open: NormalizedPrice,
    pub high: NormalizedPrice,
    pub low: NormalizedPrice,
    pub close: NormalizedPrice,
    pub volume: NormalizedQuantity,
    pub quote_volume: Option<NormalizedQuantity>,
    pub trades_count: Option<u64>,
}

impl Candle {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.instrument.validate()?;

        if self.open_time_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.open_time_ms));
        }
        if self.close_time_ms <= 0 {
            return Err(MarketTypeError::InvalidTimestamp(self.close_time_ms));
        }
        if self.open_time_ms >= self.close_time_ms {
            return Err(MarketTypeError::InvalidCandleWindow {
                open_ms: self.open_time_ms,
                close_ms: self.close_time_ms,
            });
        }

        let duration_ms = (self.close_time_ms - self.open_time_ms) as u64;
        if duration_ms > MAX_CANDLE_WINDOW_MS {
            return Err(MarketTypeError::CandleWindowExceeded {
                duration_ms,
                max_ms: MAX_CANDLE_WINDOW_MS,
            });
        }

        if self.open.is_zero() || self.high.is_zero() || self.low.is_zero() || self.close.is_zero()
        {
            return Err(MarketTypeError::ZeroPrice);
        }

        // Validate ordered bounds:
        // low must be <= open, close, high
        // high must be >= open, close, low
        if self.low > self.open {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "low price exceeds open price",
            });
        }
        if self.low > self.close {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "low price exceeds close price",
            });
        }
        if self.open > self.high {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "open price exceeds high price",
            });
        }
        if self.close > self.high {
            return Err(MarketTypeError::InvalidCandleBounds {
                reason: "close price exceeds high price",
            });
        }

        Ok(())
    }
}
