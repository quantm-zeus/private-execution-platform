//! Strongly typed market and pool identities.

use chain_types::{AssetId, ChainId};
use serde::{Deserialize, Serialize};

use crate::error::MarketTypeError;

/// Unique identifier for an on-chain liquidity pool.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolId {
    pub chain: ChainId,
    pub address: String,
}

impl PoolId {
    pub fn new(chain: ChainId, address: impl Into<String>) -> Result<Self, MarketTypeError> {
        let id = Self {
            chain,
            address: address.into(),
        };
        id.validate()?;
        Ok(id)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.chain
            .validate()
            .map_err(|_| MarketTypeError::ChainMismatch)?;
        if self.address.trim().is_empty() {
            return Err(MarketTypeError::EmptyAddress);
        }
        Ok(())
    }
}

/// Strongly typed trading instrument identifier composed of base and quote assets on the same chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstrumentId {
    pub base: AssetId,
    pub quote: AssetId,
}

impl InstrumentId {
    pub fn new(base: AssetId, quote: AssetId) -> Result<Self, MarketTypeError> {
        let inst = Self { base, quote };
        inst.validate()?;
        Ok(inst)
    }

    pub fn validate(&self) -> Result<(), MarketTypeError> {
        self.base
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;
        self.quote
            .validate()
            .map_err(|_| MarketTypeError::EmptyAddress)?;
        if self.base.chain != self.quote.chain {
            return Err(MarketTypeError::ChainMismatch);
        }
        if self.base == self.quote {
            return Err(MarketTypeError::SameAssetPair);
        }
        Ok(())
    }
}

/// Target entity for a market data feed or stream.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "target_type", content = "target_id")]
pub enum FeedTarget {
    Pool(PoolId),
    Instrument(InstrumentId),
}

impl FeedTarget {
    pub fn validate(&self) -> Result<(), MarketTypeError> {
        match self {
            Self::Pool(p) => p.validate(),
            Self::Instrument(i) => i.validate(),
        }
    }

    pub fn chain(&self) -> &ChainId {
        match self {
            Self::Pool(p) => &p.chain,
            Self::Instrument(i) => &i.base.chain,
        }
    }
}
