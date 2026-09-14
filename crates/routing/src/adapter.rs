//! Additive DEX adapter boundary for the pure quote/simulate/swap-instruction
//! responsibilities.
//!
//! Each adapter is stateless and pure: it never mutates the supplied pool state,
//! never reads a clock or RNG, never performs I/O or network access, and uses no
//! floating point. Exact-in/exact-out economics are delegated to the authoritative
//! landed `simulation` kernels (and [`crate::impact::cpmm_impact_bps`] for CPMM
//! impact), so no fee or output arithmetic is re-implemented here. Every typed
//! kernel failure is mapped into the existing redacted [`RoutingError`] variants.
//!
//! Discovery and pool-state update are feed concerns and are intentionally out of
//! scope for this additive boundary.

use chain_types::AssetId;
use market_types::{AssetAmount, AtomicAmount, Bps, PoolKindState};
use serde::{Deserialize, Serialize};
use simulation::{
    simulate_bin_exact_input, simulate_bin_exact_output, simulate_clmm_exact_input,
    simulate_clmm_exact_output, simulate_cpmm_exact_input, simulate_cpmm_exact_output,
    BinExactInputRequest, BinExactOutputRequest, ClmmExactInputRequest, ClmmExactOutputRequest,
    CpmmExactInputRequest, CpmmExactOutputRequest, CpmmSimulationErrorClass,
};

use crate::error::RoutingError;
use crate::impact::cpmm_impact_bps;
use crate::label::PoolRefLabel;

/// Hard bound on the number of adapters accepted in one registry.
pub const MAX_ADAPTERS: usize = 16;

/// Chain-agnostic exact quote returned by a pool adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterQuote {
    /// Adapter venue label.
    pub venue: String,
    /// Caller-supplied [`PoolRefLabel`] text.
    pub pool_ref: String,
    /// Exact input asset.
    pub token_in: AssetId,
    /// Exact counter-asset produced by the pool.
    pub token_out: AssetId,
    /// Gross input consumed by the pool.
    pub amount_in: AtomicAmount,
    /// Gross pool output (pre-route-tax).
    pub amount_out: AtomicAmount,
    /// Input-denominated pool fee.
    pub pool_fee: AssetAmount,
    /// Effective post-fee input entering the pool calculation.
    pub effective_input: AtomicAmount,
    /// Exact price impact for CPMM; `None` for CLMM/Bin (no local model).
    pub impact_bps: Option<Bps>,
}

/// Chain-agnostic swap instruction produced by a swap builder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapInstruction {
    /// Adapter venue label.
    pub venue: String,
    /// Pool account (EVM) or program id (Solana) reference text.
    pub pool_ref: String,
    /// Exact input asset.
    pub token_in: AssetId,
    /// Exact output asset.
    pub token_out: AssetId,
    /// Exact input amount to offer.
    pub amount_in: AtomicAmount,
    /// Minimum acceptable output floor.
    pub min_amount_out: AtomicAmount,
}

/// Pool-family quote/simulation adapter (pure, injected, no I/O).
pub trait DexAdapter: Send + Sync {
    /// Stable venue label (e.g. `"cpmm"`, `"clmm"`, `"bin"`).
    fn venue(&self) -> &'static str;

    /// Whether this adapter can quote `state`.
    fn supports(&self, state: &PoolKindState) -> bool;

    /// Exact-input quote.
    fn quote_exact_in(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_in: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError>;

    /// Exact-output quote (minimal gross input).
    fn quote_exact_out(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_out: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError>;

    /// Builds a chain-agnostic swap instruction from a quote and a floor.
    ///
    /// Fails closed when `min_amount_out > quote.amount_out`.
    fn swap_instruction(
        &self,
        quote: &AdapterQuote,
        min_amount_out: AtomicAmount,
    ) -> Result<SwapInstruction, RoutingError>;
}

/// CPMM (`PoolKindState::Cpmm`) adapter backed by the landed CPMM kernel.
pub struct CpmmAdapter;

/// CLMM (`PoolKindState::Clmm`) adapter backed by the landed CLMM kernel.
pub struct ClmmAdapter;

/// Bin/DLMM (`PoolKindState::Bin`) adapter backed by the landed Bin kernel.
pub struct BinAdapter;

/// Builds the shared swap instruction, failing closed above the quoted output.
fn build_swap_instruction(
    quote: &AdapterQuote,
    min_amount_out: AtomicAmount,
) -> Result<SwapInstruction, RoutingError> {
    if min_amount_out.get() > quote.amount_out.get() {
        return Err(RoutingError::MinAmountOutExceedsQuote);
    }
    Ok(SwapInstruction {
        venue: quote.venue.clone(),
        pool_ref: quote.pool_ref.clone(),
        token_in: quote.token_in.clone(),
        token_out: quote.token_out.clone(),
        amount_in: quote.amount_in,
        min_amount_out,
    })
}

fn unsupported(kind: &PoolKindState) -> RoutingError {
    match kind {
        PoolKindState::Cpmm(_) | PoolKindState::Clmm(_) | PoolKindState::Bin(_) => {
            RoutingError::UnsupportedPoolKind
        }
    }
}

impl DexAdapter for CpmmAdapter {
    fn venue(&self) -> &'static str {
        "cpmm"
    }

    fn supports(&self, state: &PoolKindState) -> bool {
        matches!(state, PoolKindState::Cpmm(_))
    }

    fn quote_exact_in(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_in: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Cpmm(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = CpmmExactInputRequest::new(token_in.clone(), amount_in);
        let quote = simulate_cpmm_exact_input(pool, &request)
            .map_err(|error| RoutingError::Cpmm(CpmmSimulationErrorClass::from(error)))?;
        let impact_bps = cpmm_impact_bps(
            quote.effective_input.amount.get(),
            quote.resulting_reserve_in.get(),
            amount_in.get(),
        );
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.pool_fee,
            effective_input: quote.effective_input.amount,
            impact_bps,
        })
    }

    fn quote_exact_out(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_out: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Cpmm(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = CpmmExactOutputRequest::new(token_in.clone(), amount_out);
        let quote = simulate_cpmm_exact_output(pool, &request)
            .map_err(|error| RoutingError::Cpmm(CpmmSimulationErrorClass::from(error)))?;
        let impact_bps = cpmm_impact_bps(
            quote.effective_input.amount.get(),
            quote.resulting_reserve_in.get(),
            quote.input.amount.get(),
        );
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.pool_fee,
            effective_input: quote.effective_input.amount,
            impact_bps,
        })
    }

    fn swap_instruction(
        &self,
        quote: &AdapterQuote,
        min_amount_out: AtomicAmount,
    ) -> Result<SwapInstruction, RoutingError> {
        build_swap_instruction(quote, min_amount_out)
    }
}

impl DexAdapter for ClmmAdapter {
    fn venue(&self) -> &'static str {
        "clmm"
    }

    fn supports(&self, state: &PoolKindState) -> bool {
        matches!(state, PoolKindState::Clmm(_))
    }

    fn quote_exact_in(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_in: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Clmm(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = ClmmExactInputRequest {
            token_in: token_in.clone(),
            amount_in,
            token_out: None,
        };
        let quote = simulate_clmm_exact_input(pool, &request).map_err(RoutingError::Clmm)?;
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.fee,
            effective_input: quote.effective_input.amount,
            impact_bps: None,
        })
    }

    fn quote_exact_out(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_out: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Clmm(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = ClmmExactOutputRequest::new(token_in.clone(), amount_out);
        let quote = simulate_clmm_exact_output(pool, &request).map_err(RoutingError::Clmm)?;
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.fee,
            effective_input: quote.effective_input.amount,
            impact_bps: None,
        })
    }

    fn swap_instruction(
        &self,
        quote: &AdapterQuote,
        min_amount_out: AtomicAmount,
    ) -> Result<SwapInstruction, RoutingError> {
        build_swap_instruction(quote, min_amount_out)
    }
}

impl DexAdapter for BinAdapter {
    fn venue(&self) -> &'static str {
        "bin"
    }

    fn supports(&self, state: &PoolKindState) -> bool {
        matches!(state, PoolKindState::Bin(_))
    }

    fn quote_exact_in(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_in: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Bin(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = BinExactInputRequest::new(token_in.clone(), amount_in);
        let quote = simulate_bin_exact_input(pool, &request).map_err(RoutingError::Bin)?;
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.fee,
            effective_input: quote.effective_input.amount,
            impact_bps: None,
        })
    }

    fn quote_exact_out(
        &self,
        pool_ref: &PoolRefLabel,
        state: &PoolKindState,
        token_in: &AssetId,
        amount_out: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        let pool = match state {
            PoolKindState::Bin(pool) => pool,
            other => return Err(unsupported(other)),
        };
        let request = BinExactOutputRequest::new(token_in.clone(), amount_out);
        let quote = simulate_bin_exact_output(pool, &request).map_err(RoutingError::Bin)?;
        Ok(AdapterQuote {
            venue: self.venue().to_string(),
            pool_ref: pool_ref.as_str().to_string(),
            token_in: token_in.clone(),
            token_out: quote.output.asset.clone(),
            amount_in: quote.input.amount,
            amount_out: quote.output.amount,
            pool_fee: quote.fee,
            effective_input: quote.effective_input.amount,
            impact_bps: None,
        })
    }

    fn swap_instruction(
        &self,
        quote: &AdapterQuote,
        min_amount_out: AtomicAmount,
    ) -> Result<SwapInstruction, RoutingError> {
        build_swap_instruction(quote, min_amount_out)
    }
}

/// Deterministic, bounded adapter registry.
///
/// The registry owns adapters in caller-supplied order. Lookup is a linear scan,
/// so the first supporting adapter is always selected and output never depends on
/// hash-map iteration.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn DexAdapter>>,
}

impl AdapterRegistry {
    /// Builds a registry from adapters, bounded by [`MAX_ADAPTERS`].
    ///
    /// Rejects an empty adapter list and any duplicate venue label. The venue
    /// labels of the retained adapters are unique, so dispatcher output is
    /// deterministic.
    pub fn new(adapters: Vec<Box<dyn DexAdapter>>) -> Result<Self, RoutingError> {
        if adapters.is_empty() {
            return Err(RoutingError::EmptyPoolSet);
        }
        if adapters.len() > MAX_ADAPTERS {
            return Err(RoutingError::BudgetExceeded);
        }
        for (index, adapter) in adapters.iter().enumerate() {
            let venue = adapter.venue();
            if adapters[..index]
                .iter()
                .any(|existing| existing.venue() == venue)
            {
                return Err(RoutingError::InvalidVenueLabel);
            }
        }
        Ok(Self { adapters })
    }

    /// The three local pool-family adapters in a fixed order.
    pub fn local() -> Self {
        Self {
            adapters: vec![
                Box::new(CpmmAdapter),
                Box::new(ClmmAdapter),
                Box::new(BinAdapter),
            ],
        }
    }

    /// Quotes exact-input through the first adapter that supports `state`.
    pub fn quote_exact_in(
        &self,
        state: &PoolKindState,
        pool_ref: &PoolRefLabel,
        token_in: &AssetId,
        amount_in: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        for adapter in &self.adapters {
            if adapter.supports(state) {
                return adapter.quote_exact_in(pool_ref, state, token_in, amount_in);
            }
        }
        Err(RoutingError::UnsupportedPoolKind)
    }

    /// Quotes exact-output through the first adapter that supports `state`.
    pub fn quote_exact_out(
        &self,
        state: &PoolKindState,
        pool_ref: &PoolRefLabel,
        token_in: &AssetId,
        amount_out: AtomicAmount,
    ) -> Result<AdapterQuote, RoutingError> {
        for adapter in &self.adapters {
            if adapter.supports(state) {
                return adapter.quote_exact_out(pool_ref, state, token_in, amount_out);
            }
        }
        Err(RoutingError::UnsupportedPoolKind)
    }
}
