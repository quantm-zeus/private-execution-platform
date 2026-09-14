//! Pure, deterministic provider-route benchmark comparator (P80).
//!
//! This additive module compares one exact local route basis against one
//! externally supplied provider/aggregator quote and classifies the result as
//! agreement, disagreement, or a freshness/threshold skip. It never plans a
//! route, never touches the planner, and never reaches the network: both quotes
//! and the reference timestamp are supplied by the caller, and every ratio is
//! computed with exact 256-bit integer arithmetic.
//!
//! # Redaction
//! Provider references are opaque and never rendered. Manual [`fmt::Debug`]
//! implementations for [`ProviderQuote`], [`RouteComparisonRecord`], and
//! [`RealizedExecution`] omit amounts, assets, chain ids, and references;
//! [`ProviderQuote`] renders only the non-secret [`BenchmarkSource`] label.
//! [`ProviderQuote`] deliberately does not implement `serde`, so an opaque
//! reference can never cross a serialization boundary.

use std::fmt;

use chain_types::{AssetId, ChainId};
use market_types::Bps;
use serde::{Deserialize, Serialize};
use simulation::{div_u256_by_u128_floor, mul_u128_wide};

/// Maximum accepted [`BenchmarkSource`] label length in bytes.
pub const MAX_BENCHMARK_SOURCE_BYTES: usize = 64;

/// Maximum accepted opaque provider-reference length in bytes.
pub const MAX_BENCHMARK_REFERENCE_BYTES: usize = 256;

/// Number of basis points in one whole unit (the deviation scale).
const BPS_SCALE: u128 = 10_000;

/// Default disagreement threshold in basis points.
const DEFAULT_DISAGREEMENT_BPS: u16 = 50;

/// Default maximum accepted provider-quote age in milliseconds.
const DEFAULT_MAX_PROVIDER_AGE_MS: u64 = 5_000;

/// Default maximum accepted local-state age in milliseconds.
const DEFAULT_MAX_LOCAL_STATE_AGE_MS: u64 = 2_000;

/// Validated benchmark-source label (printable non-space ASCII, 1..=64 bytes).
///
/// The label is not secret and may be rendered; it identifies the provider or
/// aggregator a [`ProviderQuote`] came from. It deliberately does not implement
/// `serde`, so a provider identity never crosses a wire boundary with a quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkSource(String);

impl BenchmarkSource {
    /// Validates and constructs a benchmark-source label.
    ///
    /// Only printable, non-space ASCII in `0x21..=0x7e` of length
    /// `1..=MAX_BENCHMARK_SOURCE_BYTES` is accepted, so an empty, whitespace,
    /// control-character, or non-ASCII label fails closed.
    pub fn new(value: impl Into<String>) -> Result<Self, BenchmarkError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_BENCHMARK_SOURCE_BYTES {
            return Err(BenchmarkError::InvalidSource);
        }
        if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(BenchmarkError::InvalidSource);
        }
        Ok(Self(value))
    }

    /// Returns the validated label text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact local route economics for one comparison basis.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouteQuote {
    /// Chain the local route executes on.
    pub chain: ChainId,
    /// Input asset of the local route.
    pub token_in: AssetId,
    /// Output asset of the local route.
    pub token_out: AssetId,
    /// Wallet-debit basis (net input) in `token_in` atomic units.
    pub amount_in: u128,
    /// Net output received in `token_out` atomic units.
    pub amount_out: u128,
    /// Caller reference time the local basis was observed at, in milliseconds.
    pub observed_at_ms: i64,
}

impl LocalRouteQuote {
    /// Constructs a local route basis.
    ///
    /// Binding and feasibility checks happen in [`compare_route`], so
    /// construction itself is infallible.
    pub fn new(
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: u128,
        amount_out: u128,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            chain,
            token_in,
            token_out,
            amount_in,
            amount_out,
            observed_at_ms,
        }
    }
}

/// Externally supplied provider/aggregator quote for the same basis.
///
/// The opaque `reference` is private and is never rendered or serialized;
/// `ProviderQuote` deliberately does not implement `serde`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderQuote {
    /// Validated provider/aggregator label.
    pub source: BenchmarkSource,
    /// Chain the provider quote is for.
    pub chain: ChainId,
    /// Input asset the provider quote was requested for.
    pub token_in: AssetId,
    /// Output asset the provider quote was requested for.
    pub token_out: AssetId,
    /// Input basis in `token_in` atomic units.
    pub amount_in: u128,
    /// Quoted output in `token_out` atomic units.
    pub amount_out: u128,
    /// Caller reference time the provider quote was observed at, in
    /// milliseconds.
    pub observed_at_ms: i64,
    /// Opaque provider reference, never rendered.
    reference: String,
}

impl fmt::Debug for ProviderQuote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: amounts, assets, chain, and the opaque reference are private
        // execution economics. Only the non-secret source label renders.
        formatter
            .debug_struct("ProviderQuote")
            .field("source", &self.source.as_str())
            .finish_non_exhaustive()
    }
}

impl ProviderQuote {
    /// Validates the opaque reference and constructs a provider quote.
    ///
    /// The reference must be `1..=MAX_BENCHMARK_REFERENCE_BYTES` bytes; it is
    /// otherwise opaque and is never rendered.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: BenchmarkSource,
        chain: ChainId,
        token_in: AssetId,
        token_out: AssetId,
        amount_in: u128,
        amount_out: u128,
        observed_at_ms: i64,
        reference: impl Into<String>,
    ) -> Result<Self, BenchmarkError> {
        let reference = reference.into();
        if reference.is_empty() || reference.len() > MAX_BENCHMARK_REFERENCE_BYTES {
            return Err(BenchmarkError::InvalidReference);
        }
        Ok(Self {
            source,
            chain,
            token_in,
            token_out,
            amount_in,
            amount_out,
            observed_at_ms,
            reference,
        })
    }

    /// Returns the opaque provider reference (never rendered by `Debug`).
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// Caller-supplied thresholds for one benchmark comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchmarkPolicy {
    /// Deviation (in basis points) at or below which the comparison agrees.
    pub disagreement_bps: Bps,
    /// Maximum accepted provider-quote age in milliseconds.
    pub max_provider_age_ms: u64,
    /// Maximum accepted local-state age in milliseconds.
    pub max_local_state_age_ms: u64,
    /// Inputs below this many atomic units are not treated as large orders.
    pub min_input_atomic: u128,
}

impl Default for BenchmarkPolicy {
    fn default() -> Self {
        Self {
            disagreement_bps: bounded_bps(DEFAULT_DISAGREEMENT_BPS),
            max_provider_age_ms: DEFAULT_MAX_PROVIDER_AGE_MS,
            max_local_state_age_ms: DEFAULT_MAX_LOCAL_STATE_AGE_MS,
            min_input_atomic: 0,
        }
    }
}

impl BenchmarkPolicy {
    /// Constructs a benchmark policy from explicit thresholds.
    pub fn new(
        disagreement_bps: Bps,
        max_provider_age_ms: u64,
        max_local_state_age_ms: u64,
        min_input_atomic: u128,
    ) -> Self {
        Self {
            disagreement_bps,
            max_provider_age_ms,
            max_local_state_age_ms,
            min_input_atomic,
        }
    }
}

/// Returns the first representable bps value at or below `value`.
///
/// [`Bps::new`] is fallible only above [`Bps::MAX`], and the constants used by
/// this module are always in range, so the loop returns on its first iteration.
/// It scans downward instead of using a panicking conversion so the constructor
/// stays total and free of `unwrap`/`expect`/`panic`.
fn bounded_bps(value: u16) -> Bps {
    let mut candidate = value.min(Bps::MAX);
    loop {
        match Bps::new(candidate) {
            Ok(bps) => return bps,
            Err(_) => candidate = candidate.saturating_sub(1),
        }
    }
}

/// Which side of the comparison produced the better exact output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkDirection {
    /// Local net output is greater than or equal to the provider's.
    LocalBetter,
    /// Provider net output is strictly greater than the local net output.
    ProviderBetter,
}

/// Reason a comparison was skipped without producing a deviation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkSkip {
    /// Input is below [`BenchmarkPolicy::min_input_atomic`].
    BelowLargeOrderThreshold,
    /// Provider quote is older than [`BenchmarkPolicy::max_provider_age_ms`].
    ProviderStale,
    /// Local state is older than [`BenchmarkPolicy::max_local_state_age_ms`].
    LocalStateStale,
}

/// Deterministic outcome of one local-vs-provider comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkVerdict {
    /// Deviation is at or below the configured disagreement threshold.
    Agree {
        /// Exact deviation in basis points.
        deviation_bps: u16,
        /// Side with the better exact output.
        direction: BenchmarkDirection,
    },
    /// Deviation exceeds the configured disagreement threshold.
    Disagree {
        /// Exact deviation in basis points.
        deviation_bps: u16,
        /// Side with the better exact output.
        direction: BenchmarkDirection,
    },
    /// The basis was not compared; see [`BenchmarkSkip`].
    Skipped(BenchmarkSkip),
}

/// Fail-closed benchmark comparison errors.
///
/// Every variant is structural and carries no value-bearing payload.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BenchmarkError {
    /// A benchmark-source label failed its structural contract.
    #[error("invalid benchmark source")]
    InvalidSource,
    /// A provider reference failed its structural contract.
    #[error("invalid benchmark reference")]
    InvalidReference,
    /// The local route and provider quote are on different chains.
    #[error("benchmark chain mismatch")]
    ChainMismatch,
    /// The local route and provider quote use different asset pairs.
    #[error("benchmark asset pair mismatch")]
    PairMismatch,
    /// The local route and provider quote bind different input amounts.
    #[error("benchmark input mismatch")]
    InputMismatch,
    /// The comparison input is zero.
    #[error("benchmark input is zero")]
    ZeroInput,
    /// The local route net output is zero.
    #[error("benchmark local output is zero")]
    ZeroLocalOutput,
    /// The provider quote output is zero.
    #[error("benchmark provider output is zero")]
    ZeroProviderOutput,
    /// The provider quote is timestamped after the caller reference time.
    #[error("benchmark quote is from the future")]
    ProviderFromFuture,
    /// The local state is timestamped after the caller reference time.
    #[error("benchmark local state is from the future")]
    LocalFromFuture,
    /// The exact deviation is not representable as a `u16`.
    #[error("benchmark arithmetic overflow")]
    ArithmeticOverflow,
}

/// Compares one local route basis against one provider quote.
///
/// # Determinism and check order
/// The comparison is pure and integer-only; `now_ms` is the caller's reference
/// time. Checks run in a fixed order:
/// 1. chain, asset-pair, and input-amount binding errors;
/// 2. zero-input and zero-local-output errors;
/// 3. future-timestamp errors (local first, then provider) — before any skip;
/// 4. skips: below-threshold, then stale-local, then stale-provider;
/// 5. zero-provider-output;
/// 6. exact deviation and the direction/agreement verdict.
///
/// Deviation is `floor(10_000 * |local.amount_out - provider.amount_out| /
/// provider.amount_out)`, computed with the exact 256-bit helpers
/// [`mul_u128_wide`] and [`div_u256_by_u128_floor`]. A non-computable quotient,
/// or one above `u16::MAX`, fails closed to
/// [`BenchmarkError::ArithmeticOverflow`]. Exact ties count as
/// [`BenchmarkDirection::LocalBetter`], and the agreement threshold is
/// inclusive (`<=`).
pub fn compare_route(
    local: &LocalRouteQuote,
    provider: &ProviderQuote,
    policy: &BenchmarkPolicy,
    now_ms: i64,
) -> Result<BenchmarkVerdict, BenchmarkError> {
    if local.chain != provider.chain {
        return Err(BenchmarkError::ChainMismatch);
    }
    if local.token_in != provider.token_in || local.token_out != provider.token_out {
        return Err(BenchmarkError::PairMismatch);
    }
    if local.amount_in != provider.amount_in {
        return Err(BenchmarkError::InputMismatch);
    }
    if local.amount_in == 0 {
        return Err(BenchmarkError::ZeroInput);
    }
    if local.amount_out == 0 {
        return Err(BenchmarkError::ZeroLocalOutput);
    }
    if now_ms < local.observed_at_ms {
        return Err(BenchmarkError::LocalFromFuture);
    }
    if now_ms < provider.observed_at_ms {
        return Err(BenchmarkError::ProviderFromFuture);
    }
    if local.amount_in < policy.min_input_atomic {
        return Ok(BenchmarkVerdict::Skipped(
            BenchmarkSkip::BelowLargeOrderThreshold,
        ));
    }
    // Future checks above guarantee both ages are non-negative; the `i128` math
    // avoids any overflow in the difference itself.
    let local_age_ms = i128::from(now_ms) - i128::from(local.observed_at_ms);
    if local_age_ms > i128::from(policy.max_local_state_age_ms) {
        return Ok(BenchmarkVerdict::Skipped(BenchmarkSkip::LocalStateStale));
    }
    let provider_age_ms = i128::from(now_ms) - i128::from(provider.observed_at_ms);
    if provider_age_ms > i128::from(policy.max_provider_age_ms) {
        return Ok(BenchmarkVerdict::Skipped(BenchmarkSkip::ProviderStale));
    }
    if provider.amount_out == 0 {
        return Err(BenchmarkError::ZeroProviderOutput);
    }

    let diff = local.amount_out.abs_diff(provider.amount_out);
    let (hi, lo) = mul_u128_wide(BPS_SCALE, diff);
    let deviation = div_u256_by_u128_floor(hi, lo, provider.amount_out)
        .ok_or(BenchmarkError::ArithmeticOverflow)?;
    if deviation > u128::from(u16::MAX) {
        return Err(BenchmarkError::ArithmeticOverflow);
    }
    let deviation_bps = deviation as u16;
    let direction = if local.amount_out >= provider.amount_out {
        BenchmarkDirection::LocalBetter
    } else {
        BenchmarkDirection::ProviderBetter
    };
    if deviation_bps <= policy.disagreement_bps.get() {
        Ok(BenchmarkVerdict::Agree {
            deviation_bps,
            direction,
        })
    } else {
        Ok(BenchmarkVerdict::Disagree {
            deviation_bps,
            direction,
        })
    }
}

/// Analytics record for "our route vs provider route vs actual execution".
///
/// Redacted [`fmt::Debug`]; deliberately not `Serialize` (never a
/// telemetry/log payload).
#[derive(Clone, PartialEq, Eq)]
pub struct RouteComparisonRecord {
    source: BenchmarkSource,
    deviation_bps: u16,
    direction: BenchmarkDirection,
    realized: Option<RealizedExecution>,
}

impl RouteComparisonRecord {
    /// Builds a record from a comparison basis and its verdict.
    ///
    /// A skipped comparison carries no deviation; the record reports `0` basis
    /// points and the raw output ordering as the direction.
    pub fn new(
        local: &LocalRouteQuote,
        provider: &ProviderQuote,
        verdict: BenchmarkVerdict,
    ) -> Self {
        let (deviation_bps, direction) = match verdict {
            BenchmarkVerdict::Agree {
                deviation_bps,
                direction,
            }
            | BenchmarkVerdict::Disagree {
                deviation_bps,
                direction,
            } => (deviation_bps, direction),
            BenchmarkVerdict::Skipped(_) => (
                0,
                if local.amount_out >= provider.amount_out {
                    BenchmarkDirection::LocalBetter
                } else {
                    BenchmarkDirection::ProviderBetter
                },
            ),
        };
        Self {
            source: provider.source.clone(),
            deviation_bps,
            direction,
            realized: None,
        }
    }

    /// Attaches the realized execution observed for the compared basis.
    pub fn with_realized(mut self, realized: RealizedExecution) -> Self {
        self.realized = Some(realized);
        self
    }

    /// Returns the comparison deviation in basis points (`0` when skipped).
    pub fn deviation_bps(&self) -> u16 {
        self.deviation_bps
    }

    /// Returns the comparison direction (raw output ordering when skipped).
    pub fn direction(&self) -> BenchmarkDirection {
        self.direction
    }
}

impl fmt::Debug for RouteComparisonRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: only the non-secret source label and the derived verdict
        // fields render; amounts, assets, chain, and reference are omitted.
        formatter
            .debug_struct("RouteComparisonRecord")
            .field("source", &self.source.as_str())
            .field("deviation_bps", &self.deviation_bps)
            .field("direction", &self.direction)
            .field("realized", &self.realized.is_some())
            .finish_non_exhaustive()
    }
}

/// Amounts actually realized for a benchmarked basis.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RealizedExecution {
    /// Net input consumed, in `token_in` atomic units.
    pub amount_in: u128,
    /// Net output received, in `token_out` atomic units.
    pub amount_out: u128,
}

impl fmt::Debug for RealizedExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: realized amounts are private execution economics.
        formatter.write_str("RealizedExecution { .. }")
    }
}
