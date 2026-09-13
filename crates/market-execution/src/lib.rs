//! Concrete relay-backed [`agent_backend::MarketExecutionPort`] composition
//! (slice P72).
//!
//! `agent_backend` delegates an already-quoted market order to an injected
//! [`MarketExecutionPort`]; its default fails closed. This crate supplies the
//! concrete composition over the landed execution relay: for one trusted,
//! already-quoted market request it runs the authority check, the locked
//! pre-sign revalidation gate, and the relay's reserve-before-sign exactly-once
//! sign+submit path.
//!
//! # Flow
//! 1. [`MarketExecutionTrustSource::trust`] yields authoritative pre-sign state
//!    (policy context, wallet balance, allowance, tax observation, allowlist,
//!    freshness policy). It is sourced from backend state, never from a
//!    Web/MCP/Telegram payload.
//! 2. [`policy::PolicyEngine::authorize_trade`] runs on the *same* engine that
//!    gates the relay ([`execution_relay::ExecutionRelay::policy`]) for the
//!    kill switch, chain, size, turnover, risk, and venue checks.
//! 3. [`execution_preview::revalidate_pre_sign`] re-proves freshness, balance,
//!    allowance, tax, min-out, route, recipient, allowlist, amount, and policy.
//! 4. [`execution_relay::ExecutionRelay::execute`] claims the attempt before
//!    signing and signs+submits at most once.
//! 5. The observational [`execution_relay::RelayOutcome`] is mapped to
//!    [`agent_backend::MarketExecutionOutcome`]. A `Filled` is produced **only**
//!    when the relay observed exact realized amounts (`Confirmed { fill: Some }`);
//!    a confirmation without amounts is `Unknown`, never a fabricated fill.
//!
//! # Boundaries
//! - **No I/O, clock, or logging.** Every instant is the explicit `now_ms`; the
//!   only capabilities that can reach a signer or a chain live behind the relay's
//!   injected seams.
//! - **Fail closed.** `TRADING_ENABLED=false` denies before signing; a missing
//!   chain adapter (production wiring) is `Unavailable`. Both retryable and final
//!   revalidation aborts deny, so no sign/submit occurs.
//! - **Redaction.** [`MarketExecutionTrust`] and [`RelayMarketExecutionPort`]
//!   render nothing user-facing; errors carry no assets, amounts, routes, or ids.
//! - `#![forbid(unsafe_code)]`; no `unwrap`/`expect`/`panic` in production code.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use agent_backend::{
    MarketExecutionError, MarketExecutionOutcome, MarketExecutionPort, MarketExecutionRequest,
};
use async_trait::async_trait;
use domain::{cmp_u128_products, mul_u128_wide, RoutePlan, TaxObservation, TradeIntent};
use execution_preview::{
    revalidate_pre_sign, AllowanceObservation, RevalidationInput, RevalidationOutcome,
    RouteBinding, WalletBalance,
};
use execution_relay::{
    AttemptReservationStore, ChainHealthBreaker, ChainSubmissionAdapter, ExecutionRelay,
    PrivySigningBoundaryAdapter, RelayError, RelayExecutionInput, RelayOutcome,
    SignedPayloadSource, SigningBoundary, UnavailableChainAdapter,
};
use market_types::{AssetAmount, AtomicAmount, FreshnessPolicy};
use policy::{PolicyContext, PolicyEngine};
use privy::PreparedExecutionRef;
use tax_engine::evaluate_tax_safety;

/// Trusted pre-sign state for one market execution.
///
/// Every field must be sourced from authoritative backend state, never from a
/// Web/MCP/Telegram request payload. `Debug` is redacted: no balances, amounts,
/// assets, allowances, program refs, or policy valuation are rendered.
#[derive(Clone)]
pub struct MarketExecutionTrust {
    /// Policy valuation/turnover/venue facts, built at the request's `now_ms`.
    pub policy_context: PolicyContext,
    /// Wallet balance for the request's input asset.
    pub wallet_balance: WalletBalance,
    /// Allowance observation, when the route requires one.
    pub allowance: AllowanceObservation,
    /// Fresh tax observation used to re-derive the tax assessment.
    pub tax_observation: TaxObservation,
    /// Allowlisted Solana programs / pools.
    pub allowed_programs: HashSet<String>,
    /// Caller freshness policy for route/wallet/tax state.
    pub freshness_policy: FreshnessPolicy,
}

impl fmt::Debug for MarketExecutionTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Payload-free: valuation, balances, allowances, and observations are
        // never rendered.
        formatter
            .debug_struct("MarketExecutionTrust")
            .finish_non_exhaustive()
    }
}

/// Injected source of trusted pre-sign state.
///
/// Implementations own the trusted backend reads (wallet/allowance/tax/policy).
/// They must never derive any field from the request payload; the request is
/// consulted only for identity (owner, wallet, chain, pair, side).
pub trait MarketExecutionTrustSource: Send + Sync {
    /// Loads the trusted pre-sign state for `request`.
    fn trust(
        &self,
        request: &MarketExecutionRequest,
    ) -> Result<MarketExecutionTrust, MarketExecutionError>;
}

/// Injected source of the opaque prepared-execution reference.
///
/// The relay binds this reference into the signing request; the transaction
/// builder owns the real reference. A source that cannot produce a
/// non-empty reference fails closed rather than fabricate one.
pub trait PreparedExecutionRefSource: Send + Sync {
    /// Builds the prepared reference bound to `intent`.
    fn prepared_ref(
        &self,
        intent: &TradeIntent,
    ) -> Result<PreparedExecutionRef, MarketExecutionError>;
}

/// Concrete [`MarketExecutionPort`] over the execution relay.
///
/// It holds the relay (the only sign/submit capability) plus the injected trust
/// and prepared-reference seams. `Debug` is redacted: the relay's configuration,
/// the seams, and every payload-derived value are never rendered.
pub struct RelayMarketExecutionPort<S, A, P, G, T, R>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    relay: ExecutionRelay<S, A, P, G>,
    trust: T,
    prepared_refs: R,
}

impl<S, A, P, G, T, R> RelayMarketExecutionPort<S, A, P, G, T, R>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    /// Wires the port from a relay and the two trust seams.
    pub fn new(relay: ExecutionRelay<S, A, P, G>, trust: T, prepared_refs: R) -> Self {
        Self {
            relay,
            trust,
            prepared_refs,
        }
    }
}

impl<S, P, T, R>
    RelayMarketExecutionPort<S, UnavailableChainAdapter, P, PrivySigningBoundaryAdapter, T, R>
where
    S: AttemptReservationStore,
    P: SignedPayloadSource,
{
    /// **Production entry point**: [`ExecutionRelay::production`]
    /// (`UnavailableChainAdapter` + `PrivySigningBoundaryAdapter`).
    ///
    /// No network, key material, or live signing exists on this path until a
    /// real chain adapter and Privy transport are installed under review: the
    /// adapter reports `Unavailable`, so every `execute` fails closed before a
    /// reservation is claimed.
    pub fn production(
        policy: PolicyEngine,
        store: S,
        payload_source: P,
        breaker: ChainHealthBreaker,
        trust: T,
        prepared_refs: R,
    ) -> Self {
        Self::new(
            ExecutionRelay::production(policy, store, payload_source, breaker),
            trust,
            prepared_refs,
        )
    }
}

impl<S, A, P, G, T, R> fmt::Debug for RelayMarketExecutionPort<S, A, P, G, T, R>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the relay's injected components, the trust seams, or any
        // payload-derived value.
        formatter
            .debug_struct("RelayMarketExecutionPort")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S, A, P, G, T, R> MarketExecutionPort for RelayMarketExecutionPort<S, A, P, G, T, R>
where
    S: AttemptReservationStore,
    A: ChainSubmissionAdapter,
    P: SignedPayloadSource,
    G: SigningBoundary,
    T: MarketExecutionTrustSource,
    R: PreparedExecutionRefSource,
{
    async fn execute(
        &self,
        request: MarketExecutionRequest,
    ) -> Result<MarketExecutionOutcome, MarketExecutionError> {
        let trust = self.trust.trust(&request)?;

        // Authority is checked on the *same* engine that gates the relay, so the
        // kill switch and limits cannot drift between the two.
        let policy = self.relay.policy();
        let approved = policy
            .authorize_trade(&request.intent, &trust.policy_context)
            .map_err(|_| MarketExecutionError::Denied)?;

        let min_out = market_min_out(&request.intent, &request.quote.plan)?;

        // Basis assessment is re-derived from the port's own trusted observation
        // and reused as the revalidation basis; the gate then requires the
        // quote's realized tax cost to equal the fresh assessment exactly, so a
        // drifted quote cannot pass.
        let basis = evaluate_tax_safety(
            &request.intent,
            Some(&trust.tax_observation),
            request.now_ms,
            &trust.freshness_policy,
        )
        .map_err(|_| MarketExecutionError::Denied)?;

        let route_binding = RouteBinding::from_route(&request.quote.plan);
        let preview = match revalidate_pre_sign(&RevalidationInput {
            intent: &request.intent,
            approval: Some(&approved),
            policy_limits: policy.limits(),
            allowed_programs: &trust.allowed_programs,
            trading_enabled: policy.is_trading_enabled(),
            now_ms: request.now_ms,
            freshness_policy: &trust.freshness_policy,
            route: &request.quote.plan,
            net_delta: &request.quote.net_delta,
            basis_assessment: &basis,
            tax_observation: Some(&trust.tax_observation),
            approved_route_binding: &route_binding,
            min_out: &min_out,
            wallet_balance: &trust.wallet_balance,
            allowance: &trust.allowance,
        }) {
            RevalidationOutcome::Valid(preview) => preview,
            // Both retryable and final aborts deny: no sign/submit occurs.
            RevalidationOutcome::AbortRequote(_) | RevalidationOutcome::AbortFinal(_) => {
                return Err(MarketExecutionError::Denied)
            }
        };

        let prepared = self.prepared_refs.prepared_ref(&request.intent)?;
        let input = RelayExecutionInput {
            intent: &request.intent,
            policy_context: &trust.policy_context,
            prepared: &prepared,
            approved: &approved,
            route: &request.quote.plan,
            preview: &preview,
            now_ms: request.now_ms,
        };
        map_outcome(self.relay.execute(input).await)
    }
}

/// Exact minimum-output floor for the request's slippage cap.
///
/// `min_out = max(1, ceil(route.expected_net_output.amount * (10_000 - max_slippage) / 10_000))`,
/// denominated in `intent.token_out`. The multiplication uses the exact 256-bit
/// helpers; any overflow fails closed as [`MarketExecutionError::Denied`].
fn market_min_out(
    intent: &TradeIntent,
    route: &RoutePlan,
) -> Result<AssetAmount, MarketExecutionError> {
    let expected = route.expected_net_output.amount.get();
    let slippage_floor_bps = 10_000u128.saturating_sub(u128::from(intent.risk.max_slippage.get()));
    let floor = checked_ceil_mul_div(expected, slippage_floor_bps, 10_000)?.max(1);
    Ok(AssetAmount {
        asset: intent.token_out.clone(),
        amount: AtomicAmount::new(floor),
    })
}

/// `ceil(a * b / d)` with a 256-bit product and checked arithmetic.
fn checked_ceil_mul_div(a: u128, b: u128, d: u128) -> Result<u128, MarketExecutionError> {
    if d == 0 {
        return Err(MarketExecutionError::Denied);
    }
    let (hi, lo) = mul_u128_wide(a, b);
    let quotient =
        simulation::div_u256_by_u128_floor(hi, lo, d).ok_or(MarketExecutionError::Denied)?;
    if cmp_u128_products(quotient, d, a, b) == Ordering::Less {
        quotient.checked_add(1).ok_or(MarketExecutionError::Denied)
    } else {
        Ok(quotient)
    }
}

/// Maps the observational relay result to the backend execution outcome.
///
/// A `Filled` is produced only when the relay observed exact realized amounts;
/// a confirmation without amounts is `Unknown` (never a fabricated fill).
/// Definitive pre-send failures are `Failed`; ambiguous transport errors are
/// `Unknown` so a caller never blindly retries a possibly-sent attempt. The
/// definitive/ambiguous error split mirrors the P57 limit-engine executor; the
/// P72 taxonomy additionally maps `TradingDisabled` to `Denied` and
/// `ChainHealthUnavailable` to `Unavailable` (a transient gate, not a trade
/// decision), and reports an in-flight `Submitted` for the observational
/// journal states.
fn map_outcome(
    result: Result<RelayOutcome, RelayError>,
) -> Result<MarketExecutionOutcome, MarketExecutionError> {
    match result {
        Ok(RelayOutcome::Confirmed { fill: Some(f), .. }) => Ok(MarketExecutionOutcome::Filled {
            net_input: f.net_input,
            net_output: f.net_output,
        }),
        Ok(RelayOutcome::Confirmed { fill: None, .. }) => Ok(MarketExecutionOutcome::Unknown),
        Ok(RelayOutcome::Submitted { .. })
        | Ok(RelayOutcome::Reserved)
        | Ok(RelayOutcome::Signed)
        | Ok(RelayOutcome::Prepared) => Ok(MarketExecutionOutcome::Submitted),
        Ok(RelayOutcome::Unknown) => Ok(MarketExecutionOutcome::Unknown),
        Ok(RelayOutcome::Rejected { .. }) | Ok(RelayOutcome::FailedBeforeSubmit) => {
            Ok(MarketExecutionOutcome::Failed)
        }
        // Policy / kill switch.
        Err(RelayError::TradingDisabled) => Err(MarketExecutionError::Denied),
        // Chain health is a transient gate, not a trade decision.
        Err(RelayError::ChainHealthUnavailable) => Err(MarketExecutionError::Unavailable),
        // Definitive pre-send: the relay provably did not reach submit.
        Err(RelayError::SigningFailed)
        | Err(RelayError::SigningRequestMismatch)
        | Err(RelayError::ChainMismatch)
        | Err(RelayError::MissingSignedPayload)
        | Err(RelayError::SignedPayloadEmpty)
        | Err(RelayError::SignedPayloadTooLarge)
        | Err(RelayError::SignedPayloadDigestMismatch)
        | Err(RelayError::ReservationUnavailable)
        | Err(RelayError::StoreUnavailable)
        | Err(RelayError::IdempotencyConflict) => Ok(MarketExecutionOutcome::Failed),
        // Ambiguous: bytes may have been sent; never retry.
        Err(RelayError::AdapterUnavailable)
        | Err(RelayError::AdapterTimeout)
        | Err(RelayError::AdapterRejected)
        | Err(RelayError::UnknownSubmissionState)
        | Err(RelayError::InvalidTransition) => Ok(MarketExecutionOutcome::Unknown),
    }
}
