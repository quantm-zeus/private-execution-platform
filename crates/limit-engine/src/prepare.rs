//! P50 — deterministic attempt preparation (policy -> preview -> revalidation).
//!
//! This module is the pure decision core of the Phase-5 orchestrator. Given a
//! stored limit order, the exact chunk and `QuotedAttempt` produced by the P45
//! trigger, and injected *trusted backend state*, it:
//!
//! 1. builds the fully bound per-attempt `TradeIntent` (deterministic
//!    idempotency key, intent id and nonce supplied by the caller from the P48
//!    attempt journal),
//! 2. runs the policy authorization (kill switch, turnover, size, venue, risk),
//! 3. derives the exact `min_out` floor from the order's net limit and the
//!    intent's slippage cap, and
//! 4. runs the locked pre-sign revalidation gate
//!    ([`execution_preview::revalidate_pre_sign`]), which internally re-runs the
//!    P38 net-delta bridge and the locked domain validation.
//!
//! It performs no I/O, no signing, no submission, and reads no clock; every
//! instant is explicit. Nothing here mutates the order: the caller persists the
//! binding and attempt journal after this function returns `Ready`.

use std::cmp::Ordering;
use std::collections::HashSet;

use domain::{
    cmp_u128_products, mul_u128_wide, AmountType, IdempotencyKey, IntentId, OrderType, RoutePlan,
    TaxObservation, TradeIntent, TradeSide, TradeSource, ValidatedExecutionPreview,
};
use execution_preview::{
    revalidate_pre_sign, AllowanceObservation, NetDelta, RevalidationInput, RevalidationOutcome,
    RevalidationReason, RouteBinding, WalletBalance,
};
use market_types::{AssetAmount, AtomicAmount, FreshnessPolicy};
use policy::{ApprovedExecution, PolicyContext, PolicyEngine};

use crate::error::LimitEngineError;
use crate::order::StoredLimitOrder;
use crate::trigger::QuotedAttempt;

/// Trusted backend facts required to prepare an attempt.
///
/// Every field must be sourced from authoritative backend state, never from a
/// Web/MCP/Telegram request payload. `allowance` may be `NotRequired`.
pub struct AttemptTrust {
    /// Policy valuation/turnover/venue facts.
    pub policy_context: PolicyContext,
    /// Wallet balance for the order's input asset.
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

/// Inputs for one attempt preparation.
pub struct PrepareAttemptInput<'a> {
    /// Stored order the attempt belongs to.
    pub order: &'a StoredLimitOrder,
    /// Trade source for the attempt intent.
    pub source: TradeSource,
    /// Attempt sequence (the journal's latest + 1; 1-based).
    pub attempt_seq: u64,
    /// Deterministic per-attempt intent id.
    pub attempt_intent_id: IntentId,
    /// Deterministic per-attempt idempotency key.
    pub attempt_key: IdempotencyKey,
    /// Exact chunk to attempt (`>= min_fill`, `<= remaining_input`).
    pub chunk: AtomicAmount,
    /// Exact quote produced by the P45 trigger for `chunk`.
    pub quoted: &'a QuotedAttempt,
    /// Trusted backend state.
    pub trust: &'a AttemptTrust,
    /// Explicit caller-supplied time.
    pub now_ms: i64,
}

/// A fully prepared, pre-sign attempt.
pub struct PreparedAttempt {
    /// Bound per-attempt intent.
    pub intent: TradeIntent,
    /// Simulated route bound to `intent`.
    pub route: RoutePlan,
    /// Exact simulated net balance delta.
    pub net_delta: NetDelta,
    /// Validated execution preview (only reachable via the locked gate).
    pub preview: ValidatedExecutionPreview,
    /// Policy approval bound to `intent`.
    pub approval: ApprovedExecution,
    /// Minimum acceptable net output for `intent`.
    pub min_out: AssetAmount,
}

impl std::fmt::Debug for PreparedAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedAttempt")
            .field("attempt_seq", &self.intent.nonce)
            .finish_non_exhaustive()
    }
}

/// Result of a preparation attempt.
#[derive(Debug)]
pub enum PreparedAttemptOutcome {
    /// The attempt is fully bound and may be persisted and signed.
    Ready(Box<PreparedAttempt>),
    /// A soft, retryable condition: requote and try again later.
    Requote(RevalidationReason),
    /// A final condition: the order must not be signed.
    Abort(RevalidationReason),
}

/// Builds and validates one attempt.
///
/// Returns:
/// - [`PreparedAttemptOutcome::Ready`] when policy, the exact net economics, the
///   derived `min_out`, and the locked revalidation gate all pass;
/// - [`PreparedAttemptOutcome::Requote`] for a soft `AbortRequote` reason;
/// - [`PreparedAttemptOutcome::Abort`] for a final `AbortFinal` reason;
/// - `Err(LimitEngineError::InvalidOrder)` for a chunk outside
///   `[min_fill, remaining_input]` or an internally inconsistent order;
/// - `Err(LimitEngineError::PolicyRejected)` when policy refuses the attempt.
pub fn prepare_attempt(
    input: &PrepareAttemptInput<'_>,
    policy: &PolicyEngine,
) -> Result<PreparedAttemptOutcome, LimitEngineError> {
    let order = &input.order.order;
    if input.chunk.is_zero() || input.chunk < order.min_fill {
        return Err(LimitEngineError::AmountBelowMinFill);
    }
    if input.chunk > order.remaining_input {
        return Err(LimitEngineError::RemainingUnderflow);
    }
    if input.attempt_seq == 0 {
        return Err(LimitEngineError::InvalidOrder);
    }

    let nonce = input
        .order
        .nonce
        .checked_add(input.attempt_seq)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    let intent = TradeIntent {
        id: input.attempt_intent_id.clone(),
        source: input.source,
        user_id: order.owner.clone(),
        wallet_ref: order.wallet_ref.clone(),
        chain: order.chain.clone(),
        token_in: order.token_in.clone(),
        token_out: order.token_out.clone(),
        side: order.side,
        amount_type: AmountType::InputAssetAtomic,
        amount: input.chunk,
        order_type: OrderType::Limit,
        limit_price: Some(order.limit_price.clone()),
        risk: order.risk.clone(),
        allow_partial_fill: order.allow_partial_fill,
        expiry_ms: Some(order.expires_at_ms),
        nonce,
        idempotency_key: input.attempt_key.clone(),
    };
    intent
        .validate(input.now_ms)
        .map_err(|_| LimitEngineError::InvalidOrder)?;

    let approval = policy
        .authorize_trade(&intent, &input.trust.policy_context)
        .map_err(|_| LimitEngineError::PolicyRejected)?;

    if input.quoted.net_delta.token_in != intent.token_in
        || input.quoted.net_delta.token_out != intent.token_out
    {
        return Err(LimitEngineError::IntegrityViolation);
    }

    let min_out = compute_min_out(&intent, &input.quoted.route, &input.quoted.net_delta)?;
    let approved_route_binding = RouteBinding::from_route(&input.quoted.route);

    let outcome = revalidate_pre_sign(&RevalidationInput {
        intent: &intent,
        approval: Some(&approval),
        policy_limits: policy.limits(),
        allowed_programs: &input.trust.allowed_programs,
        trading_enabled: policy.is_trading_enabled(),
        now_ms: input.now_ms,
        freshness_policy: &input.trust.freshness_policy,
        route: &input.quoted.route,
        net_delta: &input.quoted.net_delta,
        basis_assessment: &input.quoted.assessment,
        tax_observation: Some(&input.trust.tax_observation),
        approved_route_binding: &approved_route_binding,
        min_out: &min_out,
        wallet_balance: &input.trust.wallet_balance,
        allowance: &input.trust.allowance,
    });

    Ok(match outcome {
        RevalidationOutcome::Valid(preview) => {
            PreparedAttemptOutcome::Ready(Box::new(PreparedAttempt {
                intent,
                route: input.quoted.route.clone(),
                net_delta: input.quoted.net_delta.clone(),
                preview,
                approval,
                min_out,
            }))
        }
        RevalidationOutcome::AbortRequote(reason) => PreparedAttemptOutcome::Requote(reason),
        RevalidationOutcome::AbortFinal(reason) => PreparedAttemptOutcome::Abort(reason),
    })
}

/// Exact `min_out` floor satisfying both the net limit and the slippage cap.
///
/// BUY: `net_out >= ceil(net_in * limit_den / limit_num)`.
/// SELL: `net_out >= ceil(net_in * limit_num / limit_den)`.
/// Slippage: `net_out >= ceil(expected_net_output * (10_000 - max_slippage) / 10_000)`.
/// The floor is the maximum of the two (and at least one), which is what the
/// revalidation gate's step-9 checks accept.
fn compute_min_out(
    intent: &TradeIntent,
    route: &RoutePlan,
    net_delta: &NetDelta,
) -> Result<AssetAmount, LimitEngineError> {
    let limit = intent
        .limit_price
        .as_ref()
        .ok_or(LimitEngineError::InvalidOrder)?;
    let net_in = net_delta.net_input.amount.get();
    let (num, den) = (
        limit.ratio.numerator_atomic(),
        limit.ratio.denominator_atomic(),
    );
    let limit_floor = match intent.side {
        TradeSide::Buy => checked_ceil_mul_div(net_in, den, num)?,
        TradeSide::Sell => checked_ceil_mul_div(net_in, num, den)?,
    };
    let expected = route.expected_net_output.amount.get();
    let slip_bps = 10_000u128.saturating_sub(u128::from(intent.risk.max_slippage.get()));
    let slip_floor = checked_ceil_mul_div(expected, slip_bps, 10_000)?;
    let floor = limit_floor.max(slip_floor).max(1);
    Ok(AssetAmount {
        asset: intent.token_out.clone(),
        amount: AtomicAmount::new(floor),
    })
}

/// `ceil(a * b / d)` with a 256-bit product and checked arithmetic.
fn checked_ceil_mul_div(a: u128, b: u128, d: u128) -> Result<u128, LimitEngineError> {
    if d == 0 {
        return Err(LimitEngineError::ArithmeticOverflow);
    }
    let (hi, lo) = mul_u128_wide(a, b);
    let quotient = simulation::div_u256_by_u128_floor(hi, lo, d)
        .ok_or(LimitEngineError::ArithmeticOverflow)?;
    if cmp_u128_products(quotient, d, a, b) == Ordering::Less {
        quotient
            .checked_add(1)
            .ok_or(LimitEngineError::ArithmeticOverflow)
    } else {
        Ok(quotient)
    }
}
