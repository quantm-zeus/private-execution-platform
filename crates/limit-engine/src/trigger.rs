//! P45 — Phase 5 L2: pure limit trigger and maximum-safe-fill search.
//!
//! This module extends the P44 `limit-engine` state machine with the pure,
//! deterministic trigger decision. It owns no clock, no RNG, no I/O, no
//! persistence, no signing, and no floats: every input is explicit, and quotes
//! arrive through an injected [`QuoteProvider`].
//!
//! # The only price that may trigger
//! The trigger decides *exclusively* from the exact simulated **net** economics
//! of the candidate route, obtained through the P38 bridge
//! ([`validate_delta_preview_with_assessment`]) and read with
//! [`domain::ValidatedExecutionPreview`]'s `satisfies_limit_price` method.
//! Gross/chart price is never an input to the API and is never consulted;
//! [`domain::ExecutionPreview::gross_quote_price`] is deliberately unused.
//!
//! # Safety over completeness
//! [`max_safe_fill`] never returns a chunk whose exact net economics fail the
//! order's limit (`INVARIANTS.md` #3). The bisection is bounded by
//! [`MAX_SEARCH_STEPS`] and is followed by a bounded, deterministic confirmation
//! ladder ([`MAX_FALLBACK_STEPS`]) that can only move the chunk *down*, never
//! below `min_fill`. A partial chunk always leaves a viable remainder
//! (`remaining - chunk >= min_fill`) or is the full remainder.
//!
//! # Adaptations forced by the real APIs
//! The P45 sketch is authoritative for the semantics; the landed APIs force
//! these shape changes:
//!
//! 1. [`validate_delta_preview_with_assessment`] does not accept a
//!    `FreshnessPolicy` (it hard-codes [`FreshnessPolicy::default`] for the
//!    route). The caller-supplied policy is therefore applied by this module as
//!    an explicit pre-gate on the frozen route snapshot before the bridge runs;
//!    the bridge's own default-policy gate still applies underneath, so the
//!    combined check is never weaker than either.
//! 2. A bridge rejection (`BridgeError`) is classified as *non-executable*
//!    (`Ok(false)`), never propagated. Every [`TriggerDecision::NotExecutable`]
//!    case — quote unavailable, net limit not met, stale route, mismatched
//!    assessment — stays inside the redacted engine contract and no
//!    `BridgeError` type escapes the crate. Only genuine FSM failures from
//!    [`apply_transition`] surface as [`LimitEngineError`].
//! 3. The provider builds the per-attempt [`domain::TradeIntent`] it quotes (the
//!    trait signature receives the order, amount, and `now_ms`, and returns the
//!    intent in [`QuotedAttempt`]). [`attempt_is_executable`] verifies that the
//!    returned intent is bound to the order, the exact probe amount, the order's
//!    limit, and the order's pair before trusting it, so a provider cannot
//!    redirect the trigger.
//! 4. The spec's step-5 "cap to `remaining - min_fill`" can leave a chunk whose
//!    immediate successor is still executable. The guarantee preserved here is
//!    the stronger one: the returned chunk is the largest executable chunk that
//!    also leaves a viable remainder, or the full remainder.

use domain::{AmountType, OrderStatus, OrderType, RoutePlan, TradeIntent};
use execution_preview::{validate_delta_preview_with_assessment, NetDelta};
use market_types::{evaluate_freshness, AtomicAmount, FreshnessPolicy, FreshnessStatus};
use tax_engine::TaxAssessment;

use crate::error::LimitEngineError;
use crate::fsm::{apply_transition, is_terminal};
use crate::order::StoredLimitOrder;

/// Upper bound on bisection probes per [`max_safe_fill`] call.
///
/// The search interval is a `u128` range, so 128 halvings always resolve it.
pub const MAX_SEARCH_STEPS: u32 = 128;

/// Upper bound on the safety-confirmation fallback ladder.
pub const MAX_FALLBACK_STEPS: u32 = 128;

/// The result of asking a [`QuoteProvider`] to price one candidate chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuoteOutcome {
    /// A complete, self-consistent quote for the requested chunk.
    Quoted(Box<QuotedAttempt>),
    /// The provider could not produce a quote. Redacted: no reason leaks.
    Unavailable,
}

/// A quoted attempt: everything the bridge and the limit check need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotedAttempt {
    /// Per-attempt intent the quote was produced for.
    pub intent: TradeIntent,
    /// Simulated route bound to `intent`.
    pub route: RoutePlan,
    /// Exact normalized net balance delta for `intent`.
    pub net_delta: NetDelta,
    /// Tax assessment that explains `net_delta`.
    pub assessment: TaxAssessment,
}

/// Injected, deterministic quote source.
///
/// Implementations must be pure with respect to `(order, amount_in, now_ms)`:
/// the same triple must yield the same outcome. They must not read a wall clock,
/// perform I/O, or consult the chart/gross price for the limit decision.
pub trait QuoteProvider: Send + Sync {
    /// Prices `amount_in` for `order` at the explicit `now_ms`.
    fn quote(&self, order: &StoredLimitOrder, amount_in: AtomicAmount, now_ms: i64)
        -> QuoteOutcome;
}

/// The trigger verdict for one evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerDecision {
    /// No market signal: stay `Active` and do nothing.
    NoSignal,
    /// A signal exists but no safe, limit-satisfying fill is available now.
    NotExecutable,
    /// The exact maximum safe chunk to attempt (`<= remaining_input`).
    Fill(AtomicAmount),
}

/// Post-state order plus the trigger verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerOutcome {
    /// Post-transition order; the caller persists it through the P44 store.
    pub order: StoredLimitOrder,
    /// The verdict that produced the post-state.
    pub decision: TriggerDecision,
}

/// Reports whether the exact simulated net economics of `amount_in` satisfy the
/// order's limit.
///
/// Returns `Ok(false)` for every non-executable condition (including a missing
/// quote and any bridge rejection); a provider or quote can never make this
/// function panic.
pub fn attempt_is_executable(
    order: &StoredLimitOrder,
    amount_in: AtomicAmount,
    provider: &dyn QuoteProvider,
    now_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<bool, LimitEngineError> {
    // The probe may never exceed the order's remaining spendable input.
    if amount_in.is_zero() || amount_in > order.order.remaining_input {
        return Ok(false);
    }

    let attempt = match provider.quote(order, amount_in, now_ms) {
        QuoteOutcome::Unavailable => return Ok(false),
        QuoteOutcome::Quoted(attempt) => attempt,
    };

    if !quote_binds_to_order(order, &attempt, amount_in) {
        return Ok(false);
    }

    if !route_is_fresh(&attempt.route, now_ms, freshness_policy) {
        return Ok(false);
    }

    let preview = match validate_delta_preview_with_assessment(
        &attempt.intent,
        &attempt.route,
        &attempt.net_delta,
        &attempt.assessment,
        now_ms,
    ) {
        Ok(preview) => preview,
        Err(_) => return Ok(false),
    };

    // The decisive check: exact simulated net economics. `satisfies_limit_price`
    // cannot consult the gross quote, and it is re-run against the *order's*
    // limit so a provider cannot substitute a weaker one.
    Ok(matches!(
        preview.satisfies_limit_price(&order.order.limit_price),
        Ok(true)
    ))
}

/// Finds the largest chunk `c` in `[min_fill, remaining_input]` whose exact net
/// economics satisfy the order's limit and which leaves a viable remainder.
///
/// Returns `Ok(None)` when nothing safe is available right now. The search is
/// integer-only, bounded, and deterministic; identical inputs always produce the
/// same chunk.
pub fn max_safe_fill(
    order: &StoredLimitOrder,
    provider: &dyn QuoteProvider,
    now_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<Option<AtomicAmount>, LimitEngineError> {
    let remaining = order.order.remaining_input;
    let min_fill = order.order.min_fill;
    if min_fill.is_zero() || min_fill > remaining {
        return Ok(None);
    }

    // Step 1: all-or-nothing orders can only fill the full remainder.
    if !order.order.allow_partial_fill {
        return if attempt_is_executable(order, remaining, provider, now_ms, freshness_policy)? {
            Ok(Some(remaining))
        } else {
            Ok(None)
        };
    }

    // Step 2: full fill short-circuit.
    if attempt_is_executable(order, remaining, provider, now_ms, freshness_policy)? {
        return Ok(Some(remaining));
    }

    // Step 3: nothing safe at the minimum means nothing safe at all.
    if !attempt_is_executable(order, min_fill, provider, now_ms, freshness_policy)? {
        return Ok(None);
    }

    // Step 4: bisection with the invariant `probe(lo) == true`, `probe(hi) ==
    // false`. At most `MAX_SEARCH_STEPS` halvings resolve any `u128` interval.
    let mut lo = min_fill.get();
    let mut hi = remaining.get();
    let mut steps = 0u32;
    while hi - lo > 1 && steps < MAX_SEARCH_STEPS {
        let mid = lo + (hi - lo) / 2;
        if attempt_is_executable(
            order,
            AtomicAmount::new(mid),
            provider,
            now_ms,
            freshness_policy,
        )? {
            lo = mid;
        } else {
            hi = mid;
        }
        steps += 1;
    }

    finalize_candidate(
        order,
        AtomicAmount::new(lo),
        provider,
        now_ms,
        freshness_policy,
    )
}

/// Enforces remainder viability, then re-confirms safety with a bounded ladder.
fn finalize_candidate(
    order: &StoredLimitOrder,
    candidate: AtomicAmount,
    provider: &dyn QuoteProvider,
    now_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<Option<AtomicAmount>, LimitEngineError> {
    let remaining = order.order.remaining_input.get();
    let min_fill = order.order.min_fill.get();
    let mut chunk = candidate.get();

    // Step 6: bounded, deterministic safety confirmation. A chunk that cannot be
    // re-confirmed is halved (never below `min_fill`) until it is, or the search
    // fails closed. This is what guarantees INVARIANTS #3.
    let mut fallback_steps = 0u32;
    while !attempt_is_executable(
        order,
        AtomicAmount::new(chunk),
        provider,
        now_ms,
        freshness_policy,
    )? {
        if fallback_steps >= MAX_FALLBACK_STEPS || chunk < min_fill {
            return Ok(None);
        }
        chunk /= 2;
        fallback_steps += 1;
        if chunk < min_fill {
            return Ok(None);
        }
    }

    // Step 5: a partial chunk must leave a viable remainder.
    if chunk != remaining {
        let Some(leftover) = remaining.checked_sub(chunk) else {
            return Ok(None);
        };
        if leftover < min_fill {
            // Prefer completing the order when the full remainder is safe.
            if attempt_is_executable(
                order,
                AtomicAmount::new(remaining),
                provider,
                now_ms,
                freshness_policy,
            )? {
                return Ok(Some(AtomicAmount::new(remaining)));
            }
            // Otherwise cap so the remainder is exactly fillable; re-confirm.
            let Some(capped) = remaining.checked_sub(min_fill) else {
                return Ok(None);
            };
            if capped < min_fill
                || !attempt_is_executable(
                    order,
                    AtomicAmount::new(capped),
                    provider,
                    now_ms,
                    freshness_policy,
                )?
            {
                return Ok(None);
            }
            return Ok(Some(AtomicAmount::new(capped)));
        }
    }

    Ok(Some(AtomicAmount::new(chunk)))
}

/// Evaluates a trigger signal against a stored order.
///
/// Order of decisions:
/// 1. A non-terminal order at/after its deadline becomes `Expired` and is not
///    executable (a signal after expiry therefore never fills).
/// 2. A terminal order is returned unchanged as non-executable.
/// 3. No signal leaves the order unchanged ([`TriggerDecision::NoSignal`]).
/// 4. A signal moves `-> TriggerCandidate`; if no safe fill exists the order is
///    reverted `-> Active` with [`TriggerDecision::NotExecutable`], otherwise the
///    post-state is `TriggerCandidate` with the exact safe chunk.
pub fn evaluate_trigger(
    order: &StoredLimitOrder,
    signal: bool,
    provider: &dyn QuoteProvider,
    now_ms: i64,
    freshness_policy: &FreshnessPolicy,
) -> Result<TriggerOutcome, LimitEngineError> {
    let status = order.order.status;

    if !is_terminal(status) && now_ms >= order.order.expires_at_ms {
        let expired = apply_transition(order, OrderStatus::Expired, None, now_ms)?;
        return Ok(TriggerOutcome {
            order: expired,
            decision: TriggerDecision::NotExecutable,
        });
    }

    if is_terminal(status) {
        return Ok(TriggerOutcome {
            order: order.clone(),
            decision: TriggerDecision::NotExecutable,
        });
    }

    if !signal {
        return Ok(TriggerOutcome {
            order: order.clone(),
            decision: TriggerDecision::NoSignal,
        });
    }

    let candidate = apply_transition(order, OrderStatus::TriggerCandidate, None, now_ms)?;
    match max_safe_fill(order, provider, now_ms, freshness_policy)? {
        Some(chunk) => Ok(TriggerOutcome {
            order: candidate,
            decision: TriggerDecision::Fill(chunk),
        }),
        None => {
            let reverted = apply_transition(&candidate, OrderStatus::Active, None, now_ms)?;
            Ok(TriggerOutcome {
                order: reverted,
                decision: TriggerDecision::NotExecutable,
            })
        }
    }
}

/// Verifies the quoted intent is bound to the order, probe amount, and limit.
///
/// The provider constructs the intent, so every order-level policy the trigger
/// must honor is re-bound here: the risk caps (a provider must not quote under
/// laxer tax limits), the partial-fill policy, the deadline, the owner/wallet,
/// and the per-attempt nonce (`order.nonce + order.attempt_seq`).
fn quote_binds_to_order(
    order: &StoredLimitOrder,
    attempt: &QuotedAttempt,
    amount_in: AtomicAmount,
) -> bool {
    let intent = &attempt.intent;
    let Some(expected_nonce) = order.nonce.checked_add(order.attempt_seq) else {
        return false;
    };
    intent.amount == amount_in
        && intent.amount_type == AmountType::InputAssetAtomic
        && intent.order_type == OrderType::Limit
        && intent.chain == order.order.chain
        && intent.token_in == order.order.token_in
        && intent.token_out == order.order.token_out
        && intent.side == order.order.side
        && intent.limit_price.as_ref() == Some(&order.order.limit_price)
        && intent.risk == order.order.risk
        && intent.allow_partial_fill == order.order.allow_partial_fill
        && intent.expiry_ms == Some(order.order.expires_at_ms)
        && intent.nonce == expected_nonce
        && intent.user_id == order.order.owner
        && intent.wallet_ref == order.order.wallet_ref
}

/// Applies the caller's freshness policy to the frozen route snapshot.
fn route_is_fresh(route: &RoutePlan, now_ms: i64, policy: &FreshnessPolicy) -> bool {
    matches!(
        evaluate_freshness(
            policy,
            route.state.observed_at_ms,
            now_ms,
            route.state.sequence,
            false,
        ),
        Ok(meta) if meta.status == FreshnessStatus::Fresh
    )
}
