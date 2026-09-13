//! P45 L2 integration tests: pure limit trigger and maximum-safe-fill search.
//!
//! The synthetic providers below never touch a clock, RNG, float, or I/O. Every
//! quote is a deterministic function of the probe amount and the injected
//! `now_ms`, which is exactly the contract the trigger path requires.

mod support;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use domain::{
    AmountType, IdempotencyKey, IntentId, OrderStatus, OrderType, RouteLeg, RoutePlan, TradeIntent,
    TradeSource,
};
use execution_preview::NetDelta;
use limit_engine::{
    apply_transition, attempt_is_executable, conservation_holds, evaluate_trigger, max_safe_fill,
    FillDelta, QuoteOutcome, QuoteProvider, QuotedAttempt, StoredLimitOrder, TriggerDecision,
    MAX_FALLBACK_STEPS, MAX_SEARCH_STEPS,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use tax_engine::TaxAssessment;

const NOW_MS: i64 = 1_000;

/// A valid buy-side order with explicit fill policy and limit ratio.
fn order_with(
    id: &str,
    status: OrderStatus,
    max: u128,
    remaining: u128,
    min_fill: u128,
    allow_partial: bool,
    ratio: (u128, u128),
) -> StoredLimitOrder {
    let mut stored = support::stored(id, status, max, remaining, max - remaining);
    stored.order.min_fill = AtomicAmount::new(min_fill);
    stored.order.allow_partial_fill = allow_partial;
    stored.order.limit_price.ratio = PriceRatio::new(ratio.0, ratio.1).expect("valid ratio");
    stored
}

/// The synthetic economics a provider reports for one probe.
#[derive(Clone, Copy)]
struct QuotePlan {
    net_output: u128,
    gross_output: u128,
    tax: Option<u128>,
    buy_tax_bps: u16,
}

/// A deterministic, injected quote provider built from an amount -> plan map.
struct ModelProvider {
    plan: Box<dyn Fn(u128) -> Option<QuotePlan> + Send + Sync>,
    calls: AtomicU64,
}

impl ModelProvider {
    fn new(plan: impl Fn(u128) -> Option<QuotePlan> + Send + Sync + 'static) -> Self {
        Self {
            plan: Box::new(plan),
            calls: AtomicU64::new(0),
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl QuoteProvider for ModelProvider {
    fn quote(
        &self,
        order: &StoredLimitOrder,
        amount_in: AtomicAmount,
        now_ms: i64,
    ) -> QuoteOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match (self.plan)(amount_in.get()) {
            None => QuoteOutcome::Unavailable,
            Some(plan) => QuoteOutcome::Quoted(Box::new(build_attempt(
                order,
                amount_in.get(),
                plan,
                now_ms,
            ))),
        }
    }
}

/// Zero-tax provider whose net output is constant.
fn zero_tax(net_output: u128) -> ModelProvider {
    ModelProvider::new(move |_a| {
        Some(QuotePlan {
            net_output,
            gross_output: net_output,
            tax: None,
            buy_tax_bps: 0,
        })
    })
}

/// Threshold provider: with a `1/1` limit, executable iff `amount <= k`.
fn threshold_provider(k: u128) -> ModelProvider {
    ModelProvider::new(move |a| {
        let net = if a <= k { k } else { 1 };
        Some(QuotePlan {
            net_output: net,
            gross_output: net,
            tax: None,
            buy_tax_bps: 0,
        })
    })
}

/// Provider that drops its threshold after a value is re-probed, modelling
/// integer/tick non-monotonicity at the confirmation boundary.
fn fallback_provider(threshold: u128) -> ModelProvider {
    let last_true = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    ModelProvider::new(move |a| {
        if !dropped.load(Ordering::SeqCst) && a > 0 && last_true.load(Ordering::SeqCst) == a as u64
        {
            dropped.store(true, Ordering::SeqCst);
        }
        let effective = if dropped.load(Ordering::SeqCst) {
            threshold / 2
        } else {
            threshold
        };
        let net = if a <= effective { effective } else { 1 };
        if a <= effective {
            last_true.store(a as u64, Ordering::SeqCst);
        }
        Some(QuotePlan {
            net_output: net,
            gross_output: net,
            tax: None,
            buy_tax_bps: 0,
        })
    })
}

/// Builds the full quoted attempt the bridge expects.
fn build_attempt(
    order: &StoredLimitOrder,
    amount: u128,
    plan: QuotePlan,
    now_ms: i64,
) -> QuotedAttempt {
    let token_in = order.order.token_in.clone();
    let token_out = order.order.token_out.clone();
    let intent = TradeIntent {
        id: IntentId::new(format!("intent-{}", order.order.id.as_str())).expect("intent id"),
        source: TradeSource::Web,
        user_id: order.order.owner.clone(),
        wallet_ref: order.order.wallet_ref.clone(),
        chain: order.order.chain.clone(),
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        side: order.order.side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
        order_type: OrderType::Limit,
        limit_price: Some(order.order.limit_price.clone()),
        risk: order.order.risk.clone(),
        allow_partial_fill: order.order.allow_partial_fill,
        expiry_ms: Some(order.order.expires_at_ms),
        nonce: order.nonce + order.attempt_seq,
        idempotency_key: IdempotencyKey::new(format!("idem-{}", order.order.id.as_str()))
            .expect("idempotency key"),
    };
    let net_delta = NetDelta {
        token_in: token_in.clone(),
        token_out: token_out.clone(),
        net_input: AssetAmount {
            asset: token_in.clone(),
            amount: AtomicAmount::new(amount),
        },
        gross_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(plan.gross_output),
        },
        net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(plan.net_output),
        },
        dex_fee: None,
        tax_cost: plan.tax.map(|t| AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(t),
        }),
    };
    let route = RoutePlan {
        legs: vec![RouteLeg {
            venue: "synthetic".to_string(),
            pool_ref: "pool-1".to_string(),
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(amount),
            expected_amount_out: AtomicAmount::new(plan.gross_output),
        }],
        expected_net_output: AssetAmount {
            asset: token_out.clone(),
            amount: AtomicAmount::new(plan.net_output),
        },
        state: Freshness {
            observed_at_ms: now_ms,
            chain_height: 1,
            sequence: Sequence(1),
        },
    };
    let assessment = TaxAssessment::new(
        token_out,
        order.order.chain.clone(),
        Bps::new(plan.buy_tax_bps).expect("buy tax"),
        Bps::new(0).expect("sell tax"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: now_ms,
            evaluated_at_ms: now_ms,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    );
    QuotedAttempt {
        intent,
        route,
        net_delta,
        assessment,
    }
}

fn next_rand(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 33
}

#[test]
fn net_limit_boundary_uses_exact_net_price_not_gross() {
    let order = order_with(
        "boundary",
        OrderStatus::Active,
        100,
        100,
        1,
        true,
        (100, 25),
    );
    let policy = FreshnessPolicy::default();

    // Exact equality passes: net price 100/25 == 4.0.
    let exact = zero_tax(25);
    assert!(
        attempt_is_executable(&order, AtomicAmount::new(100), &exact, NOW_MS, &policy).unwrap(),
        "net price equal to the limit must pass"
    );

    // One atomic unit worse fails: net price 100/24 > 4.0.
    let worse = zero_tax(24);
    assert!(
        !attempt_is_executable(&order, AtomicAmount::new(100), &worse, NOW_MS, &policy).unwrap(),
        "net price one unit worse than the limit must fail"
    );

    // Gross/chart-like quote passes (100/25 == 4.0) while the net quote fails
    // (100/24 > 4.0): the trigger must never consider the gross price.
    let gross_passes_net_fails = ModelProvider::new(|_a| {
        Some(QuotePlan {
            net_output: 24,
            gross_output: 25,
            tax: Some(1),
            buy_tax_bps: 500,
        })
    });
    assert!(
        !attempt_is_executable(
            &order,
            AtomicAmount::new(100),
            &gross_passes_net_fails,
            NOW_MS,
            &policy
        )
        .unwrap(),
        "gross quote must never trigger when the exact net price violates the limit"
    );
}

#[test]
fn bisection_returns_exact_max_safe_chunk() {
    let order = order_with("mono", OrderStatus::Active, 1_000, 1_000, 1, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(100);

    let chunk = max_safe_fill(&order, &provider, NOW_MS, &policy)
        .unwrap()
        .expect("a safe chunk");
    assert_eq!(chunk, AtomicAmount::new(100));
    assert!(attempt_is_executable(&order, chunk, &provider, NOW_MS, &policy).unwrap());
    assert!(
        !attempt_is_executable(&order, AtomicAmount::new(101), &provider, NOW_MS, &policy).unwrap()
    );
}

#[test]
fn full_fill_short_circuits_bisection() {
    let order = order_with("full", OrderStatus::Active, 100, 100, 1, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(100);
    assert_eq!(
        max_safe_fill(&order, &provider, NOW_MS, &policy).unwrap(),
        Some(AtomicAmount::new(100))
    );
}

#[test]
fn none_when_min_fill_is_not_executable() {
    let order = order_with(
        "nominsafe",
        OrderStatus::Active,
        1_000,
        1_000,
        101,
        true,
        (1, 1),
    );
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(100);
    assert_eq!(
        max_safe_fill(&order, &provider, NOW_MS, &policy).unwrap(),
        None
    );
}

#[test]
fn all_or_nothing_only_allows_full_remaining() {
    let policy = FreshnessPolicy::default();

    let full_ok = order_with("aon-ok", OrderStatus::Active, 100, 100, 100, false, (1, 1));
    assert_eq!(
        max_safe_fill(&full_ok, &threshold_provider(100), NOW_MS, &policy).unwrap(),
        Some(AtomicAmount::new(100))
    );

    let full_bad = order_with("aon-bad", OrderStatus::Active, 100, 100, 100, false, (1, 1));
    assert_eq!(
        max_safe_fill(&full_bad, &threshold_provider(99), NOW_MS, &policy).unwrap(),
        None
    );
}

#[test]
fn remainder_viability_caps_or_rejects() {
    let policy = FreshnessPolicy::default();

    // Bisection max is 100, but 105 - 100 = 5 < min_fill 10: cap to 95 so the
    // remainder is exactly 10.
    let capped = order_with("cap", OrderStatus::Active, 105, 105, 10, true, (1, 1));
    assert_eq!(
        max_safe_fill(&capped, &threshold_provider(100), NOW_MS, &policy).unwrap(),
        Some(AtomicAmount::new(95))
    );

    // 105 and min_fill 60: capping to 45 is below min_fill, so reject.
    let rejected = order_with("reject", OrderStatus::Active, 105, 105, 60, true, (1, 1));
    assert_eq!(
        max_safe_fill(&rejected, &threshold_provider(100), NOW_MS, &policy).unwrap(),
        None
    );
}

#[test]
fn fallback_ladder_never_returns_an_unsafe_chunk() {
    let order = order_with(
        "fallback",
        OrderStatus::Active,
        1_000,
        1_000,
        1,
        true,
        (1, 1),
    );
    let policy = FreshnessPolicy::default();
    let provider = fallback_provider(100);

    let chunk = max_safe_fill(&order, &provider, NOW_MS, &policy)
        .unwrap()
        .expect("a fallback chunk");
    assert!(
        chunk < AtomicAmount::new(100),
        "the unconfirmable candidate must be abandoned"
    );
    assert!(
        attempt_is_executable(&order, chunk, &provider, NOW_MS, &policy).unwrap(),
        "the fallback chunk must be executable"
    );
}

#[test]
fn search_is_deterministic() {
    let order = order_with("det", OrderStatus::Active, 1_000, 1_000, 7, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let first = max_safe_fill(&order, &threshold_provider(321), NOW_MS, &policy).unwrap();
    let second = max_safe_fill(&order, &threshold_provider(321), NOW_MS, &policy).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, Some(AtomicAmount::new(321)));
}

#[test]
fn expiry_transitions_to_expired_without_quoting() {
    let order = order_with("exp", OrderStatus::Active, 1_000, 1_000, 1, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(1_000);

    for now_ms in [support::EXPIRY_MS, support::EXPIRY_MS + 1] {
        let outcome = evaluate_trigger(&order, true, &provider, now_ms, &policy).unwrap();
        assert_eq!(outcome.order.order.status, OrderStatus::Expired);
        assert_eq!(outcome.decision, TriggerDecision::NotExecutable);
        assert_eq!(
            provider.calls(),
            0,
            "no quote may be requested after expiry"
        );
    }
}

#[test]
fn terminal_order_is_returned_unchanged() {
    let order = order_with(
        "terminal",
        OrderStatus::Expired,
        1_000,
        1_000,
        1,
        true,
        (1, 1),
    );
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(1_000);
    let outcome = evaluate_trigger(&order, true, &provider, NOW_MS, &policy).unwrap();
    assert_eq!(outcome.order, order);
    assert_eq!(outcome.decision, TriggerDecision::NotExecutable);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn no_signal_does_not_quote_or_mutate() {
    let order = order_with("nosig", OrderStatus::Active, 1_000, 1_000, 1, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(100);
    let outcome = evaluate_trigger(&order, false, &provider, NOW_MS, &policy).unwrap();
    assert_eq!(outcome.decision, TriggerDecision::NoSignal);
    assert_eq!(outcome.order, order);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn unavailable_quote_is_not_executable() {
    let order = order_with(
        "unavail",
        OrderStatus::Active,
        1_000,
        1_000,
        1,
        true,
        (1, 1),
    );
    let policy = FreshnessPolicy::default();
    let provider = ModelProvider::new(|_a| None);

    assert!(
        !attempt_is_executable(&order, AtomicAmount::new(1_000), &provider, NOW_MS, &policy)
            .unwrap()
    );

    let outcome = evaluate_trigger(&order, true, &provider, NOW_MS, &policy).unwrap();
    assert_eq!(outcome.decision, TriggerDecision::NotExecutable);
    assert_eq!(outcome.order.order.status, OrderStatus::Active);
}

#[test]
fn signal_returns_trigger_candidate_and_chunk() {
    let order = order_with("sig", OrderStatus::Active, 1_000, 1_000, 10, true, (1, 1));
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(200);
    let outcome = evaluate_trigger(&order, true, &provider, NOW_MS, &policy).unwrap();
    assert_eq!(outcome.order.order.status, OrderStatus::TriggerCandidate);
    assert_eq!(
        outcome.decision,
        TriggerDecision::Fill(AtomicAmount::new(200))
    );
}

#[test]
fn signal_without_safe_fill_reverts_to_active() {
    let order = order_with(
        "nosafe",
        OrderStatus::Active,
        1_000,
        1_000,
        50,
        true,
        (1, 1),
    );
    let policy = FreshnessPolicy::default();
    let provider = threshold_provider(10);
    let outcome = evaluate_trigger(&order, true, &provider, NOW_MS, &policy).unwrap();
    assert_eq!(outcome.order.order.status, OrderStatus::Active);
    assert_eq!(outcome.decision, TriggerDecision::NotExecutable);
}

#[test]
fn search_bounds_are_within_the_spec_limits() {
    let bound = 128u32;
    assert!(MAX_SEARCH_STEPS <= bound);
    assert!(MAX_FALLBACK_STEPS <= bound);
}

#[test]
fn property_threshold_chunk_is_maximal_viable_and_conserves() {
    let policy = FreshnessPolicy::default();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    for _ in 0..200 {
        let remaining = 2 + (next_rand(&mut state) % 5_000) as u128;
        let min_fill = 1 + (next_rand(&mut state) % remaining as u64) as u128;
        let span = (remaining - min_fill + 1) as u64;
        let k = min_fill + (next_rand(&mut state) % span) as u128;
        let allow_partial = next_rand(&mut state) % 2 == 0;
        let effective_min = if allow_partial { min_fill } else { remaining };

        let order = order_with(
            "prop",
            OrderStatus::Active,
            remaining,
            remaining,
            effective_min,
            allow_partial,
            (1, 1),
        );
        let provider = threshold_provider(k);
        let chunk = max_safe_fill(&order, &provider, NOW_MS, &policy).unwrap();

        let Some(chunk) = chunk else {
            continue;
        };
        let chunk_value = chunk.get();
        assert!(chunk_value >= effective_min && chunk_value <= remaining);
        assert!(attempt_is_executable(&order, chunk, &provider, NOW_MS, &policy).unwrap());

        // Remainder viability: full or leaves at least min_fill.
        if chunk_value != remaining {
            assert!(remaining - chunk_value >= effective_min);
            // No larger *viable* executable chunk may exist.
            let candidate = chunk_value + 1;
            let viable = candidate == remaining || remaining - candidate >= effective_min;
            if viable {
                assert!(!attempt_is_executable(
                    &order,
                    AtomicAmount::new(candidate),
                    &provider,
                    NOW_MS,
                    &policy
                )
                .unwrap());
            }
        }

        // Conservation through the P44 fill ledger.
        let executing = order_with(
            "prop-exec",
            OrderStatus::Executing,
            remaining,
            remaining,
            effective_min,
            true,
            (1, 1),
        );
        let target = if chunk_value == remaining {
            OrderStatus::Filled
        } else {
            OrderStatus::PartiallyFilled
        };
        let delta = FillDelta {
            simulated_net_input: chunk,
            simulated_net_output: chunk,
            remaining_after: AtomicAmount::new(remaining - chunk_value),
        };
        let applied = apply_transition(&executing, target, Some(&delta), NOW_MS).expect("fill");
        assert!(conservation_holds(&applied));
        assert_eq!(
            applied.filled_input.get() + applied.order.remaining_input.get(),
            remaining
        );
    }
}
