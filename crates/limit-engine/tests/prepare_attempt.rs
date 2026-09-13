//! P50 — attempt preparation: policy -> exact net preview -> revalidation.
//!
//! The fixture mirrors the P38/P39 CPMM shape: USDC in (6 decimals), TOKEN out
//! (18 decimals), net_in = 1_000 USDC, gross = 250 TOKEN, 400 bps tax = 10
//! TOKEN, net = 240 TOKEN, so the bridge's realized-tax check
//! `floor(250 * 400 / 10_000) = 10` holds exactly.

mod support;

use std::collections::HashSet;

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IntentId, LimitPrice, OrderStatus, OrderType, RouteLeg, RoutePlan, TaxObservation,
    TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::{
    AllowanceObservation, AllowanceState, NetDelta, RevalidationReason, WalletBalance,
};
use limit_engine::{
    prepare_attempt, AttemptTrust, LimitEngineError, PrepareAttemptInput, PreparedAttemptOutcome,
    QuotedAttempt,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, PriceRatio,
    SafeFreshnessMeta, Sequence,
};
use policy::{PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot, UsdMicros};
use tax_engine::TaxAssessment;

use support::{asset, idempotency_key, stored, EXPIRY_MS};

const NOW: i64 = 100_000;
const OBSERVED: i64 = NOW - 1_000;
const CHUNK: u128 = 1_000;

fn usdc() -> AssetId {
    asset("USDC")
}

fn token() -> AssetId {
    asset("TOKEN")
}

fn wallet_ref() -> WalletRef {
    WalletRef::new("w1").expect("wallet")
}

fn freshness() -> Freshness {
    Freshness {
        observed_at_ms: OBSERVED,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

fn amount(asset: &AssetId, value: u128) -> AssetAmount {
    AssetAmount {
        asset: asset.clone(),
        amount: AtomicAmount::new(value),
    }
}

fn order() -> limit_engine::StoredLimitOrder {
    let mut order = stored("p50", OrderStatus::Executing, 10_000, 10_000, 0);
    // BUY limit 100/24 -> exact floor ceil(1000 * 24 / 100) = 240, which the
    // 240-TOKEN net output satisfies exactly.
    order.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    order
}

fn route() -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "0xpool-p50".to_string(),
            token_in: usdc(),
            token_out: token(),
            amount_in: AtomicAmount::new(CHUNK),
            expected_amount_out: AtomicAmount::new(250),
        }],
        expected_net_output: amount(&token(), 240),
        state: freshness(),
    }
}

fn net_delta() -> NetDelta {
    NetDelta {
        token_in: usdc(),
        token_out: token(),
        net_input: amount(&usdc(), CHUNK),
        gross_output: amount(&token(), 250),
        net_output: amount(&token(), 240),
        dex_fee: Some(amount(&usdc(), 3)),
        tax_cost: Some(amount(&token(), 10)),
    }
}

fn assessment() -> TaxAssessment {
    TaxAssessment::new(
        token(),
        ChainId::Base,
        Bps::new(400).unwrap(),
        Bps::new(0).unwrap(),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: OBSERVED,
            evaluated_at_ms: OBSERVED,
            age_ms: 1_000,
            sequence: Sequence(1),
        },
        1,
    )
}

fn tax_observation() -> TaxObservation {
    TaxObservation {
        chain: ChainId::Base,
        token: token(),
        pool_ref: "0xpool-p50".to_string(),
        router_ref: "uniswap_v3".to_string(),
        wallet_ref: wallet_ref(),
        amount: AtomicAmount::new(CHUNK),
        block_or_slot: 1,
        buy_tax: Bps::new(400).unwrap(),
        sell_tax: Bps::new(0).unwrap(),
        buy_succeeds: true,
        sell_succeeds: true,
        sellable: true,
        confidence: Bps::new(9_000).unwrap(),
        observed_at_ms: OBSERVED,
        expires_at_ms: NOW + 60_000,
    }
}

fn provisional_intent(order: &limit_engine::StoredLimitOrder) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("quoted-intent").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("u1").unwrap(),
        wallet_ref: order.order.wallet_ref.clone(),
        chain: ChainId::Base,
        token_in: order.order.token_in.clone(),
        token_out: order.order.token_out.clone(),
        side: order.order.side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(CHUNK),
        order_type: OrderType::Limit,
        limit_price: Some(order.order.limit_price.clone()),
        risk: order.order.risk.clone(),
        allow_partial_fill: true,
        expiry_ms: Some(order.order.expires_at_ms),
        nonce: 1,
        idempotency_key: idempotency_key("quoted-key"),
    }
}

fn quoted(order: &limit_engine::StoredLimitOrder) -> QuotedAttempt {
    QuotedAttempt {
        intent: provisional_intent(order),
        route: route(),
        net_delta: net_delta(),
        assessment: assessment(),
    }
}

fn limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(5_000_000),
        max_daily_turnover_usd: UsdMicros::new(20_000_000),
        max_buy_tax: Bps::new(500).unwrap(),
        max_sell_tax: Bps::new(500).unwrap(),
        max_price_impact: Bps::new(300).unwrap(),
        max_slippage: Bps::new(200).unwrap(),
        allowed_chains: [ChainId::Base].into_iter().collect(),
        allowed_venues: ["uniswap_v3".to_string()].into_iter().collect(),
    }
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).unwrap(),
        limits(),
    )
    .unwrap()
}

fn trust() -> AttemptTrust {
    AttemptTrust {
        policy_context: PolicyContext::from_trusted_backend_state(
            NOW,
            UsdMicros::new(500_000),
            TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
            Some("uniswap_v3".to_string()),
        )
        .unwrap(),
        wallet_balance: WalletBalance {
            wallet_ref: wallet_ref(),
            chain: ChainId::Base,
            asset: usdc(),
            available: AtomicAmount::new(10_000),
            freshness: freshness(),
        },
        allowance: AllowanceObservation::NotRequired,
        tax_observation: tax_observation(),
        allowed_programs: HashSet::new(),
        freshness_policy: FreshnessPolicy::default(),
    }
}

fn input<'a>(
    order: &'a limit_engine::StoredLimitOrder,
    quoted: &'a QuotedAttempt,
    trust: &'a AttemptTrust,
    chunk: u128,
) -> PrepareAttemptInput<'a> {
    PrepareAttemptInput {
        order,
        source: TradeSource::Web,
        attempt_seq: 1,
        attempt_intent_id: IntentId::new("attempt-intent-1").unwrap(),
        attempt_key: idempotency_key("attempt-key-1"),
        chunk: AtomicAmount::new(chunk),
        quoted,
        trust,
        now_ms: NOW,
    }
}

fn ready(outcome: &PreparedAttemptOutcome) -> &limit_engine::PreparedAttempt {
    match outcome {
        PreparedAttemptOutcome::Ready(prepared) => prepared,
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[test]
fn ready_attempt_binds_identity_limit_and_exact_min_out() {
    let order = order();
    let quoted = quoted(&order);
    let trust = trust();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    let prepared = ready(&outcome);

    assert_eq!(prepared.intent.id.as_str(), "attempt-intent-1");
    assert_eq!(prepared.intent.idempotency_key.as_str(), "attempt-key-1");
    assert_eq!(prepared.intent.source, TradeSource::Web);
    assert_eq!(prepared.intent.amount.get(), CHUNK);
    assert_eq!(prepared.intent.amount_type, AmountType::InputAssetAtomic);
    assert_eq!(prepared.intent.order_type, OrderType::Limit);
    assert_eq!(prepared.intent.side, TradeSide::Buy);
    assert_eq!(prepared.intent.nonce, 1);
    assert_eq!(prepared.intent.expiry_ms, Some(EXPIRY_MS));
    assert!(prepared.intent.limit_price.is_some());

    // BUY limit 100/24 with net_in 1_000 -> exact limit floor 240; slip floor 236.
    assert_eq!(prepared.min_out.amount.get(), 240);
    assert_eq!(prepared.min_out.asset, token());
    assert!(prepared
        .preview
        .preview()
        .satisfies_limit_price(prepared.intent.limit_price.as_ref().unwrap())
        .unwrap());
    assert!(prepared.preview.preview().simulated_net_output.amount >= prepared.min_out.amount);
    // The approval binds the attempt identity.
    assert_eq!(prepared.approval.intent_id(), &prepared.intent.id);
    assert_eq!(
        prepared.approval.idempotency_key(),
        &prepared.intent.idempotency_key
    );
    assert_eq!(prepared.route, route());
    assert_eq!(prepared.net_delta, net_delta());
}

#[test]
fn min_out_is_driven_by_the_slippage_floor_when_the_limit_is_loose() {
    let mut order = order();
    order.order.limit_price = LimitPrice {
        numerator_asset: usdc(),
        denominator_asset: token(),
        ratio: PriceRatio::new(5_000, 1).expect("ratio"),
    };
    let quoted = quoted(&order);
    let trust = trust();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    let prepared = ready(&outcome);
    // Loose limit -> limit floor 1; slip floor = ceil(240 * 9800 / 10000) = 236.
    assert_eq!(prepared.min_out.amount.get(), 236);
}

#[test]
fn stale_route_requests_a_requote() {
    let order = order();
    let mut route = route();
    route.state.observed_at_ms = NOW - 20_000;
    let quoted = QuotedAttempt {
        route,
        ..quoted(&order)
    };
    let trust = trust();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(
        matches!(
            outcome,
            PreparedAttemptOutcome::Requote(RevalidationReason::StaleState)
        ),
        "got {outcome:?}"
    );
}

#[test]
fn insufficient_balance_requests_a_requote() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.wallet_balance.available = AtomicAmount::new(CHUNK - 1);
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Requote(RevalidationReason::InsufficientBalance)
    ));
}

#[test]
fn changed_tax_requests_a_requote() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.tax_observation.buy_tax = Bps::new(300).unwrap();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Requote(RevalidationReason::TaxChanged)
    ));
}

#[test]
fn a_final_revalidation_failure_aborts() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    // An observation above the intent's tax cap is a final revalidation failure.
    trust.tax_observation.buy_tax = Bps::new(600).unwrap();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Abort(RevalidationReason::TaxCapExceeded)
    ));
}

#[test]
fn policy_refuses_an_oversized_attempt() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.policy_context = PolicyContext::from_trusted_backend_state(
        NOW,
        UsdMicros::new(2_000_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap_v3".to_string()),
    )
    .unwrap();
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine()),
        Err(LimitEngineError::PolicyRejected)
    ));
}

#[test]
fn trading_disabled_fails_closed() {
    let order = order();
    let quoted = quoted(&order);
    let trust = trust();
    let disabled = PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("false")).unwrap(),
        limits(),
    )
    .unwrap();
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &disabled),
        Err(LimitEngineError::PolicyRejected)
    ));
}

#[test]
fn chunk_outside_the_fillable_range_is_rejected() {
    let order = order();
    let quoted = quoted(&order);
    let trust = trust();
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, 0), &engine()),
        Err(LimitEngineError::AmountBelowMinFill)
    ));
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, 10_001), &engine()),
        Err(LimitEngineError::RemainingUnderflow)
    ));
    let mut bounded = order.clone();
    bounded.order.min_fill = AtomicAmount::new(500);
    assert!(matches!(
        prepare_attempt(&input(&bounded, &quoted, &trust, 100), &engine()),
        Err(LimitEngineError::AmountBelowMinFill)
    ));
}

#[test]
fn zero_attempt_sequence_is_rejected() {
    let order = order();
    let quoted = quoted(&order);
    let trust = trust();
    let mut probe = input(&order, &quoted, &trust, CHUNK);
    probe.attempt_seq = 0;
    assert!(matches!(
        prepare_attempt(&probe, &engine()),
        Err(LimitEngineError::InvalidOrder)
    ));
}

#[test]
fn prepared_attempt_debug_is_redacted() {
    let order = order();
    let quoted = quoted(&order);
    let trust = trust();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    let rendered = format!("{outcome:?}");
    for needle in [
        "USDC",
        "TOKEN",
        "attempt-key-1",
        "attempt-intent-1",
        "1000",
        "250",
    ] {
        assert!(
            !rendered.contains(needle),
            "PreparedAttempt Debug leaked `{needle}`: {rendered}"
        );
    }
}

#[test]
fn chunk_equal_to_min_fill_or_remaining_is_allowed() {
    // chunk == min_fill is allowed (the check is strict `<`, not `<=`).
    let mut at_min = order();
    at_min.order.min_fill = AtomicAmount::new(CHUNK);
    let at_min_quote = quoted(&at_min);
    let trust = trust();
    let outcome = prepare_attempt(&input(&at_min, &at_min_quote, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(outcome, PreparedAttemptOutcome::Ready(_)));

    // chunk == remaining_input is allowed (the check is strict `>`, not `>=`).
    let mut at_remaining = stored("p50-full", OrderStatus::Executing, CHUNK, CHUNK, 0);
    at_remaining.order.limit_price.ratio = PriceRatio::new(100, 24).expect("ratio");
    let at_remaining_quote = quoted(&at_remaining);
    let outcome = prepare_attempt(
        &input(&at_remaining, &at_remaining_quote, &trust, CHUNK),
        &engine(),
    )
    .expect("preparation must not error");
    assert!(matches!(outcome, PreparedAttemptOutcome::Ready(_)));
}

#[test]
fn nonce_is_the_order_nonce_plus_the_attempt_sequence() {
    let mut order = order();
    order.nonce = 7;
    let quoted = quoted(&order);
    let trust = trust();
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert_eq!(ready(&outcome).intent.nonce, 8);
}

#[test]
fn a_quote_that_does_not_price_the_chunk_is_an_integrity_violation() {
    let order = order();
    let mut quoted = quoted(&order);
    quoted.net_delta.net_input.amount = AtomicAmount::new(CHUNK - 1);
    let trust = trust();
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine()),
        Err(LimitEngineError::IntegrityViolation)
    ));
}

#[test]
fn a_delta_pair_mismatch_is_an_integrity_violation() {
    let order = order();
    let mut quoted = quoted(&order);
    quoted.net_delta.token_in = asset("OTHER");
    let trust = trust();
    assert!(matches!(
        prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine()),
        Err(LimitEngineError::IntegrityViolation)
    ));
}

#[test]
fn a_stricter_caller_freshness_policy_is_applied() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    // Observed 1s ago: fresh under the 10s default, stale under this policy.
    trust.freshness_policy = FreshnessPolicy::new(500, 1_000).expect("policy");
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Requote(RevalidationReason::StaleState)
    ));
}

fn allowance(value: u128, spender: &str) -> AllowanceObservation {
    AllowanceObservation::Required(AllowanceState {
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        asset: usdc(),
        spender_ref: spender.to_string(),
        amount: AtomicAmount::new(value),
        freshness: freshness(),
    })
}

#[test]
fn a_sufficient_required_allowance_is_accepted() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.allowance = allowance(CHUNK, "uniswap_v3");
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(outcome, PreparedAttemptOutcome::Ready(_)));
}

#[test]
fn an_insufficient_allowance_requests_a_requote() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.allowance = allowance(CHUNK - 1, "uniswap_v3");
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Requote(RevalidationReason::InsufficientAllowance)
    ));
}

#[test]
fn a_wrong_allowance_spender_aborts() {
    let order = order();
    let quoted = quoted(&order);
    let mut trust = trust();
    trust.allowance = allowance(CHUNK, "evil_router");
    let outcome = prepare_attempt(&input(&order, &quoted, &trust, CHUNK), &engine())
        .expect("preparation must not error");
    assert!(matches!(
        outcome,
        PreparedAttemptOutcome::Abort(RevalidationReason::AllowanceSpenderMismatch)
    ));
}
