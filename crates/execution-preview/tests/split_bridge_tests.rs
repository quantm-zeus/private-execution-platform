//! P77 aggregate net-delta bridge and split pre-sign revalidation tests.
//!
//! Deterministic fixtures only: no clock, RPC, or randomness.

use std::collections::HashSet;

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, RouteLeg, RoutePlan,
    SplitLeg, SplitPlan, TaxObservation, TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use execution_preview::{
    revalidate_split_pre_sign, AllowanceObservation, AllowanceState, BridgeError, NetDelta,
    RevalidationOutcome, RevalidationReason, SplitRevalidationInput, SplitRouteBinding,
    WalletBalance,
};
use market_types::{
    AssetAmount, AtomicAmount, Bps, Freshness, FreshnessPolicy, FreshnessStatus, SafeFreshnessMeta,
    Sequence,
};
use policy::{
    ApprovedExecution, PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot,
    UsdMicros,
};
use tax_engine::TaxAssessment;

const NOW_MS: i64 = 1_000_000;

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid asset")
}
fn usdc() -> AssetId {
    asset("0xusdc")
}
fn token() -> AssetId {
    asset("0xtoken")
}

fn amount(asset: AssetId, value: u128) -> AssetAmount {
    AssetAmount {
        asset,
        amount: AtomicAmount::new(value),
    }
}

fn delta(net_input: u128, gross: u128, net: u128, tax: Option<AssetAmount>) -> NetDelta {
    NetDelta {
        token_in: usdc(),
        token_out: token(),
        net_input: amount(usdc(), net_input),
        gross_output: amount(token(), gross),
        net_output: amount(token(), net),
        dex_fee: None,
        tax_cost: tax,
    }
}

fn risk() -> RiskConstraints {
    RiskConstraints {
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        max_total_cost: None,
    }
}

fn buy_intent(amount_in: u128) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("id"),
        source: TradeSource::Internal,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        token_in: usdc(),
        token_out: token(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount_in),
        order_type: OrderType::Market,
        limit_price: None,
        risk: risk(),
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn route(venue: &str, pool: &str, amount_in: u128, out: u128) -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: venue.to_string(),
            pool_ref: pool.to_string(),
            token_in: usdc(),
            token_out: token(),
            amount_in: AtomicAmount::new(amount_in),
            expected_amount_out: AtomicAmount::new(out),
        }],
        expected_net_output: amount(token(), out),
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    }
}

fn split_two(expected: u128) -> SplitPlan {
    SplitPlan {
        legs: vec![
            SplitLeg {
                amount_in: AtomicAmount::new(600),
                route: route("uniswap", "0xpoolA", 600, 300),
            },
            SplitLeg {
                amount_in: AtomicAmount::new(400),
                route: route("pancake", "0xpoolB", 400, 210),
            },
        ],
        expected_net_output: amount(token(), expected),
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    }
}

fn fresh_basis(tax: u16) -> TaxAssessment {
    TaxAssessment::new(
        token(),
        ChainId::Base,
        Bps::new(tax).expect("bps"),
        Bps::new(tax).expect("bps"),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: NOW_MS,
            evaluated_at_ms: NOW_MS,
            age_ms: 0,
            sequence: Sequence(1),
        },
        1,
    )
}

fn limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::from(["uniswap".to_string(), "pancake".to_string()]),
    }
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).expect("gate"),
        limits(),
    )
    .expect("engine")
}

fn approved(intent: &TradeIntent) -> ApprovedExecution {
    let context = PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .expect("context");
    engine()
        .authorize_trade(intent, &context)
        .expect("approved")
}

fn observation(router_ref: &str) -> TaxObservation {
    TaxObservation {
        chain: ChainId::Base,
        token: token(),
        pool_ref: "0xpoolA".to_string(),
        router_ref: router_ref.to_string(),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        amount: AtomicAmount::new(1),
        block_or_slot: 1,
        buy_tax: Bps::new(0).expect("bps"),
        sell_tax: Bps::new(0).expect("bps"),
        buy_succeeds: true,
        sell_succeeds: true,
        sellable: true,
        confidence: Bps::new(10_000).expect("bps"),
        observed_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 60_000,
    }
}

fn allowance(spender: &str, value: u128) -> AllowanceObservation {
    AllowanceObservation::Required(AllowanceState {
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        asset: usdc(),
        spender_ref: spender.to_string(),
        amount: AtomicAmount::new(value),
        freshness: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    })
}

fn wallet() -> WalletBalance {
    WalletBalance {
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        asset: usdc(),
        available: AtomicAmount::new(1_000),
        freshness: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn revalidate(
    intent: &TradeIntent,
    approval: &ApprovedExecution,
    split: &SplitPlan,
    binding: &SplitRouteBinding,
    branches: &[NetDelta],
    assessment: &TaxAssessment,
    observation: &TaxObservation,
    allowances: &[AllowanceObservation],
    min_out: &AssetAmount,
    wallet: &WalletBalance,
    policy: &FreshnessPolicy,
    limits: &PolicyLimits,
    programs: &HashSet<String>,
) -> RevalidationOutcome {
    revalidate_split_pre_sign(&SplitRevalidationInput {
        intent,
        approval: Some(approval),
        policy_limits: limits,
        allowed_programs: programs,
        trading_enabled: true,
        now_ms: NOW_MS,
        freshness_policy: policy,
        split,
        branch_deltas: branches,
        basis_assessment: assessment,
        tax_observation: Some(observation),
        approved_split_binding: binding,
        min_out,
        wallet_balance: wallet,
        allowances,
    })
}

#[test]
fn aggregate_empty_rejected() {
    assert!(matches!(
        NetDelta::aggregate(&[]),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));
}

#[test]
fn aggregate_checked_sums_and_never_emits_some_zero() {
    let branch_a = delta(600, 300, 240, Some(amount(token(), 60)));
    let branch_b = delta(400, 210, 168, Some(amount(token(), 42)));
    let aggregate = NetDelta::aggregate(&[branch_a, branch_b]).expect("aggregate");
    assert_eq!(aggregate.net_input.amount.get(), 1_000);
    assert_eq!(aggregate.gross_output.amount.get(), 510);
    assert_eq!(aggregate.net_output.amount.get(), 408);
    assert_eq!(
        aggregate.tax_cost.as_ref().map(|tax| tax.amount.get()),
        Some(102)
    );
    assert!(aggregate.dex_fee.is_none());

    let zero = NetDelta::aggregate(&[delta(600, 300, 300, None), delta(400, 210, 210, None)])
        .expect("aggregate");
    assert!(zero.tax_cost.is_none());
    assert!(zero.dex_fee.is_none());
}

#[test]
fn aggregate_pair_and_tax_denomination_mismatch_rejected() {
    let mut mismatched = delta(400, 210, 210, None);
    mismatched.token_out = asset("0xother");
    assert!(NetDelta::aggregate(&[delta(600, 300, 300, None), mismatched]).is_err());

    let input_tax = delta(600, 300, 300, Some(amount(usdc(), 60)));
    let output_tax = delta(400, 210, 168, Some(amount(token(), 42)));
    assert!(NetDelta::aggregate(&[input_tax, output_tax]).is_err());
}

#[test]
fn aggregate_overflow_rejected() {
    let huge = NetDelta {
        token_in: usdc(),
        token_out: token(),
        net_input: amount(usdc(), u128::MAX),
        gross_output: amount(token(), 1),
        net_output: amount(token(), 1),
        dex_fee: None,
        tax_cost: None,
    };
    assert!(NetDelta::aggregate(&[huge.clone(), huge]).is_err());
}

#[test]
fn aggregate_associativity() {
    let a = delta(600, 300, 300, None);
    let b = delta(400, 210, 210, None);
    let c = delta(200, 90, 90, None);
    let left = NetDelta::aggregate(&[
        NetDelta::aggregate(&[a.clone(), b.clone()]).expect("ab"),
        c.clone(),
    ])
    .expect("left");
    let right =
        NetDelta::aggregate(&[a, NetDelta::aggregate(&[b, c]).expect("bc")]).expect("right");
    assert_eq!(left, right);
}

#[test]
fn validate_split_delta_preview_positive() {
    let intent = buy_intent(1_000);
    let split = split_two(510);
    let branches = [delta(600, 300, 300, None), delta(400, 210, 210, None)];
    let assessment = fresh_basis(0);
    assert!(
        execution_preview::validate_split_delta_preview_with_assessment(
            &intent,
            &split,
            &branches,
            &assessment,
            NOW_MS
        )
        .is_ok()
    );
}

#[test]
fn validate_split_with_assessment_checks_each_branch() {
    let intent = buy_intent(1_000);
    let split = split_two(510);
    let assessment = fresh_basis(100);
    // Branch A is correctly taxed (300 * 100 bps = 3); branch B is not
    // (210 * 100 bps = 2, but the delta carries 3).
    let branches = [
        delta(600, 300, 297, Some(amount(token(), 3))),
        delta(400, 210, 207, Some(amount(token(), 3))),
    ];
    assert!(matches!(
        execution_preview::validate_split_delta_preview_with_assessment(
            &intent,
            &split,
            &branches,
            &assessment,
            NOW_MS
        ),
        Err(BridgeError::AssessmentDeltaMismatch)
    ));
}

#[test]
fn validate_split_rejects_per_branch_route_mismatch() {
    let intent = buy_intent(1_000);
    // Branch routes claim 300 and 210; the second realized delta claims 207.
    // Per-branch binding must reject it even though the totals are close.
    let split = split_two(510);
    let branches = [delta(600, 300, 300, None), delta(400, 210, 207, None)];
    let assessment = fresh_basis(0);
    assert!(matches!(
        execution_preview::validate_split_delta_preview_with_assessment(
            &intent,
            &split,
            &branches,
            &assessment,
            NOW_MS
        ),
        Err(BridgeError::NetDeltaInconsistent(_))
    ));
}

#[test]
fn revalidate_split_positive_with_per_spender_allowances() {
    let intent = buy_intent(1_000);
    let split = split_two(510);
    let binding = SplitRouteBinding::from_split(&split);
    let approval = approved(&intent);
    let branches = [delta(600, 300, 300, None), delta(400, 210, 210, None)];
    let assessment = fresh_basis(0);
    let observation = observation("uniswap");
    let allowances = [allowance("uniswap", 600), allowance("pancake", 400)];
    let min_out = amount(token(), 500);
    let wallet = wallet();
    let policy = FreshnessPolicy::default();
    let limits = limits();
    let programs = HashSet::new();

    assert!(matches!(
        revalidate(
            &intent,
            &approval,
            &split,
            &binding,
            &branches,
            &assessment,
            &observation,
            &allowances,
            &min_out,
            &wallet,
            &policy,
            &limits,
            &programs,
        ),
        RevalidationOutcome::Valid(_)
    ));
}

#[test]
fn revalidate_split_requires_every_spender() {
    let intent = buy_intent(1_000);
    let split = split_two(510);
    let binding = SplitRouteBinding::from_split(&split);
    let approval = approved(&intent);
    let branches = [delta(600, 300, 300, None), delta(400, 210, 210, None)];
    let assessment = fresh_basis(0);
    let observation = observation("uniswap");
    let min_out = amount(token(), 500);
    let wallet = wallet();
    let policy = FreshnessPolicy::default();
    let limits = limits();
    let programs = HashSet::new();

    let missing = [allowance("uniswap", 600)];
    assert_eq!(
        revalidate(
            &intent,
            &approval,
            &split,
            &binding,
            &branches,
            &assessment,
            &observation,
            &missing,
            &min_out,
            &wallet,
            &policy,
            &limits,
            &programs,
        ),
        RevalidationOutcome::AbortFinal(RevalidationReason::MissingAllowanceObservation)
    );

    let extra = [
        allowance("uniswap", 600),
        allowance("pancake", 400),
        allowance("evil", 1),
    ];
    assert_eq!(
        revalidate(
            &intent,
            &approval,
            &split,
            &binding,
            &branches,
            &assessment,
            &observation,
            &extra,
            &min_out,
            &wallet,
            &policy,
            &limits,
            &programs,
        ),
        RevalidationOutcome::AbortFinal(RevalidationReason::AllowanceSpenderMismatch)
    );

    // Each spender must cover only its own branch input, not the aggregate.
    let short = [allowance("uniswap", 600), allowance("pancake", 399)];
    assert_eq!(
        revalidate(
            &intent,
            &approval,
            &split,
            &binding,
            &branches,
            &assessment,
            &observation,
            &short,
            &min_out,
            &wallet,
            &policy,
            &limits,
            &programs,
        ),
        RevalidationOutcome::AbortRequote(RevalidationReason::InsufficientAllowance)
    );
}

#[test]
fn revalidate_split_rejects_selected_route_mismatch() {
    let intent = buy_intent(1_000);
    let split = split_two(510);
    let mut binding = SplitRouteBinding::from_split(&split);
    binding.branches[0].amount_in = AtomicAmount::new(601);
    let approval = approved(&intent);
    let branches = [delta(600, 300, 300, None), delta(400, 210, 210, None)];
    let assessment = fresh_basis(0);
    let observation = observation("uniswap");
    let allowances = [allowance("uniswap", 600), allowance("pancake", 400)];
    let min_out = amount(token(), 500);
    let wallet = wallet();
    let policy = FreshnessPolicy::default();
    let limits = limits();
    let programs = HashSet::new();

    assert_eq!(
        revalidate(
            &intent,
            &approval,
            &split,
            &binding,
            &branches,
            &assessment,
            &observation,
            &allowances,
            &min_out,
            &wallet,
            &policy,
            &limits,
            &programs,
        ),
        RevalidationOutcome::AbortRequote(RevalidationReason::SelectedRouteMismatch)
    );
}
