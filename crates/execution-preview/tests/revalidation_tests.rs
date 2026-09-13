//! P39 pre-sign revalidation tests.
//!
//! All economics are exact integers. The fixture follows the P38 CPMM shape:
//! USDC = token_in (6 decimals), TOKEN = token_out (18 decimals), a 30 bps pool
//! fee, and a basis assessment with `buy_tax = 400` bps. The simulated net
//! delta is net_in = 1_000 USDC, gross = 250 TOKEN, tax = 10 TOKEN, net = 240
//! TOKEN, so the bridge's realized-tax check (`floor(250 * 400 / 10_000) = 10`)
//! holds exactly.

use std::cmp::Ordering;
use std::collections::HashSet;

use chain_types::{AssetId, ChainId};
use domain::{
    cmp_u128_products, AmountType, IdempotencyKey, IntentId, OrderType, RiskConstraints, RouteLeg,
    RoutePlan, TaxObservation, TradeIntent, TradeSide, TradeSource, UserId,
    ValidatedExecutionPreview, WalletRef,
};
use execution_preview::{
    revalidate_pre_sign, AllowanceObservation, AllowanceState, NetDelta, RevalidationInput,
    RevalidationOutcome, RevalidationReason, RouteBinding, WalletBalance,
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

const NOW: i64 = 100_000;
const OBSERVED: i64 = NOW - 1_000;

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).unwrap()
}

fn usdc() -> AssetId {
    base_asset("0xusdc-p39")
}

fn token() -> AssetId {
    base_asset("0xtoken-p39")
}

fn wallet_ref() -> WalletRef {
    WalletRef::new("wallet-p39").unwrap()
}

fn amount(asset: &AssetId, value: u128) -> AssetAmount {
    AssetAmount {
        asset: asset.clone(),
        amount: AtomicAmount::new(value),
    }
}

fn freshness() -> Freshness {
    Freshness {
        observed_at_ms: OBSERVED,
        chain_height: 100,
        sequence: Sequence(1),
    }
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-p39").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-p39").unwrap(),
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        token_in: usdc(),
        token_out: token(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(500).unwrap(),
            max_sell_tax: Bps::new(500).unwrap(),
            max_price_impact: Bps::new(300).unwrap(),
            max_slippage: Bps::new(200).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-p39").unwrap(),
    }
}

fn route() -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "0xpool-p39".to_string(),
            token_in: usdc(),
            token_out: token(),
            amount_in: AtomicAmount::new(1_000),
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
        net_input: amount(&usdc(), 1_000),
        gross_output: amount(&token(), 250),
        net_output: amount(&token(), 240),
        dex_fee: Some(amount(&usdc(), 3)),
        tax_cost: Some(amount(&token(), 10)),
    }
}

fn basis_assessment() -> TaxAssessment {
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
        pool_ref: "0xpool-p39".to_string(),
        router_ref: "uniswap_v3".to_string(),
        wallet_ref: wallet_ref(),
        amount: AtomicAmount::new(1_000),
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

fn wallet_balance() -> WalletBalance {
    WalletBalance {
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        asset: usdc(),
        available: AtomicAmount::new(1_000),
        freshness: freshness(),
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

fn turnover() -> TurnoverSnapshot {
    TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0))
}

fn engine_with_limits(limits: PolicyLimits) -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).unwrap(),
        limits,
    )
    .unwrap()
}

fn policy_context(now_ms: i64) -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        now_ms,
        UsdMicros::new(1_000_000),
        turnover(),
        Some("uniswap_v3".to_string()),
    )
    .unwrap()
}

fn approval_for_with_limits(
    intent: &TradeIntent,
    now_ms: i64,
    limits: PolicyLimits,
) -> ApprovedExecution {
    engine_with_limits(limits)
        .authorize_trade(intent, &policy_context(now_ms))
        .unwrap()
}

fn approval_for(intent: &TradeIntent, now_ms: i64) -> ApprovedExecution {
    approval_for_with_limits(intent, now_ms, limits())
}

fn allowance(value: u128) -> AllowanceObservation {
    AllowanceObservation::Required(AllowanceState {
        wallet_ref: wallet_ref(),
        chain: ChainId::Base,
        asset: usdc(),
        spender_ref: "uniswap_v3".to_string(),
        amount: AtomicAmount::new(value),
        freshness: freshness(),
    })
}

struct Fixture {
    intent: TradeIntent,
    approval: Option<ApprovedExecution>,
    limits: PolicyLimits,
    allowed_programs: HashSet<String>,
    trading_enabled: bool,
    freshness_policy: FreshnessPolicy,
    route: RoutePlan,
    net_delta: NetDelta,
    basis_assessment: TaxAssessment,
    tax_observation: Option<TaxObservation>,
    approved_route_binding: RouteBinding,
    min_out: AssetAmount,
    wallet_balance: WalletBalance,
    allowance: AllowanceObservation,
}

impl Fixture {
    fn new() -> Self {
        let intent = intent();
        let approval = approval_for(&intent, NOW);
        let route = route();
        let approved_route_binding = RouteBinding::from_route(&route);
        Self {
            intent,
            approval: Some(approval),
            limits: limits(),
            allowed_programs: HashSet::new(),
            trading_enabled: true,
            freshness_policy: FreshnessPolicy::default(),
            route,
            net_delta: net_delta(),
            basis_assessment: basis_assessment(),
            tax_observation: Some(tax_observation()),
            approved_route_binding,
            min_out: amount(&token(), 240),
            wallet_balance: wallet_balance(),
            allowance: AllowanceObservation::NotRequired,
        }
    }

    fn run(&self) -> RevalidationOutcome {
        let input = RevalidationInput {
            intent: &self.intent,
            approval: self.approval.as_ref(),
            policy_limits: &self.limits,
            allowed_programs: &self.allowed_programs,
            trading_enabled: self.trading_enabled,
            now_ms: NOW,
            freshness_policy: &self.freshness_policy,
            route: &self.route,
            net_delta: &self.net_delta,
            basis_assessment: &self.basis_assessment,
            tax_observation: self.tax_observation.as_ref(),
            approved_route_binding: &self.approved_route_binding,
            min_out: &self.min_out,
            wallet_balance: &self.wallet_balance,
            allowance: &self.allowance,
        };
        revalidate_pre_sign(&input)
    }
}

/// A complete two-leg Solana route fixture used to prove the spender binding is
/// the FIRST leg's program (`pool_ref`), not the last leg's.
fn solana_fixture() -> Fixture {
    let sol_in = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let sol_mid = AssetId::new(ChainId::Solana, "mid-mint-p39").unwrap();
    let sol_out = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();

    let mut intent = intent();
    intent.chain = ChainId::Solana;
    intent.token_in = sol_in.clone();
    intent.token_out = sol_out.clone();

    let route = RoutePlan {
        legs: vec![
            RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "program-first".to_string(),
                token_in: sol_in.clone(),
                token_out: sol_mid.clone(),
                amount_in: AtomicAmount::new(1_000),
                expected_amount_out: AtomicAmount::new(500),
            },
            RouteLeg {
                venue: "uniswap_v3".to_string(),
                pool_ref: "program-last".to_string(),
                token_in: sol_mid,
                token_out: sol_out.clone(),
                amount_in: AtomicAmount::new(500),
                expected_amount_out: AtomicAmount::new(250),
            },
        ],
        expected_net_output: amount(&sol_out, 240),
        state: freshness(),
    };

    let mut solana_limits = limits();
    solana_limits.allowed_chains = [ChainId::Solana].into_iter().collect();
    let approval = approval_for_with_limits(&intent, NOW, solana_limits.clone());

    let allowed_programs = ["program-first", "program-last", "router-program"]
        .into_iter()
        .map(str::to_string)
        .collect();

    Fixture {
        intent,
        approval: Some(approval),
        limits: solana_limits,
        allowed_programs,
        trading_enabled: true,
        freshness_policy: FreshnessPolicy::default(),
        approved_route_binding: RouteBinding::from_route(&route),
        route,
        net_delta: NetDelta {
            token_in: sol_in.clone(),
            token_out: sol_out.clone(),
            net_input: amount(&sol_in, 1_000),
            gross_output: amount(&sol_out, 250),
            net_output: amount(&sol_out, 240),
            dex_fee: Some(amount(&sol_in, 3)),
            tax_cost: Some(amount(&sol_out, 10)),
        },
        basis_assessment: TaxAssessment::new(
            sol_out.clone(),
            ChainId::Solana,
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
        ),
        tax_observation: Some(TaxObservation {
            chain: ChainId::Solana,
            token: sol_out.clone(),
            pool_ref: "program-last".to_string(),
            router_ref: "router-program".to_string(),
            wallet_ref: wallet_ref(),
            amount: AtomicAmount::new(1_000),
            block_or_slot: 1,
            buy_tax: Bps::new(400).unwrap(),
            sell_tax: Bps::new(0).unwrap(),
            buy_succeeds: true,
            sell_succeeds: true,
            sellable: true,
            confidence: Bps::new(9_000).unwrap(),
            observed_at_ms: OBSERVED,
            expires_at_ms: NOW + 60_000,
        }),
        min_out: amount(&sol_out, 240),
        wallet_balance: WalletBalance {
            wallet_ref: wallet_ref(),
            chain: ChainId::Solana,
            asset: sol_in.clone(),
            available: AtomicAmount::new(1_000),
            freshness: freshness(),
        },
        allowance: AllowanceObservation::Required(AllowanceState {
            wallet_ref: wallet_ref(),
            chain: ChainId::Solana,
            asset: sol_in,
            spender_ref: "program-first".to_string(),
            amount: AtomicAmount::new(1_000),
            freshness: freshness(),
        }),
    }
}

fn expect_valid(outcome: RevalidationOutcome) -> ValidatedExecutionPreview {
    match outcome {
        RevalidationOutcome::Valid(preview) => preview,
        other => panic!("expected Valid, got {other:?}"),
    }
}

fn expect_requote(outcome: RevalidationOutcome, reason: RevalidationReason) {
    assert_eq!(outcome, RevalidationOutcome::AbortRequote(reason));
}

fn expect_final(outcome: RevalidationOutcome, reason: RevalidationReason) {
    assert_eq!(outcome, RevalidationOutcome::AbortFinal(reason));
}

#[test]
fn valid_happy_path_wraps_domain_validated_preview() {
    let preview = expect_valid(Fixture::new().run());
    assert_eq!(
        preview.preview().simulated_net_input,
        amount(&usdc(), 1_000)
    );
    assert_eq!(
        preview.preview().simulated_net_output,
        amount(&token(), 240)
    );
    assert_eq!(preview.preview().gross_output, amount(&token(), 250));
}

#[test]
fn insufficient_balance_boundary_is_requote() {
    let mut below = Fixture::new();
    below.wallet_balance.available = AtomicAmount::new(999);
    expect_requote(below.run(), RevalidationReason::InsufficientBalance);

    // Boundary equality is Valid.
    expect_valid(Fixture::new().run());
}

#[test]
fn allowance_boundary_and_spender_binding() {
    let mut sufficient = Fixture::new();
    sufficient.allowance = allowance(1_000);
    expect_valid(sufficient.run());

    let mut insufficient = Fixture::new();
    insufficient.allowance = allowance(999);
    expect_requote(
        insufficient.run(),
        RevalidationReason::InsufficientAllowance,
    );

    let mut wrong_spender = Fixture::new();
    wrong_spender.allowance = allowance(1_000);
    if let AllowanceObservation::Required(state) = &mut wrong_spender.allowance {
        state.spender_ref = "0xattacker".to_string();
    }
    expect_final(
        wrong_spender.run(),
        RevalidationReason::AllowanceSpenderMismatch,
    );
}

#[test]
fn route_age_freshness_boundaries() {
    let mut boundary = Fixture::new();
    boundary.route.state.observed_at_ms = NOW - 10_000;
    expect_valid(boundary.run());

    let mut stale = Fixture::new();
    stale.route.state.observed_at_ms = NOW - 10_001;
    expect_requote(stale.run(), RevalidationReason::StaleState);
}

#[test]
fn zero_route_sequence_requires_resync() {
    let mut fixture = Fixture::new();
    fixture.route.state.sequence = Sequence(0);
    expect_final(fixture.run(), RevalidationReason::ResyncRequired);
}

#[test]
fn stale_tax_observation_is_requote() {
    let mut fixture = Fixture::new();
    fixture.tax_observation.as_mut().unwrap().observed_at_ms = NOW - 20_000;
    expect_requote(fixture.run(), RevalidationReason::TaxObservationStale);
}

#[test]
fn changed_fresh_buy_tax_is_requote() {
    let mut fixture = Fixture::new();
    fixture.tax_observation.as_mut().unwrap().buy_tax = Bps::new(401).unwrap();
    expect_requote(fixture.run(), RevalidationReason::TaxChanged);
}

#[test]
fn tax_over_intent_cap_is_final() {
    let mut fixture = Fixture::new();
    fixture.tax_observation.as_mut().unwrap().buy_tax = Bps::new(600).unwrap();
    expect_final(fixture.run(), RevalidationReason::TaxCapExceeded);
}

#[test]
fn non_sellable_token_is_final() {
    let mut fixture = Fixture::new();
    let observation = fixture.tax_observation.as_mut().unwrap();
    observation.sellable = false;
    observation.sell_succeeds = false;
    expect_final(fixture.run(), RevalidationReason::TokenNotSellable);
}

#[test]
fn min_out_boundary() {
    let mut not_met = Fixture::new();
    not_met.min_out = amount(&token(), 241);
    expect_requote(not_met.run(), RevalidationReason::MinOutNotMet);

    // Boundary equality is Valid.
    expect_valid(Fixture::new().run());
}

#[test]
fn slippage_floor_uses_wide_product_comparison() {
    // Wide boundary directly through the exact 256-bit helper: no overflow.
    assert_eq!(
        cmp_u128_products(u128::MAX - 1, 10_000, u128::MAX, 9_999),
        Ordering::Greater
    );

    // A min_out below the intent slippage floor is a policy violation.
    let mut permissive = Fixture::new();
    permissive.min_out = amount(&token(), 200);
    expect_final(permissive.run(), RevalidationReason::AmountPolicyViolation);
}

#[test]
fn route_pool_drift_is_requote() {
    let mut fixture = Fixture::new();
    fixture.route.legs[0].pool_ref = "0xother-pool".to_string();
    expect_requote(fixture.run(), RevalidationReason::SelectedRouteMismatch);
}

#[test]
fn route_amount_only_change_stays_valid() {
    let mut fixture = Fixture::new();
    fixture.route.legs[0].amount_in = AtomicAmount::new(999);
    expect_valid(fixture.run());
}

#[test]
fn tax_observation_wallet_mismatch_is_recipient_mismatch() {
    let mut fixture = Fixture::new();
    fixture.tax_observation.as_mut().unwrap().wallet_ref =
        WalletRef::new("wallet-attacker").unwrap();
    expect_final(fixture.run(), RevalidationReason::RecipientMismatch);
}

#[test]
fn unknown_venue_is_final() {
    let mut fixture = Fixture::new();
    fixture.route.legs[0].venue = "unknown_venue".to_string();
    expect_final(fixture.run(), RevalidationReason::VenueNotAllowlisted);
}

#[test]
fn unlisted_solana_program_is_final() {
    let solana_in = AssetId::new(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
    )
    .unwrap();
    let solana_out = AssetId::new(
        ChainId::Solana,
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    )
    .unwrap();
    let mut fixture = Fixture::new();
    fixture.route.legs[0].token_in = solana_in;
    fixture.route.legs[0].token_out = solana_out;
    fixture.route.legs[0].pool_ref = "unlisted-solana-program".to_string();
    expect_final(fixture.run(), RevalidationReason::ProgramNotAllowlisted);
}

#[test]
fn all_or_nothing_partial_amount_is_policy_violation() {
    let mut fixture = Fixture::new();
    fixture.intent.allow_partial_fill = false;
    fixture.route.legs[0].amount_in = AtomicAmount::new(999);
    fixture.net_delta.net_input = amount(&usdc(), 999);
    expect_requote(fixture.run(), RevalidationReason::AmountPolicyViolation);
}

#[test]
fn trading_disabled_is_final() {
    let mut fixture = Fixture::new();
    fixture.trading_enabled = false;
    expect_final(fixture.run(), RevalidationReason::TradingDisabled);
}

#[test]
fn approval_intent_binding_mismatch_is_final() {
    let mut fixture = Fixture::new();
    let mut other = fixture.intent.clone();
    other.id = IntentId::new("other-intent").unwrap();
    fixture.approval = Some(approval_for(&other, NOW));
    expect_final(fixture.run(), RevalidationReason::ApprovalBindingMismatch);
}

#[test]
fn approval_expired_at_now_is_final() {
    let mut fixture = Fixture::new();
    fixture.intent.expiry_ms = Some(NOW);
    // Approval minted before expiry, so the binding itself is valid.
    fixture.approval = Some(approval_for(&fixture.intent, NOW - 1_000));
    expect_final(fixture.run(), RevalidationReason::PolicyExpired);
}

#[test]
fn approval_missing_is_final() {
    let mut fixture = Fixture::new();
    fixture.approval = None;
    expect_final(fixture.run(), RevalidationReason::ApprovalMissing);
}

#[test]
fn missing_tax_observation_is_final() {
    let mut fixture = Fixture::new();
    fixture.tax_observation = None;
    expect_final(fixture.run(), RevalidationReason::MissingTaxObservation);
}

#[test]
fn inconsistent_net_delta_fails_closed() {
    // Same-asset pair makes the delta structurally inconsistent; the bridge's
    // `NetDelta::validate` must reject it.
    let mut fixture = Fixture::new();
    fixture.net_delta.token_out = usdc();
    expect_final(fixture.run(), RevalidationReason::NetDeltaInconsistent);
}

#[test]
fn valid_requires_bridge_domain_validation() {
    // A route whose expected output disagrees with the delta must never be Valid,
    // proving success flows through the locked canonical domain validation.
    let mut fixture = Fixture::new();
    fixture.route.expected_net_output = amount(&token(), 241);
    expect_final(fixture.run(), RevalidationReason::DomainInvalid);

    // Control: the unmodified fixture is Valid.
    expect_valid(Fixture::new().run());
}

#[test]
fn evm_router_ref_must_bind_approved_first_leg_venue() {
    // The EVM router ref is the allowance spender: it must equal the approved
    // route's first-leg venue, so an attacker-controlled value fails closed.
    let mut fixture = Fixture::new();
    fixture.tax_observation.as_mut().unwrap().router_ref = "0xattacker".to_string();
    expect_final(fixture.run(), RevalidationReason::AllowanceSpenderMismatch);
}

#[test]
fn solana_spender_is_first_leg_pool_not_last_leg() {
    // The program that pulls `token_in` is the FIRST leg.
    expect_valid(solana_fixture().run());

    let mut last_leg = solana_fixture();
    if let AllowanceObservation::Required(state) = &mut last_leg.allowance {
        state.spender_ref = "program-last".to_string();
    }
    expect_final(last_leg.run(), RevalidationReason::AllowanceSpenderMismatch);
}

#[test]
fn wallet_freshness_boundary_is_valid_and_stale_is_requote() {
    // Age exactly 10000 with the default 10s policy is still Fresh.
    let mut boundary = Fixture::new();
    boundary.wallet_balance.freshness.observed_at_ms = NOW - 10_000;
    expect_valid(boundary.run());

    // One millisecond past the boundary is Stale and only requoteable.
    let mut stale = Fixture::new();
    stale.wallet_balance.freshness.observed_at_ms = NOW - 10_001;
    expect_requote(stale.run(), RevalidationReason::StaleState);
}

#[test]
fn allowance_freshness_stale_is_requote() {
    let mut fixture = Fixture::new();
    fixture.allowance = allowance(1_000);
    if let AllowanceObservation::Required(state) = &mut fixture.allowance {
        state.freshness.observed_at_ms = NOW - 10_001;
    }
    expect_requote(fixture.run(), RevalidationReason::StaleState);
}

#[test]
fn zero_wallet_sequence_requires_resync() {
    let mut fixture = Fixture::new();
    fixture.wallet_balance.freshness.sequence = Sequence(0);
    expect_final(fixture.run(), RevalidationReason::ResyncRequired);
}

#[test]
fn zero_allowance_sequence_requires_resync() {
    let mut fixture = Fixture::new();
    fixture.allowance = allowance(1_000);
    if let AllowanceObservation::Required(state) = &mut fixture.allowance {
        state.freshness.sequence = Sequence(0);
    }
    expect_final(fixture.run(), RevalidationReason::ResyncRequired);
}

#[test]
fn caller_freshness_policy_applies_to_route_state() {
    // Under the default 10s policy this route (age 1000) is Fresh and Valid;
    // a tighter caller policy must be honored by the route pre-check.
    let mut tight = Fixture::new();
    tight.wallet_balance.freshness.observed_at_ms = NOW;
    tight.freshness_policy = FreshnessPolicy::new(500, 2_000).unwrap();
    expect_requote(tight.run(), RevalidationReason::StaleState);
}

#[test]
fn approval_wallet_binding_mismatch_is_final() {
    let mut fixture = Fixture::new();
    let mut other = fixture.intent.clone();
    other.wallet_ref = WalletRef::new("wallet-attacker").unwrap();
    fixture.approval = Some(approval_for(&other, NOW));
    expect_final(fixture.run(), RevalidationReason::ApprovalBindingMismatch);
}

#[test]
fn approval_idempotency_binding_mismatch_is_final() {
    let mut fixture = Fixture::new();
    let mut other = fixture.intent.clone();
    other.idempotency_key = IdempotencyKey::new("idem-attacker").unwrap();
    fixture.approval = Some(approval_for(&other, NOW));
    expect_final(fixture.run(), RevalidationReason::ApprovalBindingMismatch);
}

#[test]
fn approval_chain_binding_mismatch_is_final() {
    let mut fixture = Fixture::new();
    let mut other = fixture.intent.clone();
    other.chain = ChainId::BnbChain;
    other.token_in = AssetId::new(ChainId::BnbChain, "0xbnb-in-p39").unwrap();
    other.token_out = AssetId::new(ChainId::BnbChain, "0xbnb-out-p39").unwrap();
    let mut bnb_limits = limits();
    bnb_limits.allowed_chains.insert(ChainId::BnbChain);
    fixture.approval = Some(approval_for_with_limits(&other, NOW, bnb_limits));
    expect_final(fixture.run(), RevalidationReason::ApprovalBindingMismatch);
}

#[test]
fn min_out_asset_mismatch_is_final() {
    let mut fixture = Fixture::new();
    fixture.min_out = amount(&usdc(), 240);
    expect_final(fixture.run(), RevalidationReason::MinOutNotMet);
}

#[test]
fn valid_outcome_debug_is_redacted() {
    let outcome = Fixture::new().run();
    assert!(matches!(outcome, RevalidationOutcome::Valid(_)));
    let debug = format!("{outcome:?}");
    assert_eq!(debug, "Valid");
    for pattern in [
        "intent-p39",
        "wallet-p39",
        "usdc",
        "token",
        "0x",
        "1000",
        "240",
    ] {
        assert!(
            !debug.contains(pattern),
            "Valid Debug leaked '{pattern}': {debug}"
        );
    }

    // Abort arms still expose only the redacted reason.
    let mut drifted = Fixture::new();
    drifted.route.legs[0].pool_ref = "0xother-pool".to_string();
    let abort = drifted.run();
    assert_eq!(format!("{abort:?}"), "AbortRequote(SelectedRouteMismatch)");
}

#[test]
fn revalidation_reasons_are_payload_free_and_redacted() {
    let reasons = [
        RevalidationReason::TradingDisabled,
        RevalidationReason::ApprovalMissing,
        RevalidationReason::ApprovalBindingMismatch,
        RevalidationReason::PolicyExpired,
        RevalidationReason::RecipientMismatch,
        RevalidationReason::VenueNotAllowlisted,
        RevalidationReason::ProgramNotAllowlisted,
        RevalidationReason::SelectedRouteMismatch,
        RevalidationReason::StateRegression,
        RevalidationReason::StaleState,
        RevalidationReason::ResyncRequired,
        RevalidationReason::TaxObservationStale,
        RevalidationReason::TaxChanged,
        RevalidationReason::TaxCapExceeded,
        RevalidationReason::TokenNotSellable,
        RevalidationReason::MissingTaxObservation,
        RevalidationReason::InsufficientBalance,
        RevalidationReason::InsufficientAllowance,
        RevalidationReason::AllowanceSpenderMismatch,
        RevalidationReason::MissingAllowanceObservation,
        RevalidationReason::MinOutNotMet,
        RevalidationReason::AmountPolicyViolation,
        RevalidationReason::UnsupportedAmountType,
        RevalidationReason::NetDeltaInconsistent,
        RevalidationReason::DomainInvalid,
        RevalidationReason::BridgeInvalid,
    ];

    let forbidden = [
        "0x",
        "So111",
        "EPjFW",
        "wallet",
        "pool",
        "router",
        "secret",
        "credential",
        "password",
        "bearer",
        "payload",
        "endpoint",
        "http://",
        "https://",
    ];

    for reason in reasons {
        let display = reason.to_string();
        let debug = format!("{reason:?}");
        for pattern in forbidden {
            assert!(
                !display.contains(pattern),
                "Display leaked '{pattern}': {display}"
            );
            assert!(
                !debug.contains(pattern),
                "Debug leaked '{pattern}': {debug}"
            );
        }
        assert!(
            !display.chars().any(|c| c.is_ascii_digit()),
            "Display leaked a numeric value: {display}"
        );
        // Payload-free Copy/Eq smoke check.
        let copied = reason;
        assert_eq!(copied, reason);
    }
}
