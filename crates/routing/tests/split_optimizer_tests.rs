//! P77 split optimizer integration tests.
//!
//! Deterministic fixtures only: no clock, RPC, or randomness.

mod common;

use execution_preview::{validate_split_delta_preview_with_assessment, NetDelta};
use market_types::{AtomicAmount, Bps, PoolKindState, PriceRatio};
use routing::{
    plan_split, PoolDescriptor, RoutingError, SplitConfig, SplitUsdConversion, MAX_SPLIT_LEGS,
};

fn pool(pool_ref: &str, reserve_in: u128, reserve_out: u128, fee_bps: u16) -> PoolDescriptor {
    common::fresh_descriptor(
        "uniswap",
        pool_ref,
        PoolKindState::Cpmm(common::cpmm(
            common::usdc(),
            common::weth(),
            reserve_in,
            reserve_out,
            fee_bps,
        )),
    )
}

fn intent(total: u128) -> domain::TradeIntent {
    // A permissive impact cap keeps the single-path baseline viable so the
    // improvement gate (not the impact cap) decides the test.
    common::intent_with_risk(
        domain::TradeSide::Buy,
        common::usdc(),
        common::weth(),
        total,
        common::risk(10_000),
    )
}

fn config(max_legs: usize, improve_bps: u16, min_leg_output: u128) -> SplitConfig {
    SplitConfig {
        min_split_improvement_bps: Bps::new(improve_bps).expect("bps"),
        min_leg_input: AtomicAmount::new(1),
        min_leg_output: AtomicAmount::new(min_leg_output),
        min_leg_usd_micros: 0,
        usd_conversion: None,
        max_legs,
    }
}

fn request<'a>(
    intent: &'a domain::TradeIntent,
    descriptors: &'a [PoolDescriptor],
    assessment: &'a tax_engine::TaxAssessment,
    policy: &'a market_types::FreshnessPolicy,
    scoring: &'a routing::ScoringInputs,
) -> routing::RouteRequest<'a> {
    common::request(
        intent,
        descriptors,
        intent.amount.get(),
        assessment,
        1,
        policy,
        scoring,
        None,
        None,
    )
}

fn identical_pair() -> [PoolDescriptor; 2] {
    [
        pool("0xpoolA", 1_000_000, 1_000_000, 0),
        pool("0xpoolB", 1_000_000, 1_000_000, 0),
    ]
}

#[test]
fn split_improves_over_single_path() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = identical_pair();
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    let decision = plan_split(&req, &config(2, 10, 1)).expect("plan");
    let selected = decision.selected.expect("split selected");
    assert_eq!(selected.legs.len(), 2);
    assert_eq!(selected.split.legs.len(), 2);
    let total: u128 = selected
        .split
        .legs
        .iter()
        .map(|leg| leg.amount_in.get())
        .sum();
    assert_eq!(total, 100_000);

    let incumbent = decision.incumbent.expect("incumbent");
    assert!(selected.net_output.amount.get() > incumbent.quote.net_output.amount.get());

    let branch_deltas: Vec<NetDelta> = selected
        .legs
        .iter()
        .map(|leg| leg.quote.net_delta.clone())
        .collect();
    assert!(validate_split_delta_preview_with_assessment(
        &intent,
        &selected.split,
        &branch_deltas,
        &assessment,
        common::NOW_MS,
    )
    .is_ok());
    assert!(!decision.candidates.is_empty());
}

#[test]
fn split_gate_rejects_marginal_improvement() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = identical_pair();
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    let decision = plan_split(&req, &config(2, 5_000, 1)).expect("plan");
    assert!(decision.selected.is_none());
    assert!(decision.candidates.is_empty());
    assert!(decision.incumbent.is_some());
}

#[test]
fn split_dust_gates_reject() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = identical_pair();
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    // Minimum leg input larger than half the trade: no two-path allocation.
    let mut cfg = config(2, 10, 1);
    cfg.min_leg_input = AtomicAmount::new(100_000);
    assert!(plan_split(&req, &cfg).expect("plan").selected.is_none());

    // Minimum leg output above any achievable branch output.
    assert!(plan_split(&req, &config(2, 10, 10_000_000))
        .expect("plan")
        .selected
        .is_none());

    // USD gate with a conversion that rounds every branch to zero micros.
    let mut usd = config(2, 10, 1);
    usd.min_leg_usd_micros = 1;
    usd.usd_conversion = Some(SplitUsdConversion {
        input_asset: common::usdc(),
        usd_micros_per_atomic: PriceRatio::new(1, 1_000_000_000).expect("ratio"),
    });
    assert!(plan_split(&req, &usd).expect("plan").selected.is_none());

    // A USD gate without a conversion fails closed.
    let mut missing = config(2, 10, 1);
    missing.min_leg_usd_micros = 1;
    assert_eq!(
        plan_split(&req, &missing),
        Err(RoutingError::InvalidSplitConfig)
    );
}

#[test]
fn split_extends_to_three_legs_when_beneficial() {
    let intent = intent(150_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = [
        pool("0xpoolA", 1_000_000, 1_000_000, 0),
        pool("0xpoolB", 1_000_000, 1_000_000, 0),
        pool("0xpoolC", 1_000_000, 1_000_000, 0),
    ];
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    let decision = plan_split(&req, &config(3, 1, 1)).expect("plan");
    let selected = decision.selected.expect("split selected");
    assert_eq!(selected.legs.len(), 3);
    assert!(selected.legs.len() <= MAX_SPLIT_LEGS);
    let total: u128 = selected
        .split
        .legs
        .iter()
        .map(|leg| leg.amount_in.get())
        .sum();
    assert_eq!(total, 150_000);
}

#[test]
fn split_never_returns_more_than_max_legs() {
    let intent = intent(150_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = [
        pool("0xpoolA", 1_000_000, 1_000_000, 0),
        pool("0xpoolB", 1_000_000, 1_000_000, 0),
        pool("0xpoolC", 1_000_000, 1_000_000, 0),
    ];
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    let decision = plan_split(&req, &config(5, 1, 1)).expect("plan");
    if let Some(selected) = decision.selected {
        assert!(selected.legs.len() <= MAX_SPLIT_LEGS);
        assert!(selected.legs.len() >= 2);
    }
}

#[test]
fn split_deterministic_under_reordering() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    let forward = identical_pair();
    let mut reversed = forward.clone();
    reversed.reverse();
    let policy = common::caller_policy();
    let scoring = common::scoring();

    let first = plan_split(
        &request(&intent, &forward, &assessment, &policy, &scoring),
        &config(2, 10, 1),
    )
    .expect("first");
    let second = plan_split(
        &request(&intent, &reversed, &assessment, &policy, &scoring),
        &config(2, 10, 1),
    )
    .expect("second");

    let a = first.selected.expect("first selected");
    let b = second.selected.expect("second selected");
    assert_eq!(a.canonical_key, b.canonical_key);
    assert_eq!(a.net_output, b.net_output);
}

#[test]
fn split_config_leg_count_is_bounded() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    let descriptors = identical_pair();
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    assert_eq!(
        plan_split(&req, &config(0, 10, 1)),
        Err(RoutingError::UnsupportedSplitLegCount)
    );
    assert_eq!(
        plan_split(&req, &config(1, 10, 1)),
        Err(RoutingError::UnsupportedSplitLegCount)
    );
    assert_eq!(
        plan_split(&req, &config(MAX_SPLIT_LEGS + 1, 10, 1)),
        Err(RoutingError::UnsupportedSplitLegCount)
    );
}

#[test]
fn split_no_viable_route_fails_closed() {
    let intent = intent(100_000);
    let assessment = common::zero_tax_for(&intent);
    // A pool that does not connect `usdc` to `weth`.
    let descriptors = [common::fresh_descriptor(
        "uniswap",
        "0xdisconnected",
        PoolKindState::Cpmm(common::cpmm(
            common::weth(),
            common::another_token(),
            1_000_000,
            1_000_000,
            0,
        )),
    )];
    let policy = common::caller_policy();
    let scoring = common::scoring();
    let req = request(&intent, &descriptors, &assessment, &policy, &scoring);

    assert_eq!(
        plan_split(&req, &config(2, 10, 1)),
        Err(RoutingError::NoViableRoute)
    );
}

#[test]
fn split_conservation_fuzz_over_bounded_reserves() {
    let policy = common::caller_policy();
    let scoring = common::scoring();
    for (reserve_in, reserve_out, total) in [
        (500_000_u128, 2_000_000_u128, 90_000_u128),
        (2_000_000, 500_000, 40_000),
        (1_000_000, 1_000_000, 250_000),
        (5_000_000, 100_000, 30_000),
    ] {
        let intent = intent(total);
        let assessment = common::zero_tax_for(&intent);
        let descriptors = [
            pool("0xpoolA", reserve_in, reserve_out, 30),
            pool("0xpoolB", reserve_in, reserve_out, 30),
        ];
        let req = request(&intent, &descriptors, &assessment, &policy, &scoring);
        let decision = plan_split(&req, &config(3, 1, 1)).expect("plan");
        if let Some(selected) = decision.selected {
            let sum: u128 = selected
                .split
                .legs
                .iter()
                .map(|leg| leg.amount_in.get())
                .sum();
            assert_eq!(sum, total, "conservation must hold for committed splits");
            assert!(selected.legs.len() >= 2);
            assert!(selected.legs.len() <= MAX_SPLIT_LEGS);
            let branch_deltas: Vec<NetDelta> = selected
                .legs
                .iter()
                .map(|leg| leg.quote.net_delta.clone())
                .collect();
            assert!(validate_split_delta_preview_with_assessment(
                &intent,
                &selected.split,
                &branch_deltas,
                &assessment,
                common::NOW_MS,
            )
            .is_ok());
        }
    }
}
