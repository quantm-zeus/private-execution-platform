//! Focused tests for the P84B provider-route composition.
//!
//! Every case is a pure, deterministic composition over caller-supplied
//! provider economics; no network or provider client is involved.

mod common;

use std::sync::OnceLock;

use common::{assessment, buy, caller_policy, scoring, sell, usdc, weth, NOW_MS};
use market_types::{AtomicAmount, Bps, FreshnessStatus};
use routing::{quote_provider_route, PoolRefLabel, ProviderRouteInput, RoutingError, VenueLabel};

fn venue() -> &'static VenueLabel {
    static VENUE: OnceLock<VenueLabel> = OnceLock::new();
    VENUE.get_or_init(|| VenueLabel::new("okx").expect("venue"))
}

fn pool_ref() -> &'static PoolRefLabel {
    static POOL_REF: OnceLock<PoolRefLabel> = OnceLock::new();
    POOL_REF.get_or_init(|| PoolRefLabel::new("okx").expect("pool ref"))
}

fn input<'a>(
    intent: &'a domain::TradeIntent,
    amount_in: u128,
    provider_out: u128,
    assessment: &'a tax_engine::TaxAssessment,
    policy: &'a market_types::FreshnessPolicy,
    scoring: &'a routing::ScoringInputs,
) -> ProviderRouteInput<'a> {
    ProviderRouteInput {
        intent,
        amount_in: AtomicAmount::new(amount_in),
        provider_gross_output: AtomicAmount::new(provider_out),
        assessment,
        freshness_policy: policy,
        now_ms: NOW_MS,
        venue: venue(),
        pool_ref: pool_ref(),
        scoring,
        price_impact_bps: Bps::new(0).expect("bps"),
    }
}

#[test]
fn buy_zero_tax_composes_exact_net_delta() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = assessment(weth(), 0, 0);
    let scoring = scoring();
    let policy = caller_policy();
    let composed = quote_provider_route(&input(
        &intent,
        1_000,
        2_500,
        &assessment,
        &policy,
        &scoring,
    ))
    .expect("composed");

    let delta = &composed.quote.net_delta;
    assert_eq!(delta.net_input.amount.get(), 1_000);
    assert_eq!(delta.gross_output.amount.get(), 2_500);
    assert_eq!(delta.net_output.amount.get(), 2_500);
    assert!(delta.tax_cost.is_none());
    assert!(delta.dex_fee.is_none());
    assert_eq!(composed.quote.plan.legs.len(), 1);
    assert_eq!(composed.quote.plan.legs[0].amount_in.get(), 1_000);
    assert_eq!(composed.quote.plan.legs[0].expected_amount_out.get(), 2_500);
    assert_eq!(composed.quote.plan.expected_net_output.amount.get(), 2_500);
    assert_eq!(composed.score.simulated_net_output.amount.get(), 2_500);
    assert_eq!(composed.quote.route_impact_bps, None);
}

#[test]
fn buy_output_tax_is_applied_and_validated() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = assessment(weth(), 100, 0);
    let scoring = scoring();
    let policy = caller_policy();
    let composed = quote_provider_route(&input(
        &intent,
        1_000,
        2_500,
        &assessment,
        &policy,
        &scoring,
    ))
    .expect("composed");

    // floor(2500 * 100 / 10_000) = 25.
    assert_eq!(composed.quote.gross_output.amount.get(), 2_500);
    assert_eq!(composed.quote.net_output.amount.get(), 2_475);
    let tax = composed.quote.tax_cost.as_ref().expect("tax");
    assert_eq!(tax.asset, weth());
    assert_eq!(tax.amount.get(), 25);
    assert_eq!(composed.quote.plan.expected_net_output.amount.get(), 2_475);
}

#[test]
fn sell_input_tax_is_applied_before_the_provider_swap() {
    let intent = sell(weth(), usdc(), 1_000);
    let assessment = assessment(weth(), 0, 200);
    let scoring = scoring();
    let policy = caller_policy();
    let composed = quote_provider_route(&input(
        &intent,
        1_000,
        2_450,
        &assessment,
        &policy,
        &scoring,
    ))
    .expect("composed");

    // floor(1000 * 200 / 10_000) = 20; the provider swaps the 980 transferable.
    let tax = composed.quote.tax_cost.as_ref().expect("tax");
    assert_eq!(tax.asset, weth());
    assert_eq!(tax.amount.get(), 20);
    assert_eq!(composed.quote.net_delta.net_input.amount.get(), 1_000);
    assert_eq!(composed.quote.plan.legs[0].amount_in.get(), 980);
    assert_eq!(composed.quote.net_output.amount.get(), 2_450);
}

#[test]
fn zero_provider_output_fails_closed() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = assessment(weth(), 0, 0);
    let scoring = scoring();
    let policy = caller_policy();
    assert_eq!(
        quote_provider_route(&input(&intent, 1_000, 0, &assessment, &policy, &scoring)).err(),
        Some(RoutingError::ZeroHopOutput)
    );
}

#[test]
fn tax_cap_exceeded_is_a_bridge_rejection() {
    let mut risk = common::risk(500);
    risk.max_buy_tax = Bps::new(0).expect("bps");
    let intent = common::intent_with_risk(domain::TradeSide::Buy, usdc(), weth(), 1_000, risk);
    let assessment = assessment(weth(), 100, 0);
    let scoring = scoring();
    let policy = caller_policy();
    match quote_provider_route(&input(
        &intent,
        1_000,
        2_500,
        &assessment,
        &policy,
        &scoring,
    )) {
        Err(RoutingError::SelectedRejected(_)) => {}
        other => panic!("expected SelectedRejected, got {other:?}"),
    }
}

#[test]
fn stale_assessment_fails_closed() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = common::assessment_at(
        chain_types::ChainId::Base,
        weth(),
        0,
        0,
        NOW_MS,
        FreshnessStatus::Stale,
    );
    let scoring = scoring();
    let policy = caller_policy();
    assert_eq!(
        quote_provider_route(&input(
            &intent,
            1_000,
            2_500,
            &assessment,
            &policy,
            &scoring
        ))
        .err(),
        Some(RoutingError::TaxAssessmentNotFresh)
    );
}

#[test]
fn mismatched_assessment_asset_fails_closed() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = assessment(usdc(), 0, 0);
    let scoring = scoring();
    let policy = caller_policy();
    assert_eq!(
        quote_provider_route(&input(
            &intent,
            1_000,
            2_500,
            &assessment,
            &policy,
            &scoring
        ))
        .err(),
        Some(RoutingError::TaxAssessmentMismatch)
    );
}

#[test]
fn composition_is_deterministic_and_redacted() {
    let intent = buy(usdc(), weth(), 1_000);
    let assessment = assessment(weth(), 100, 0);
    let scoring = scoring();
    let policy = caller_policy();
    let first = quote_provider_route(&input(
        &intent,
        1_000,
        2_500,
        &assessment,
        &policy,
        &scoring,
    ))
    .expect("first");
    let second = quote_provider_route(&input(
        &intent,
        1_000,
        2_500,
        &assessment,
        &policy,
        &scoring,
    ))
    .expect("second");
    assert_eq!(first.quote, second.quote);
    assert_eq!(first.score, second.score);

    // The error surface renders no amounts.
    let error = quote_provider_route(&input(&intent, 1_000, 0, &assessment, &policy, &scoring))
        .expect_err("zero output");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("2500"));
    assert!(!rendered.contains("1000"));
}
