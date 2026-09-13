//! Gas-aware scoring and deterministic ordering tests.
//!
//! The primary selection key is simulated net output adjusted by an exact,
//! floor-rounded gas conversion. A route with strictly higher gross output can
//! still lose once gas is charged.

mod common;

use common::*;
use market_types::{PoolKindState, PriceRatio};
use routing::{plan_single_path, RoutingError};

fn two_hop_descriptors() -> Vec<routing::PoolDescriptor> {
    vec![
        fresh_descriptor(
            "direct-ac",
            "0xpool-ac",
            PoolKindState::Cpmm(cpmm(usdc(), token2(), 1_000_000, 2_000_000, 30)),
        ),
        fresh_descriptor(
            "uniswap-v2",
            "0xpool-ab",
            PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
        ),
        fresh_descriptor(
            "sushi-v2",
            "0xpool-bc",
            PoolKindState::Cpmm(cpmm(weth(), token2(), 1_000_000, 2_000_000, 30)),
        ),
    ]
}

#[test]
fn without_gas_higher_net_route_wins() {
    let intent = buy(usdc(), token2(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = two_hop_descriptors();
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        2,
        &policy,
        &scoring,
        None,
        None,
        true,
    );
    let decision = plan_single_path(&request).expect("viable routes");
    let selected = decision.selected.as_ref().expect("selected");
    assert_eq!(selected.plan.legs.len(), 2);
    assert_eq!(selected.net_output.amount.get(), 38_608);
}

#[test]
fn gas_makes_higher_gross_route_lose_to_lower_gross_higher_net_route() {
    let intent = buy(usdc(), token2(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = two_hop_descriptors();
    let policy = caller_policy();
    let scoring = scoring();

    let gas = FixedGas {
        asset: native_gas(),
        per_hop: 19_000,
    };
    let price = PriceRatio::new(1, 1).expect("price ratio");
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        2,
        &policy,
        &scoring,
        Some(&gas),
        Some(price),
        true,
    );

    let decision = plan_single_path(&request).expect("viable gas-aware routes");
    let selected = decision.selected.as_ref().expect("selected");

    // The one-hop route has lower gross output but wins after gas.
    assert_eq!(selected.plan.legs.len(), 1);
    assert_eq!(selected.gross_output.amount.get(), 19_743);
    assert_eq!(selected.net_output.amount.get(), 19_743);

    // The losing candidate genuinely had higher gross (and higher net) output.
    let losing = decision
        .candidates
        .iter()
        .find(|candidate| candidate.quote.plan.legs.len() == 2)
        .expect("two-hop candidate survived verification");
    assert!(losing.quote.gross_output.amount.get() > selected.gross_output.amount.get());
    assert!(losing.score.gas_cost.is_some());
    assert_eq!(
        losing.score.gas_cost.as_ref().map(|gas| gas.amount.get()),
        Some(38_000)
    );
    let selected_score = decision
        .candidates
        .first()
        .map(|candidate| candidate.score.clone())
        .expect("first candidate");
    assert_eq!(
        selected_score.gas_cost.as_ref().map(|gas| gas.amount.get()),
        Some(19_000)
    );
    assert_eq!(selected_score.simulated_net_output.amount.get(), 19_743);
}

#[test]
fn score_populates_all_r1_fields() {
    let observed = NOW_MS - 3_000;
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
        observed,
        7,
        None,
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let gas = FixedGas {
        asset: native_gas(),
        per_hop: 100,
    };
    let price = PriceRatio::new(1, 1).expect("price ratio");
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        1,
        &policy,
        &scoring,
        Some(&gas),
        Some(price),
        true,
    );
    let decision = plan_single_path(&request).expect("viable route");
    let score = &decision.candidates.first().expect("candidate").score;
    assert_eq!(score.gross_output.amount.get(), 19_743);
    assert_eq!(score.simulated_net_output.amount.get(), 19_743);
    assert!(score.tax_cost.is_none());
    assert_eq!(score.dex_fee.as_ref().map(|fee| fee.amount.get()), Some(30));
    assert!(score.provider_fee.is_none());
    let gas_cost = score.gas_cost.as_ref().expect("gas cost");
    assert_eq!(gas_cost.amount.get(), 100);
    assert_eq!(gas_cost.asset, native_gas());
    assert_eq!(score.price_impact.get(), 98);
    assert_eq!(score.expected_slippage.get(), 20);
    assert_eq!(score.mev_risk.get(), 5);
    assert_eq!(score.failure_probability.get(), 1);
    assert_eq!(score.state_age_ms, 3_000);
    assert_eq!(score.provider_reliability.get(), 9_900);
    assert_eq!(score.latency_ms, 42);
}

#[test]
fn gas_chain_mismatch_fails_closed() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let gas = FixedGas {
        asset: solana_asset("So11111111111111111111111111111111111111112"),
        per_hop: 1,
    };
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        1,
        &policy,
        &scoring,
        Some(&gas),
        None,
        true,
    );
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::GasChainMismatch)
    );
}

#[test]
fn gas_conversion_overflow_fails_closed() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let gas = FixedGas {
        asset: native_gas(),
        per_hop: u128::MAX,
    };
    let price = PriceRatio::new(u128::MAX, 1).expect("price ratio");
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        1,
        &policy,
        &scoring,
        Some(&gas),
        Some(price),
        true,
    );
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::GasConversionFailed)
    );
}

#[test]
fn higher_net_orders_first_deterministically() {
    let intent = buy(usdc(), token2(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = two_hop_descriptors();
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        2,
        &policy,
        &scoring,
        None,
        None,
        true,
    );
    let decision = plan_single_path(&request).expect("viable routes");
    assert!(decision.candidates.len() >= 2);
    let first = decision.candidates.first().expect("first");
    let second = decision.candidates.get(1).expect("second");
    assert!(
        first.score.simulated_net_output.amount.get()
            >= second.score.simulated_net_output.amount.get()
    );
    assert_eq!(
        first.quote.net_output.amount.get(),
        decision
            .selected
            .as_ref()
            .expect("selected")
            .net_output
            .amount
            .get()
    );
}

#[test]
fn equal_economics_tie_breaks_on_canonical_leg_key() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let state = PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30));
    let descriptors = vec![
        fresh_descriptor("zvenue", "0xpool-z", state.clone()),
        fresh_descriptor("avenue", "0xpool-a", state),
    ];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        10_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
        true,
    );
    let decision = plan_single_path(&request).expect("viable routes");
    assert_eq!(decision.candidates.len(), 2);
    let first = decision.candidates.first().expect("first");
    assert_eq!(first.quote.plan.legs[0].venue, "avenue");
    assert_eq!(first.quote.plan.legs[0].pool_ref, "0xpool-a");
    assert_eq!(
        first.score.simulated_net_output,
        decision
            .candidates
            .get(1)
            .expect("second")
            .score
            .simulated_net_output
    );
}
