//! Tax projection tests: the router must delegate bps arithmetic to `tax-engine`
//! and reproduce the same net delta as the landed single-hop constructors.

mod common;

use common::*;
use domain::TradeSide;
use execution_preview::NetDelta;
use market_types::{AtomicAmount, PoolKindState};
use routing::plan_single_path;
use simulation::{
    simulate_tax_aware_cpmm_buy_exact_input, simulate_tax_aware_cpmm_sell_exact_input,
    CpmmExactInputRequest,
};

#[test]
fn direct_buy_with_tax_matches_pinned_vector_and_bridge_constructor() {
    let pool = cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30);
    let intent = buy(usdc(), weth(), 10_000);
    let tax = assessment(weth(), 500, 500);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(pool.clone()),
    )];
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
    );

    let decision = plan_single_path(&request).expect("viable buy");
    let selected = decision.selected.as_ref().expect("selected");
    assert_eq!(selected.gross_output.amount.get(), 19_743);
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.amount.get()),
        Some(987)
    );
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.asset.clone()),
        Some(weth())
    );
    assert_eq!(selected.net_output.amount.get(), 18_756);
    assert_eq!(
        selected.net_output.amount.get()
            + selected
                .tax_cost
                .as_ref()
                .map(|t| t.amount.get())
                .unwrap_or(0),
        selected.gross_output.amount.get()
    );

    let quote_request =
        CpmmExactInputRequest::new_directed(usdc(), AtomicAmount::new(10_000), weth());
    let expected_quote =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &quote_request, &tax).expect("quote");
    let expected_delta = NetDelta::from_tax_aware_cpmm_buy(&expected_quote).expect("delta");
    assert_eq!(selected.net_delta, expected_delta);
}

#[test]
fn direct_sell_with_tax_matches_pinned_vector_and_bridge_constructor() {
    let pool = cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30);
    let intent = sell(weth(), usdc(), 20_000);
    let tax = assessment(weth(), 0, 500);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(pool.clone()),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        20_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );

    let decision = plan_single_path(&request).expect("viable sell");
    let selected = decision.selected.as_ref().expect("selected");
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.amount.get()),
        Some(1_000)
    );
    assert_eq!(selected.gross_output.amount.get(), 9_382);
    assert_eq!(selected.net_output.amount.get(), 9_382);
    assert_eq!(selected.net_delta.net_input.amount.get(), 20_000);
    assert_eq!(selected.plan.legs[0].amount_in.get(), 19_000);
    // Sell side: net output equals gross output by construction.
    assert_eq!(selected.net_output.amount, selected.gross_output.amount);

    let quote_request =
        CpmmExactInputRequest::new_directed(weth(), AtomicAmount::new(20_000), usdc());
    let expected_quote =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &quote_request, &tax).expect("quote");
    let expected_delta = NetDelta::from_tax_aware_cpmm_sell(&expected_quote).expect("delta");
    assert_eq!(selected.net_delta, expected_delta);
}

#[test]
fn zero_fee_pool_yields_none_never_some_zero() {
    let intent = intent_with_risk(TradeSide::Buy, usdc(), weth(), 1_000, risk(0));
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "meteora-dlmm",
        "0xpool-bin",
        PoolKindState::Bin(bin(usdc(), weth())),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        1_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );

    let decision = plan_single_path(&request).expect("viable zero-fee route");
    let selected = decision.selected.as_ref().expect("selected");
    assert!(selected.hop_quotes[0].fee.is_none());
    assert!(selected.net_delta.dex_fee.is_none());
    assert!(selected.tax_cost.is_none());
    assert_eq!(selected.net_output.amount, selected.gross_output.amount);
}

#[test]
fn zero_tax_buy_has_no_tax_cost_and_exact_conservation() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
    )];
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
    );
    let decision = plan_single_path(&request).expect("viable route");
    let selected = decision.selected.as_ref().expect("selected");
    assert!(selected.tax_cost.is_none());
    assert!(selected.net_delta.tax_cost.is_none());
    assert_eq!(selected.net_output.amount.get(), 19_743);
}
