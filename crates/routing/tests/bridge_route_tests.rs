//! R1 pinned bridge/direct route vectors and bounded-enumeration tests.
//!
//! The literal vectors mirror the Phase-4 R1 plan: a direct CPMM buy at
//! `19_743`, and a two-hop `A -> B -> C` route at `37_876`. Both are verified
//! through the public `validate_delta_preview_with_assessment` bridge.

mod common;

use common::*;
use domain::TradeSide;
use execution_preview::validate_delta_preview_with_assessment;
use market_types::{AtomicAmount, PoolKindState};
use routing::{enumerate_candidates, plan_single_path, PoolKindClass, MAX_ROUTE_CANDIDATES};

fn pool_ab() -> PoolKindState {
    PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30))
}

fn pool_bc() -> PoolKindState {
    PoolKindState::Cpmm(cpmm(weth(), token2(), 500_000, 1_000_000, 30))
}

#[test]
fn direct_cpmm_buy_is_pinned_and_passes_bridge() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab())];
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

    let decision = plan_single_path(&request).expect("viable direct route");
    assert!(!decision.truncated);
    let selected = decision.selected.as_ref().expect("selected route");
    assert_eq!(selected.net_output.amount.get(), 19_743);
    assert_eq!(selected.gross_output.amount.get(), 19_743);
    assert_eq!(selected.plan.legs.len(), 1);
    assert_eq!(selected.plan.legs[0].amount_in.get(), 10_000);
    assert_eq!(selected.plan.legs[0].expected_amount_out.get(), 19_743);
    assert_eq!(
        selected
            .net_delta
            .dex_fee
            .as_ref()
            .map(|fee| fee.amount.get()),
        Some(30)
    );
    assert_eq!(
        selected
            .net_delta
            .dex_fee
            .as_ref()
            .map(|fee| fee.asset.clone()),
        Some(usdc())
    );
    assert_eq!(
        selected.route_impact_bps.map(|impact| impact.get()),
        Some(98)
    );
    assert!(selected.net_delta.tax_cost.is_none());

    let validated = validate_delta_preview_with_assessment(
        &intent,
        &selected.plan,
        &selected.net_delta,
        &tax,
        NOW_MS,
    );
    assert!(validated.is_ok());
}

#[test]
fn two_hop_bridge_buy_is_pinned_and_contiguous() {
    let intent = buy(usdc(), token2(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![
        fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab()),
        fresh_descriptor("sushi-v2", "0xpool-bc", pool_bc()),
    ];
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
    );

    let decision = plan_single_path(&request).expect("viable bridge route");
    assert!(!decision.truncated);
    let selected = decision.selected.as_ref().expect("selected route");
    assert_eq!(selected.hop_quotes.len(), 2);
    assert_eq!(selected.net_output.amount.get(), 37_876);
    assert_eq!(selected.gross_output.amount.get(), 37_876);
    assert!(selected.tax_cost.is_none());

    // Contiguous locked legs.
    assert_eq!(selected.plan.legs.len(), 2);
    assert_eq!(selected.plan.legs[0].token_in, usdc());
    assert_eq!(selected.plan.legs[0].token_out, weth());
    assert_eq!(selected.plan.legs[1].token_in, weth());
    assert_eq!(selected.plan.legs[1].token_out, token2());
    assert_eq!(selected.plan.legs[0].amount_in.get(), 10_000);
    assert_eq!(selected.plan.legs[0].expected_amount_out.get(), 19_743);
    assert_eq!(selected.plan.legs[1].amount_in.get(), 19_743);
    assert_eq!(selected.plan.legs[1].expected_amount_out.get(), 37_876);
    assert_eq!(selected.plan.expected_net_output.amount.get(), 37_876);

    // Multi-hop fees cannot be represented in the single-asset delta: detail
    // stays in the hop quotes.
    assert!(selected.net_delta.dex_fee.is_none());
    assert_eq!(
        selected.hop_quotes[0]
            .fee
            .as_ref()
            .map(|fee| fee.amount.get()),
        Some(30)
    );
    assert_eq!(
        selected.hop_quotes[1]
            .fee
            .as_ref()
            .map(|fee| fee.amount.get()),
        Some(59)
    );
    assert_eq!(
        selected.hop_quotes[1]
            .fee
            .as_ref()
            .map(|fee| fee.asset.clone()),
        Some(weth())
    );

    let validated = validate_delta_preview_with_assessment(
        &intent,
        &selected.plan,
        &selected.net_delta,
        &tax,
        NOW_MS,
    );
    assert!(validated.is_ok());
}

#[test]
fn two_hop_bridge_buy_with_tax_matches_hand_derived_vector() {
    // V3 uses a deeper B->C pool: R_weth = 2_000_000, R_token2 = 1_000_000.
    let intent = buy(usdc(), token2(), 10_000);
    let tax = assessment(token2(), 500, 500);
    let descriptors = vec![
        fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab()),
        fresh_descriptor(
            "sushi-v2",
            "0xpool-bc-deep",
            PoolKindState::Cpmm(cpmm(weth(), token2(), 2_000_000, 1_000_000, 30)),
        ),
    ];
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
    );

    let decision = plan_single_path(&request).expect("viable taxed bridge route");
    let selected = decision.selected.as_ref().expect("selected route");
    assert_eq!(selected.gross_output.amount.get(), 9_746);
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.amount.get()),
        Some(487)
    );
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.asset.clone()),
        Some(token2())
    );
    assert_eq!(selected.net_output.amount.get(), 9_259);
    assert_eq!(selected.plan.expected_net_output.amount.get(), 9_259);
    assert!(validate_delta_preview_with_assessment(
        &intent,
        &selected.plan,
        &selected.net_delta,
        &tax,
        NOW_MS,
    )
    .is_ok());
}

#[test]
fn enumeration_is_bounded_and_truncation_is_flagged() {
    // 100 distinct direct pools exceed MAX_ROUTE_CANDIDATES (64).
    let state: Vec<routing::PoolDescriptor> = (0..100)
        .map(|index| {
            let pool_ref = format!("0xpool{index:03}");
            fresh_descriptor("uniswap-v2", &pool_ref, pool_ab())
        })
        .collect();

    let intent = buy(usdc(), weth(), 10_000);
    let enumerated = enumerate_candidates(&intent, 1, &state).expect("bounded enumeration");
    assert!(enumerated.truncated);
    assert_eq!(enumerated.paths.len(), MAX_ROUTE_CANDIDATES);
    // Each candidate is one hop, so bounded simulation work is at most the cap.
    let total_hops: usize = enumerated.paths.iter().map(|path| path.legs.len()).sum();
    assert!(total_hops <= MAX_ROUTE_CANDIDATES);

    // The orchestrator simulates exactly the enumerated candidates, no more: the
    // surviving candidate count cannot exceed the hard cap even for 100 pools.
    let tax = zero_tax_for(&intent);
    let policy = caller_policy();
    let scoring = scoring();
    let planned = plan_single_path(&request(
        &intent, &state, 10_000, &tax, 1, &policy, &scoring, None, None,
    ))
    .expect("bounded planning");
    assert!(planned.truncated);
    assert!(planned.candidates.len() <= MAX_ROUTE_CANDIDATES);
    let simulated_hops: usize = planned
        .candidates
        .iter()
        .map(|candidate| candidate.quote.hop_quotes.len())
        .sum();
    assert!(simulated_hops <= MAX_ROUTE_CANDIDATES);
}

#[test]
fn enumeration_dedupes_same_pool_id() {
    let descriptor = fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab());
    let descriptors = vec![descriptor.clone(), descriptor];
    let intent = buy(usdc(), weth(), 10_000);
    let enumerated = enumerate_candidates(&intent, 2, &descriptors).expect("enumeration");
    assert_eq!(enumerated.paths.len(), 1);
}

#[test]
fn bridge_enumeration_dedupes_conflicting_duplicate_pools() {
    let intent = buy(usdc(), token2(), 10_000);

    // Without bridge-side dedupe these 41x41 descriptors would emit 1_681
    // identical two-hop candidates and truncate at MAX_ROUTE_CANDIDATES.
    let ab = PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30));
    let ab_conflicting = PoolKindState::Cpmm(cpmm(usdc(), weth(), 5_000_000, 2_000_000, 30));
    let bc = PoolKindState::Cpmm(cpmm(weth(), token2(), 500_000, 1_000_000, 30));
    let bc_conflicting = PoolKindState::Cpmm(cpmm(weth(), token2(), 1_000_000, 1_000_000, 30));

    let mut forward = Vec::new();
    for _ in 0..40 {
        forward.push(fresh_descriptor("uniswap-v2", "0xpool-ab", ab.clone()));
        forward.push(fresh_descriptor("sushi-v2", "0xpool-bc", bc.clone()));
    }
    forward.push(fresh_descriptor("uniswap-v2", "0xpool-ab", ab_conflicting));
    forward.push(fresh_descriptor("sushi-v2", "0xpool-bc", bc_conflicting));

    let enumerated = enumerate_candidates(&intent, 2, &forward).expect("enumeration");
    assert!(
        !enumerated.truncated,
        "dedupe must avoid route-cap truncation"
    );
    assert_eq!(enumerated.paths.len(), 1);

    let mut reversed = forward.clone();
    reversed.reverse();

    let tax = zero_tax_for(&intent);
    let policy = caller_policy();
    let scoring = scoring();
    let first = plan_single_path(&request(
        &intent, &forward, 10_000, &tax, 2, &policy, &scoring, None, None,
    ))
    .expect("forward planning");
    let second = plan_single_path(&request(
        &intent, &reversed, 10_000, &tax, 2, &policy, &scoring, None, None,
    ))
    .expect("reversed planning");

    assert!(!first.truncated);
    assert_eq!(first.candidates.len(), 1);
    assert_eq!(first.selected, second.selected);
}

#[test]
fn bridge_paths_never_reuse_a_pool() {
    let descriptors = vec![
        fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab()),
        fresh_descriptor("sushi-v2", "0xpool-bc", pool_bc()),
    ];
    let intent = buy(usdc(), token2(), 10_000);
    let enumerated = enumerate_candidates(&intent, 2, &descriptors).expect("enumeration");
    assert!(!enumerated.paths.is_empty());
    for path in &enumerated.paths {
        let mut used: Vec<usize> = path.legs.iter().map(|leg| leg.descriptor_index).collect();
        used.sort_unstable();
        used.dedup();
        assert_eq!(
            used.len(),
            path.legs.len(),
            "pool reused in a candidate path"
        );
    }
}

#[test]
fn amount_comes_from_request_not_intent() {
    // The request debit is the route's wallet input; the intent cap is enforced
    // independently by the bridge.
    let intent = buy(usdc(), weth(), 20_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor("uniswap-v2", "0xpool-ab", pool_ab())];
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
    let decision = plan_single_path(&request).expect("partial route");
    let selected = decision.selected.as_ref().expect("selected");
    assert_eq!(
        selected.net_delta.net_input.amount,
        AtomicAmount::new(10_000)
    );
    assert_eq!(selected.plan.legs[0].amount_in.get(), 10_000);
}

#[test]
fn sell_route_is_linear_and_uses_input_tax() {
    let intent = sell(weth(), usdc(), 20_000);
    let tax = assessment(weth(), 0, 500);
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
    assert_eq!(
        selected.tax_cost.as_ref().map(|t| t.asset.clone()),
        Some(weth())
    );
    assert_eq!(selected.net_delta.net_input.amount.get(), 20_000);
    assert_eq!(selected.gross_output.amount.get(), 9_382);
    assert_eq!(selected.net_output.amount.get(), 9_382);
    assert_eq!(selected.plan.legs[0].amount_in.get(), 19_000);
    assert_eq!(intent.side, TradeSide::Sell);
}

#[test]
fn clmm_hop_composes_through_public_api_with_override() {
    let intent = buy(usdc(), weth(), 100_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![descriptor(
        "orca",
        "0xpool-clmm",
        PoolKindState::Clmm(clmm(usdc(), weth())),
        NOW_MS,
        1,
        Some(15),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        100_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    let decision = plan_single_path(&request).expect("viable clmm route");
    let selected = decision.selected.as_ref().expect("selected");
    assert_eq!(selected.hop_quotes[0].kind, PoolKindClass::Clmm);
    assert_eq!(
        selected.hop_quotes[0]
            .fee
            .as_ref()
            .map(|fee| fee.amount.get()),
        Some(300)
    );
    assert_eq!(
        selected.route_impact_bps.map(|impact| impact.get()),
        Some(15)
    );
    assert!(selected.net_output.amount.get() > 0);
    assert!(validate_delta_preview_with_assessment(
        &intent,
        &selected.plan,
        &selected.net_delta,
        &tax,
        NOW_MS,
    )
    .is_ok());
}
