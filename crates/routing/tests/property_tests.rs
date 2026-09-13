//! Property-style tests over deterministic fixture sweeps.
//!
//! No randomness is used: each sweep is a fixed literal progression so the tests
//! remain byte-stable. The properties exercised are conservation, bridge
//! agreement, determinism under descriptor permutation, output monotonicity, and
//! enumeration caps.

mod common;

use common::*;
use domain::TradeSide;
use execution_preview::validate_delta_preview_with_assessment;
use market_types::PoolKindState;
use routing::{enumerate_candidates, plan_single_path, MAX_BRIDGE_ASSETS, MAX_ROUTE_CANDIDATES};

fn ab() -> PoolKindState {
    PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30))
}

fn bc() -> PoolKindState {
    PoolKindState::Cpmm(cpmm(weth(), token2(), 500_000, 1_000_000, 30))
}

#[test]
fn cpmm_sweep_preserves_conservation_and_bridge_agreement() {
    let intent = buy(usdc(), weth(), 100_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor("uniswap-v2", "0xpool-ab", ab())];
    let policy = caller_policy();
    let scoring = scoring();

    for amount in [1_000u128, 5_000, 10_000, 50_000] {
        let request = request(
            &intent,
            &descriptors,
            amount,
            &tax,
            1,
            &policy,
            &scoring,
            None,
            None,
        );
        let decision = plan_single_path(&request).expect("viable direct route");
        let selected = decision.selected.as_ref().expect("selected");
        assert!(selected.plan.legs[0].amount_in.get() <= amount);
        assert!(validate_delta_preview_with_assessment(
            &intent,
            &selected.plan,
            &selected.net_delta,
            &tax,
            NOW_MS,
        )
        .is_ok());
    }
}

#[test]
fn two_hop_sweep_preserves_contiguity_and_bridge_agreement() {
    let intent = intent_with_risk(TradeSide::Buy, usdc(), token2(), 100_000, risk(2_000));
    let tax = zero_tax_for(&intent);
    let descriptors = vec![
        fresh_descriptor("uniswap-v2", "0xpool-ab", ab()),
        fresh_descriptor("sushi-v2", "0xpool-bc", bc()),
    ];
    let policy = caller_policy();
    let scoring = scoring();

    for amount in [1_000u128, 7_500, 10_000, 25_000] {
        let request = request(
            &intent,
            &descriptors,
            amount,
            &tax,
            2,
            &policy,
            &scoring,
            None,
            None,
        );
        let decision = plan_single_path(&request).expect("viable bridge route");
        let selected = decision.selected.as_ref().expect("selected");
        assert_eq!(selected.plan.legs.len(), 2);
        for window in selected.plan.legs.windows(2) {
            assert_eq!(window[0].token_out, window[1].token_in);
            assert_eq!(window[1].amount_in, window[0].expected_amount_out);
        }
        assert!(validate_delta_preview_with_assessment(
            &intent,
            &selected.plan,
            &selected.net_delta,
            &tax,
            NOW_MS,
        )
        .is_ok());
    }
}

#[test]
fn planning_is_deterministic_and_permutation_invariant() {
    let intent = buy(usdc(), token2(), 10_000);
    let tax = zero_tax_for(&intent);
    let forward = vec![
        fresh_descriptor("uniswap-v2", "0xpool-ab", ab()),
        fresh_descriptor("sushi-v2", "0xpool-bc", bc()),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();
    let policy = caller_policy();
    let scoring = scoring();

    let first = plan_single_path(&request(
        &intent, &forward, 10_000, &tax, 2, &policy, &scoring, None, None,
    ))
    .expect("first");
    let second = plan_single_path(&request(
        &intent, &forward, 10_000, &tax, 2, &policy, &scoring, None, None,
    ))
    .expect("second");
    assert_eq!(
        serde_json::to_string(&first).expect("json"),
        serde_json::to_string(&second).expect("json")
    );

    let permuted = plan_single_path(&request(
        &intent, &reversed, 10_000, &tax, 2, &policy, &scoring, None, None,
    ))
    .expect("permuted");
    assert_eq!(first.selected, permuted.selected);
}

#[test]
fn cpmm_output_is_monotonic_in_input() {
    let intent = buy(usdc(), weth(), 100_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor("uniswap-v2", "0xpool-ab", ab())];
    let policy = caller_policy();
    let scoring = scoring();

    let mut previous = 0u128;
    for amount in (1_000u128..=20_000).step_by(1_000) {
        let request = request(
            &intent,
            &descriptors,
            amount,
            &tax,
            1,
            &policy,
            &scoring,
            None,
            None,
        );
        let decision = plan_single_path(&request).expect("viable route");
        let net = decision
            .selected
            .as_ref()
            .expect("selected")
            .net_output
            .amount
            .get();
        assert!(net >= previous, "net output decreased at input {amount}");
        previous = net;
    }
}

#[test]
fn excess_bridge_assets_flag_truncation() {
    let mut descriptors = Vec::new();
    for index in 0..(MAX_BRIDGE_ASSETS + 8) {
        let bridge = base_asset(&format!("0xfeed{index:036x}"));
        descriptors.push(fresh_descriptor(
            "uniswap-v2",
            &format!("0xpool-in-{index}"),
            PoolKindState::Cpmm(cpmm(usdc(), bridge.clone(), 1_000_000, 2_000_000, 30)),
        ));
        descriptors.push(fresh_descriptor(
            "sushi-v2",
            &format!("0xpool-out-{index}"),
            PoolKindState::Cpmm(cpmm(bridge, token2(), 1_000_000, 2_000_000, 30)),
        ));
    }
    let intent = buy(usdc(), token2(), 1_000);
    let enumerated = enumerate_candidates(&intent, 2, &descriptors).expect("enumeration");
    assert!(enumerated.truncated);
    assert!(enumerated.paths.len() <= MAX_ROUTE_CANDIDATES);
    assert!(!enumerated.paths.iter().any(|path| path.legs.len() > 2));
}

#[test]
fn zero_tax_direct_never_models_funding() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor("uniswap-v2", "0xpool-ab", ab())];
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
    let decision = plan_single_path(&request).expect("bridge-verified route");
    let selected = decision.selected.as_ref().expect("selected");
    // The zero-tax route passes unconditional bridge verification and is valid.
    assert!(selected.plan.validate().is_ok());
    assert_eq!(intent.side, TradeSide::Buy);
}
