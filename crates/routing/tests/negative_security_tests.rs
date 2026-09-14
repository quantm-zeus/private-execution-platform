//! Negative and security cases for the R1 single-path router.
//!
//! Covers fail-closed taxonomy, freshness under both policies, label validation,
//! impact override requirements, redaction of every error variant, and static
//! source/manifest hygiene (no split, no forbidden dependencies, no ambient I/O).

mod common;

use std::path::Path;

use common::*;
use domain::{AmountType, DomainError, LimitPrice, OrderType, RiskConstraints, TradeSide};
use execution_preview::BridgeError;
use market_types::{AssetAmount, AtomicAmount, Bps, PoolKindState, PriceRatio, Sequence};
use routing::{
    plan_single_path, BridgeRejectClass, PoolKindClass, PoolRefLabel, RoutingError, VenueLabel,
    MAX_POOLS_SCANNED, MAX_ROUTE_HOPS,
};
use simulation::{BinSimulationError, ClmmSimulationError, CpmmSimulationErrorClass};
use tax_engine::TaxSafetyError;

fn direct_descriptor() -> routing::PoolDescriptor {
    fresh_descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
    )
}

#[test]
fn same_asset_pair_is_rejected() {
    let intent = buy(usdc(), usdc(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(plan_single_path(&request), Err(RoutingError::SameAssetPair));
}

#[test]
fn hop_count_bounds_are_enforced() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
    let policy = caller_policy();
    let scoring = scoring();
    for hops in [0usize, MAX_ROUTE_HOPS + 1] {
        let request = request(
            &intent,
            &descriptors,
            1_000,
            &tax,
            hops,
            &policy,
            &scoring,
            None,
            None,
        );
        assert_eq!(
            plan_single_path(&request),
            Err(RoutingError::UnsupportedHopCount)
        );
    }
}

#[test]
fn empty_pool_set_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors: Vec<routing::PoolDescriptor> = Vec::new();
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
    assert_eq!(plan_single_path(&request), Err(RoutingError::EmptyPoolSet));
}

#[test]
fn pool_set_over_the_scanned_bound_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor(); MAX_POOLS_SCANNED + 1];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::PoolSetTooLarge)
    );
}

#[test]
fn pool_chain_mismatch_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let solana_pool = PoolKindState::Cpmm(cpmm(
        solana_asset("So11111111111111111111111111111111111111112"),
        solana_asset("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
        1_000_000,
        2_000_000,
        30,
    ));
    let descriptors = vec![descriptor_on(
        chain_types::ChainId::Solana,
        "orca",
        "program-ref-1",
        solana_pool,
        NOW_MS,
        1,
        None,
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::PoolChainMismatch)
    );
}

#[test]
fn invalid_pool_state_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-bad",
        PoolKindState::Cpmm(cpmm(usdc(), usdc(), 1_000_000, 2_000_000, 30)),
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::PoolStateInvalid)
    );
}

#[test]
fn malformed_labels_are_rejected() {
    assert_eq!(VenueLabel::new(""), Err(RoutingError::InvalidVenueLabel));
    assert_eq!(
        VenueLabel::new("has space"),
        Err(RoutingError::InvalidVenueLabel)
    );
    assert_eq!(
        VenueLabel::new("bad\nlabel"),
        Err(RoutingError::InvalidVenueLabel)
    );
    assert_eq!(
        VenueLabel::new("x".repeat(65)),
        Err(RoutingError::InvalidVenueLabel)
    );
    assert_eq!(PoolRefLabel::new(""), Err(RoutingError::InvalidPoolRef));
    assert_eq!(
        PoolRefLabel::new(" leading"),
        Err(RoutingError::InvalidPoolRef)
    );
}

#[test]
fn stale_under_default_policy_fails_closed() {
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    // Fresh under the caller's 60s policy, stale under the pinned 10s default.
    let descriptors = vec![descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
        NOW_MS - 20_000,
        1,
        None,
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
    assert_eq!(plan_single_path(&request), Err(RoutingError::NoViableRoute));
}

#[test]
fn zero_sequence_pool_is_rejected_fail_closed() {
    // `PoolStateEnvelope::validate` already rejects a zero sequence, so this is
    // surfaced as a structural pool-state rejection rather than a silent route.
    let intent = buy(usdc(), weth(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![descriptor(
        "uniswap-v2",
        "0xpool-ab",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
        NOW_MS,
        0,
        None,
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::PoolStateInvalid)
    );
}

#[test]
fn disconnected_pools_fail_closed() {
    let intent = buy(usdc(), another_token(), 10_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![
        fresh_descriptor(
            "uniswap-v2",
            "0xpool-ab",
            PoolKindState::Cpmm(cpmm(usdc(), weth(), 1_000_000, 2_000_000, 30)),
        ),
        fresh_descriptor(
            "sushi-v2",
            "0xpool-bc",
            PoolKindState::Cpmm(cpmm(weth(), token2(), 500_000, 1_000_000, 30)),
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
    assert_eq!(plan_single_path(&request), Err(RoutingError::NoViableRoute));
}

#[test]
fn zero_reserve_hop_surfaces_kernel_class_without_payload() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "uniswap-v2",
        "0xpool-empty",
        PoolKindState::Cpmm(cpmm(usdc(), weth(), 0, 2_000_000, 30)),
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
    let error = plan_single_path(&request).expect_err("zero reserve must fail");
    assert_eq!(
        error,
        RoutingError::HopSimulationFailed(PoolKindClass::Cpmm)
    );
    assert_no_payload(&format!("{error}"));
    assert_no_payload(&format!("{error:?}"));
}

#[test]
fn bin_impact_requires_override_when_cap_is_set() {
    let intent = intent_with_risk(domain::TradeSide::Buy, usdc(), weth(), 1_010, risk(500));
    let tax = zero_tax_for(&intent);
    let descriptors = vec![fresh_descriptor(
        "meteora",
        "0xpool-bin",
        PoolKindState::Bin(bin(usdc(), weth())),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        1_010,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::ImpactUnavailable)
    );
}

#[test]
fn bin_impact_override_allows_route() {
    let intent = intent_with_risk(domain::TradeSide::Buy, usdc(), weth(), 1_010, risk(500));
    let tax = zero_tax_for(&intent);
    let descriptors = vec![descriptor(
        "meteora",
        "0xpool-bin",
        PoolKindState::Bin(bin(usdc(), weth())),
        NOW_MS,
        1,
        Some(10),
    )];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        1_010,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    let decision = plan_single_path(&request).expect("override permits route");
    assert_eq!(
        decision
            .candidates
            .first()
            .map(|c| c.score.price_impact.get()),
        Some(10)
    );
}

#[test]
fn assessment_asset_mismatch_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    // Assessed asset must be token_out (weth) for a buy.
    let tax = assessment(token2(), 500, 500);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::TaxAssessmentMismatch)
    );
}

#[test]
fn stale_assessment_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = assessment_at(
        chain_types::ChainId::Base,
        weth(),
        0,
        0,
        NOW_MS - 20_000,
        market_types::FreshnessStatus::Fresh,
    );
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::TaxAssessmentNotFresh)
    );
}

#[test]
fn assessment_zero_sequence_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let mut tax = assessment(weth(), 0, 0);
    tax.freshness.sequence = Sequence(0);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::TaxAssessmentNotFresh)
    );
}

#[test]
fn non_input_amount_type_is_rejected() {
    let mut intent = buy(usdc(), weth(), 1_000);
    intent.amount_type = AmountType::OutputAssetAtomic;
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
    let policy = caller_policy();
    let scoring = scoring();
    // The exact-input scope is enforced before any candidate is considered.
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::Domain(DomainError::UnsupportedAmountType))
    );
}

#[test]
fn request_amount_above_intent_is_rejected() {
    let intent = buy(usdc(), weth(), 1_000);
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        2_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::InputConservationViolated)
    );
}

#[test]
fn max_total_cost_is_bound_unconditionally() {
    let mut intent = buy(usdc(), weth(), 10_000);
    intent.risk.max_total_cost = Some(AssetAmount {
        asset: usdc(),
        amount: AtomicAmount::new(500),
    });
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::SelectedRejected(BridgeRejectClass::Domain))
    );
}

#[test]
fn limit_price_is_bound_unconditionally() {
    let mut intent = buy(usdc(), weth(), 10_000);
    intent.order_type = OrderType::Limit;
    intent.limit_price = Some(LimitPrice {
        numerator_asset: usdc(),
        denominator_asset: weth(),
        ratio: PriceRatio::new(1, 10).expect("limit ratio"),
    });
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::SelectedRejected(BridgeRejectClass::Domain))
    );
}

#[test]
fn tax_cap_rejection_surfaces_selected_rejected() {
    let constrained = RiskConstraints {
        max_buy_tax: Bps::new(0).expect("bps"),
        max_sell_tax: Bps::new(0).expect("bps"),
        max_price_impact: Bps::new(500).expect("bps"),
        max_slippage: Bps::new(500).expect("bps"),
        max_total_cost: None,
    };
    let intent = intent_with_risk(TradeSide::Buy, usdc(), weth(), 10_000, constrained);
    // The assessment charges 500 bps while the intent cap is 0.
    let tax = assessment(weth(), 500, 500);
    let descriptors = vec![direct_descriptor()];
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
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::SelectedRejected(BridgeRejectClass::TaxCap))
    );
}

#[test]
fn impact_exceeds_cap_is_surfaced() {
    let intent = intent_with_risk(TradeSide::Buy, usdc(), weth(), 400_000, risk(50));
    let tax = zero_tax_for(&intent);
    let descriptors = vec![direct_descriptor()];
    let policy = caller_policy();
    let scoring = scoring();
    let request = request(
        &intent,
        &descriptors,
        400_000,
        &tax,
        1,
        &policy,
        &scoring,
        None,
        None,
    );
    assert_eq!(
        plan_single_path(&request),
        Err(RoutingError::ImpactExceedsCap)
    );
}

fn all_errors() -> Vec<RoutingError> {
    vec![
        RoutingError::Domain(DomainError::SameAssetPair),
        RoutingError::Cpmm(CpmmSimulationErrorClass::InvalidPoolState),
        RoutingError::Clmm(ClmmSimulationError::InvalidPoolState),
        RoutingError::Bin(BinSimulationError::InvalidPoolState),
        RoutingError::Tax(TaxSafetyError::ChainMismatch),
        RoutingError::Tax(TaxSafetyError::InvalidTradeIntent(
            DomainError::SameAssetPair,
        )),
        RoutingError::Tax(TaxSafetyError::InvalidTaxObservation(
            DomainError::ChainMismatch,
        )),
        RoutingError::Tax(TaxSafetyError::MissingObservation),
        RoutingError::Tax(TaxSafetyError::FreshnessEvaluationFailed),
        RoutingError::Tax(TaxSafetyError::StaleObservation),
        RoutingError::Tax(TaxSafetyError::ResyncRequired),
        RoutingError::Tax(TaxSafetyError::BuySimulationFailed),
        RoutingError::Tax(TaxSafetyError::SellSimulationFailed),
        RoutingError::Tax(TaxSafetyError::TokenNotSellable),
        RoutingError::Tax(TaxSafetyError::BuyTaxExceedsCap),
        RoutingError::Tax(TaxSafetyError::SellTaxExceedsCap),
        RoutingError::Tax(TaxSafetyError::ZeroGrossOutput),
        RoutingError::Tax(TaxSafetyError::ZeroNetOutput),
        RoutingError::Tax(TaxSafetyError::ZeroGrossInput),
        RoutingError::Tax(TaxSafetyError::ZeroNetInput),
        RoutingError::NoViableRoute,
        RoutingError::TaxAssessmentRequired,
        RoutingError::StaleState,
        RoutingError::StalePoolState,
        RoutingError::ResyncRequired,
        RoutingError::UnsupportedPoolKind,
        RoutingError::UnsupportedBinTaxComposition,
        RoutingError::InputConservationViolated,
        RoutingError::BudgetExceeded,
        RoutingError::SameAssetPair,
        RoutingError::UnsupportedHopCount,
        RoutingError::EmptyPoolSet,
        RoutingError::PoolChainMismatch,
        RoutingError::PoolStateInvalid,
        RoutingError::PoolSetTooLarge,
        RoutingError::InvalidVenueLabel,
        RoutingError::InvalidPoolRef,
        RoutingError::TaxAssessmentNotFresh,
        RoutingError::TaxAssessmentMismatch,
        RoutingError::ZeroNetOutput,
        RoutingError::GasConversionFailed,
        RoutingError::GasChainMismatch,
        RoutingError::ImpactUnavailable,
        RoutingError::ImpactExceedsCap,
        RoutingError::ZeroHopOutput,
        RoutingError::AmountOverflow,
        RoutingError::HopSimulationFailed(PoolKindClass::Cpmm),
        RoutingError::HopSimulationFailed(PoolKindClass::Clmm),
        RoutingError::HopSimulationFailed(PoolKindClass::Bin),
        RoutingError::ScoreInconsistent("net output exceeds gross output"),
        RoutingError::SelectedRejected(BridgeRejectClass::Domain),
        RoutingError::SelectedRejected(BridgeRejectClass::NetDeltaInconsistent),
        RoutingError::Internal("fixed reason"),
    ]
}

fn assert_no_payload(text: &str) {
    let mut run = 0usize;
    let mut longest = 0usize;
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(longest < 8, "hex-looking payload leaked: {text}");
    for sentinel in [
        "0xdeadbeefcafebabe",
        "So11111111111111111111111111111111111111112",
        "123456789",
    ] {
        assert!(!text.contains(sentinel), "sentinel leaked: {text}");
    }
}

#[test]
fn every_error_variant_is_redacted() {
    for error in all_errors() {
        assert_no_payload(&format!("{error}"));
        assert_no_payload(&format!("{error:?}"));
    }
}

#[test]
fn bridge_reject_classes_are_redacted() {
    let mapping = [
        (BridgeError::DirectionMismatch, BridgeRejectClass::Direction),
        (BridgeError::ChainMismatch, BridgeRejectClass::Chain),
        (
            BridgeError::InputAssetMismatch,
            BridgeRejectClass::InputAsset,
        ),
        (
            BridgeError::OutputAssetMismatch,
            BridgeRejectClass::OutputAsset,
        ),
        (
            BridgeError::AssessedAssetMismatch,
            BridgeRejectClass::AssessedAsset,
        ),
        (
            BridgeError::AssessmentDeltaMismatch,
            BridgeRejectClass::AssessmentDelta,
        ),
        (BridgeError::TaxCapExceeded, BridgeRejectClass::TaxCap),
        (
            BridgeError::FreshnessUnavailable,
            BridgeRejectClass::Freshness,
        ),
    ];
    for (bridge, expected) in mapping {
        let class = BridgeRejectClass::from_bridge_error(&bridge);
        assert_eq!(class, expected);
        assert_no_payload(&format!("{class}"));
        assert_no_payload(&format!("{class:?}"));
    }
}

fn routing_src() -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut combined = String::new();
    let entries = std::fs::read_dir(src).expect("read src dir");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            combined.push_str(&std::fs::read_to_string(&path).expect("read source"));
            combined.push('\n');
        }
    }
    combined
}

#[test]
fn source_has_no_ambient_io_or_panic_macros() {
    let source = routing_src();
    for forbidden in [
        "std::time",
        "std::fs",
        "std::net",
        "use rand",
        "f64",
        "f32",
        ".unwrap(",
        ".expect(",
        "panic!",
        "unsafe ",
        "unsafe{",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source pattern present: {forbidden}"
        );
    }
}

#[test]
fn split_source_has_no_split_bypass() {
    // The split optimizer may produce a `SplitPlan`, but `routing` must never
    // validate, sign, or digest it: aggregate validation lives in
    // `execution-preview`/`domain` and signing lives in `privy`.
    let source = routing_src();
    for forbidden in [
        "privy",
        "compute_route_digest",
        "fn validate_split",
        "fn validate_split_preview",
        "route_digest",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden split-bypass symbol present: {forbidden}"
        );
    }
    // Positive control: the test is non-vacuous only if the optimizer exists.
    assert!(
        source.contains("pub fn plan_split"),
        "split optimizer is missing from the routing source"
    );
}

#[test]
fn manifest_has_no_forbidden_direct_dependencies() {
    // Direct dependency hygiene only. `execution-preview` is mandated by R1 and
    // transitively pulls `policy` through its pre-existing revalidation module;
    // that is recorded as a spec inconsistency in the slice report, not a
    // routing-controlled dependency.
    let manifest = include_str!("../Cargo.toml");
    for forbidden in [
        "privy",
        "execution-relay",
        "policy",
        "storage",
        "audit",
        "telemetry",
        "tokio",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency present: {forbidden}"
        );
    }
}
