//! P84: actual-execution analytics — exact deviation, deltas, binding, redaction.

use adaptive_exec::{
    analyze, AnalyticsError, Delta, DeltaDirection, ExecutionEstimate, RealizedExecution,
};
use chain_types::{AssetId, ChainId};

/// Sentinel amount that is both a hex-looking payload and a long decimal run.
const SENTINEL: u128 = 0xdead_beef_cafe_babe;

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("test asset")
}

fn estimate(expected_amount_out: u128) -> ExecutionEstimate {
    ExecutionEstimate {
        token_in: asset("USDC"),
        token_out: asset("TOKEN"),
        amount_in: 1_000,
        expected_amount_out,
        expected_gas: None,
        expected_tax: None,
    }
}

fn realized(amount_out: u128) -> RealizedExecution {
    RealizedExecution {
        token_in: asset("USDC"),
        token_out: asset("TOKEN"),
        amount_in: 1_000,
        amount_out,
        gas_paid: None,
        tax_paid: None,
    }
}

#[test]
fn exact_match_reports_zero_deviation_and_zero_deltas() {
    let analytics = analyze(&estimate(10_000), &realized(10_000)).expect("analytics");

    assert_eq!(analytics.output_deviation_bps, 0);
    assert_eq!(analytics.output_direction, DeltaDirection::Exact);
    assert_eq!(
        analytics.input_delta,
        Delta {
            direction: DeltaDirection::Exact,
            magnitude: 0,
        }
    );
    assert_eq!(analytics.gas_delta, None);
    assert_eq!(analytics.tax_delta, None);
}

#[test]
fn realized_better_by_a_known_amount_has_exact_bps() {
    // 10_000 * 200 / 10_000 = 200 bps.
    let analytics = analyze(&estimate(10_000), &realized(10_200)).expect("analytics");

    assert_eq!(analytics.output_deviation_bps, 200);
    assert_eq!(analytics.output_direction, DeltaDirection::RealizedBetter);
    assert_eq!(
        analytics.input_delta,
        Delta {
            direction: DeltaDirection::Exact,
            magnitude: 0,
        }
    );
}

#[test]
fn realized_worse_by_a_known_amount_has_exact_bps() {
    // 10_000 * 200 / 10_000 = 200 bps.
    let analytics = analyze(&estimate(10_000), &realized(9_800)).expect("analytics");

    assert_eq!(analytics.output_deviation_bps, 200);
    assert_eq!(analytics.output_direction, DeltaDirection::RealizedWorse);
}

#[test]
fn deviation_is_floored_not_rounded() {
    // Exactly 100 bps: 10_000 -> 10_100.
    let exact = analyze(&estimate(10_000), &realized(10_100)).expect("analytics");
    assert_eq!(exact.output_deviation_bps, 100);

    // 10_000 * 1 / 3 = 3333.33 -> floor 3333, never ceil 3334.
    let better = analyze(&estimate(3), &realized(4)).expect("analytics");
    assert_eq!(better.output_deviation_bps, 3_333);
    assert_eq!(better.output_direction, DeltaDirection::RealizedBetter);

    let worse = analyze(&estimate(3), &realized(2)).expect("analytics");
    assert_eq!(worse.output_deviation_bps, 3_333);
    assert_eq!(worse.output_direction, DeltaDirection::RealizedWorse);
}

#[test]
fn deviation_boundary_at_u16_max_and_overflow_fail_closed() {
    // Exactly u16::MAX bps: diff 65_535 over expected 10_000.
    let boundary = analyze(&estimate(10_000), &realized(75_535)).expect("analytics");
    assert_eq!(boundary.output_deviation_bps, u16::MAX);
    assert_eq!(boundary.output_direction, DeltaDirection::RealizedBetter);

    // One bps over the boundary: 10_000 * 7 / 1 = 70_000 > u16::MAX.
    assert_eq!(
        analyze(&estimate(1), &realized(8)),
        Err(AnalyticsError::ArithmeticOverflow)
    );

    // `u128::MAX` expected vs 1 realized overflows the checked multiply itself.
    assert_eq!(
        analyze(&estimate(u128::MAX), &realized(1)),
        Err(AnalyticsError::ArithmeticOverflow)
    );
}

#[test]
fn input_delta_is_realized_minus_expected() {
    let mut spent_more = estimate(10_000);
    spent_more.amount_in = 1_000;
    let mut realized_more = realized(10_000);
    realized_more.amount_in = 1_250;
    let analytics = analyze(&spent_more, &realized_more).expect("analytics");
    assert_eq!(
        analytics.input_delta,
        Delta {
            direction: DeltaDirection::RealizedWorse,
            magnitude: 250,
        }
    );

    realized_more.amount_in = 750;
    let analytics = analyze(&spent_more, &realized_more).expect("analytics");
    assert_eq!(
        analytics.input_delta,
        Delta {
            direction: DeltaDirection::RealizedBetter,
            magnitude: 250,
        }
    );
}

#[test]
fn gas_and_tax_deltas_and_presence_mismatches() {
    // Both absent on both sides -> no delta at all.
    let absent = analyze(&estimate(10_000), &realized(10_000)).expect("analytics");
    assert_eq!(absent.gas_delta, None);
    assert_eq!(absent.tax_delta, None);

    // Both present: a larger realized gas/tax is worse, a smaller one better.
    let mut expected = estimate(10_000);
    expected.expected_gas = Some(21_000);
    expected.expected_tax = Some(500);
    let mut actual = realized(10_000);
    actual.gas_paid = Some(21_500);
    actual.tax_paid = Some(450);
    let analytics = analyze(&expected, &actual).expect("analytics");
    assert_eq!(
        analytics.gas_delta,
        Some(Delta {
            direction: DeltaDirection::RealizedWorse,
            magnitude: 500,
        })
    );
    assert_eq!(
        analytics.tax_delta,
        Some(Delta {
            direction: DeltaDirection::RealizedBetter,
            magnitude: 50,
        })
    );

    // Estimate carries a gas baseline but the fill does not.
    let mut missing_gas = realized(10_000);
    missing_gas.gas_paid = None;
    let mut expected_gas = estimate(10_000);
    expected_gas.expected_gas = Some(21_000);
    assert_eq!(
        analyze(&expected_gas, &missing_gas),
        Err(AnalyticsError::GasBaselineMismatch)
    );

    // The fill carries gas but the estimate does not.
    let mut unexpected_gas = realized(10_000);
    unexpected_gas.gas_paid = Some(21_000);
    assert_eq!(
        analyze(&estimate(10_000), &unexpected_gas),
        Err(AnalyticsError::GasBaselineMismatch)
    );

    // The same presence contract for tax.
    let mut missing_tax = realized(10_000);
    missing_tax.tax_paid = None;
    let mut expected_tax = estimate(10_000);
    expected_tax.expected_tax = Some(500);
    assert_eq!(
        analyze(&expected_tax, &missing_tax),
        Err(AnalyticsError::TaxBaselineMismatch)
    );

    let mut unexpected_tax = realized(10_000);
    unexpected_tax.tax_paid = Some(500);
    assert_eq!(
        analyze(&estimate(10_000), &unexpected_tax),
        Err(AnalyticsError::TaxBaselineMismatch)
    );
}

#[test]
fn binding_mismatches_fail_closed() {
    let baseline = estimate(10_000);

    // Wrong chain on token_in.
    let mut wrong_chain = realized(10_000);
    wrong_chain.token_in = AssetId::new(ChainId::Solana, "USDC").expect("test asset");
    assert_eq!(
        analyze(&baseline, &wrong_chain),
        Err(AnalyticsError::ChainMismatch)
    );

    // Wrong chain on token_out.
    let mut wrong_out_chain = realized(10_000);
    wrong_out_chain.token_out = AssetId::new(ChainId::Solana, "TOKEN").expect("test asset");
    assert_eq!(
        analyze(&baseline, &wrong_out_chain),
        Err(AnalyticsError::ChainMismatch)
    );

    // Same chain, different token_in.
    let mut wrong_in = realized(10_000);
    wrong_in.token_in = asset("DAI");
    assert_eq!(
        analyze(&baseline, &wrong_in),
        Err(AnalyticsError::PairMismatch)
    );

    // Same chain, different token_out.
    let mut wrong_out = realized(10_000);
    wrong_out.token_out = asset("WETH");
    assert_eq!(
        analyze(&baseline, &wrong_out),
        Err(AnalyticsError::PairMismatch)
    );
}

#[test]
fn zero_expected_output_fails_closed_even_when_realized_is_zero() {
    assert_eq!(
        analyze(&estimate(0), &realized(0)),
        Err(AnalyticsError::ZeroExpectedOutput)
    );
    assert_eq!(
        analyze(&estimate(0), &realized(5)),
        Err(AnalyticsError::ZeroExpectedOutput)
    );
}

#[test]
fn analysis_is_deterministic() {
    let mut expected = estimate(10_000);
    expected.expected_gas = Some(21_000);
    expected.expected_tax = Some(500);
    let mut actual = realized(9_800);
    actual.amount_in = 1_010;
    actual.gas_paid = Some(21_500);
    actual.tax_paid = Some(400);

    let first = analyze(&expected, &actual).expect("first");
    let second = analyze(&expected, &actual).expect("second");
    assert_eq!(first, second);
    assert_eq!(first.output_deviation_bps, 200);
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
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

fn all_errors() -> Vec<AnalyticsError> {
    vec![
        AnalyticsError::ChainMismatch,
        AnalyticsError::PairMismatch,
        AnalyticsError::ZeroExpectedOutput,
        AnalyticsError::GasBaselineMismatch,
        AnalyticsError::TaxBaselineMismatch,
        AnalyticsError::ArithmeticOverflow,
    ]
}

#[test]
fn every_analytics_error_variant_is_redacted() {
    for error in all_errors() {
        assert_no_payload(&format!("{error}"));
        assert_no_payload(&format!("{error:?}"));
    }
}

#[test]
fn redaction_sweep_covers_every_variant() {
    // Completeness guard: the sweep is only meaningful if every variant is
    // present, so dropping one must fail here.
    assert_eq!(all_errors().len(), 6);
    assert!(all_errors().contains(&AnalyticsError::ArithmeticOverflow));
}

#[test]
fn structs_and_delta_debug_are_redacted() {
    let estimate = ExecutionEstimate {
        token_in: asset("0xdeadbeefcafebabe"),
        token_out: asset("So11111111111111111111111111111111111111112"),
        amount_in: SENTINEL,
        expected_amount_out: SENTINEL,
        expected_gas: Some(SENTINEL),
        expected_tax: Some(SENTINEL),
    };
    let realized = RealizedExecution {
        token_in: asset("0xdeadbeefcafebabe"),
        token_out: asset("So11111111111111111111111111111111111111112"),
        amount_in: 1,
        amount_out: SENTINEL,
        gas_paid: Some(0),
        tax_paid: Some(SENTINEL),
    };
    let analytics = analyze(&estimate, &realized).expect("analytics");
    assert_eq!(analytics.output_deviation_bps, 0);

    // `SENTINEL` is nonzero so a magnitude leak would fail `assert_no_payload`;
    // exercise `Delta` directly, as required, in addition to the structs.
    let delta = Delta {
        direction: DeltaDirection::RealizedWorse,
        magnitude: SENTINEL,
    };
    assert!(delta.magnitude > 0);

    assert_no_payload(&format!("{estimate:?}"));
    assert_no_payload(&format!("{realized:?}"));
    assert_no_payload(&format!("{analytics:?}"));
    assert_no_payload(&format!("{delta:?}"));
    assert_no_payload(&format!("{analytics:?} {delta:?}"));
}
