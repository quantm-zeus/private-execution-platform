//! P80 provider-route benchmark comparator tests.
//!
//! Covers the exact comparison vectors, the inclusive disagreement threshold,
//! fail-closed binding/zero/future/overflow errors, freshness skips, strict
//! source/reference validation, determinism, and redaction of `ProviderQuote`,
//! `RouteComparisonRecord`, `RealizedExecution`, and every `BenchmarkError`.

use chain_types::{AssetId, ChainId};
use market_types::Bps;
use routing::benchmark::{MAX_BENCHMARK_REFERENCE_BYTES, MAX_BENCHMARK_SOURCE_BYTES};
use routing::{
    compare_route, BenchmarkDirection, BenchmarkError, BenchmarkPolicy, BenchmarkSkip,
    BenchmarkSource, BenchmarkVerdict, LocalRouteQuote, ProviderQuote, RealizedExecution,
    RouteComparisonRecord,
};

const NOW_MS: i64 = 1_000_000;

fn base_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid base asset")
}

fn usdc() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000001")
}

fn weth() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000002")
}

fn token2() -> AssetId {
    base_asset("0x0000000000000000000000000000000000000003")
}

fn source(label: impl Into<String>) -> BenchmarkSource {
    BenchmarkSource::new(label).expect("valid source label")
}

fn local(amount_in: u128, amount_out: u128) -> LocalRouteQuote {
    LocalRouteQuote::new(ChainId::Base, usdc(), weth(), amount_in, amount_out, NOW_MS)
}

fn provider(amount_in: u128, amount_out: u128) -> ProviderQuote {
    ProviderQuote::new(
        source("okx"),
        ChainId::Base,
        usdc(),
        weth(),
        amount_in,
        amount_out,
        NOW_MS,
        "ref-1",
    )
    .expect("valid provider quote")
}

fn policy(disagreement_bps: u16) -> BenchmarkPolicy {
    BenchmarkPolicy::new(
        Bps::new(disagreement_bps).expect("valid bps"),
        5_000,
        2_000,
        0,
    )
}

// ---------------------------------------------------------------------------
// Exact comparison vectors
// ---------------------------------------------------------------------------

#[test]
fn equal_outputs_agree_with_zero_deviation() {
    let verdict = compare_route(
        &local(1_000, 10_000),
        &provider(1_000, 10_000),
        &policy(50),
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Agree {
            deviation_bps: 0,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
}

#[test]
fn local_premium_is_local_better_with_exact_bps() {
    let verdict = compare_route(
        &local(1_000, 10_100),
        &provider(1_000, 10_000),
        &policy(50),
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Disagree {
            deviation_bps: 100,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
}

#[test]
fn provider_premium_is_provider_better_with_exact_bps() {
    let verdict = compare_route(
        &local(1_000, 9_900),
        &provider(1_000, 10_000),
        &policy(50),
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Disagree {
            deviation_bps: 100,
            direction: BenchmarkDirection::ProviderBetter,
        }
    );
}

#[test]
fn disagreement_threshold_is_inclusive() {
    let inclusive = policy(100);
    let at_threshold = compare_route(
        &local(1_000, 10_100),
        &provider(1_000, 10_000),
        &inclusive,
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        at_threshold,
        BenchmarkVerdict::Agree {
            deviation_bps: 100,
            direction: BenchmarkDirection::LocalBetter,
        }
    );

    let above_threshold = compare_route(
        &local(1_000, 10_101),
        &provider(1_000, 10_000),
        &inclusive,
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        above_threshold,
        BenchmarkVerdict::Disagree {
            deviation_bps: 101,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
    // Non-vacuous: an exclusive `<` comparison would flip the boundary case.
    assert_ne!(at_threshold, above_threshold);
}

#[test]
fn deviation_above_bps_max_is_still_representable() {
    // The quotient is not clamped to `Bps::MAX`: 20_000 bps is a valid `u16`.
    let verdict = compare_route(
        &local(1_000, 30_000),
        &provider(1_000, 10_000),
        &policy(50),
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Disagree {
            deviation_bps: 20_000,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
}

// ---------------------------------------------------------------------------
// Binding, zero, and future errors
// ---------------------------------------------------------------------------

#[test]
fn chain_mismatch_fails_closed() {
    let cross_chain = ProviderQuote::new(
        source("okx"),
        ChainId::Solana,
        usdc(),
        weth(),
        1_000,
        10_000,
        NOW_MS,
        "ref-1",
    )
    .expect("valid provider quote");
    assert_eq!(
        compare_route(&local(1_000, 10_000), &cross_chain, &policy(50), NOW_MS),
        Err(BenchmarkError::ChainMismatch)
    );
}

#[test]
fn asset_pair_mismatch_fails_closed() {
    let other_input = ProviderQuote::new(
        source("okx"),
        ChainId::Base,
        token2(),
        weth(),
        1_000,
        10_000,
        NOW_MS,
        "ref-1",
    )
    .expect("valid provider quote");
    assert_eq!(
        compare_route(&local(1_000, 10_000), &other_input, &policy(50), NOW_MS),
        Err(BenchmarkError::PairMismatch)
    );

    let other_output = ProviderQuote::new(
        source("okx"),
        ChainId::Base,
        usdc(),
        token2(),
        1_000,
        10_000,
        NOW_MS,
        "ref-1",
    )
    .expect("valid provider quote");
    assert_eq!(
        compare_route(&local(1_000, 10_000), &other_output, &policy(50), NOW_MS),
        Err(BenchmarkError::PairMismatch)
    );
}

#[test]
fn input_mismatch_fails_closed() {
    assert_eq!(
        compare_route(
            &local(1_000, 10_000),
            &provider(1_001, 10_000),
            &policy(50),
            NOW_MS
        ),
        Err(BenchmarkError::InputMismatch)
    );
}

#[test]
fn zero_amounts_fail_closed() {
    assert_eq!(
        compare_route(&local(0, 10_000), &provider(0, 10_000), &policy(50), NOW_MS),
        Err(BenchmarkError::ZeroInput)
    );
    assert_eq!(
        compare_route(
            &local(1_000, 0),
            &provider(1_000, 10_000),
            &policy(50),
            NOW_MS
        ),
        Err(BenchmarkError::ZeroLocalOutput)
    );
    assert_eq!(
        compare_route(
            &local(1_000, 10_000),
            &provider(1_000, 0),
            &policy(50),
            NOW_MS
        ),
        Err(BenchmarkError::ZeroProviderOutput)
    );
}

#[test]
fn future_timestamps_fail_closed_before_skips() {
    let mut future_local = local(1_000, 10_000);
    future_local.observed_at_ms = NOW_MS + 1;
    // `min_input_atomic` would otherwise skip this basis; the future error wins.
    let skipping = BenchmarkPolicy::new(Bps::new(50).expect("bps"), 5_000, 2_000, 10_000);
    assert_eq!(
        compare_route(&future_local, &provider(1_000, 10_000), &skipping, NOW_MS),
        Err(BenchmarkError::LocalFromFuture)
    );

    let mut future_provider = provider(1_000, 10_000);
    future_provider.observed_at_ms = NOW_MS + 1;
    assert_eq!(
        compare_route(&local(1_000, 10_000), &future_provider, &skipping, NOW_MS),
        Err(BenchmarkError::ProviderFromFuture)
    );
}

// ---------------------------------------------------------------------------
// Freshness and size skips
// ---------------------------------------------------------------------------

#[test]
fn input_below_minimum_skips_before_staleness() {
    let skipping = BenchmarkPolicy::new(Bps::new(50).expect("bps"), 5_000, 2_000, 2_000);
    let mut stale_local = local(1_999, 10_000);
    stale_local.observed_at_ms = NOW_MS - 10_000;
    assert_eq!(
        compare_route(&stale_local, &provider(1_999, 10_000), &skipping, NOW_MS),
        Ok(BenchmarkVerdict::Skipped(
            BenchmarkSkip::BelowLargeOrderThreshold
        ))
    );
}

#[test]
fn stale_local_state_skips() {
    let mut stale_local = local(1_000, 10_000);
    stale_local.observed_at_ms = NOW_MS - 2_001;
    assert_eq!(
        compare_route(&stale_local, &provider(1_000, 10_000), &policy(50), NOW_MS),
        Ok(BenchmarkVerdict::Skipped(BenchmarkSkip::LocalStateStale))
    );
}

#[test]
fn stale_provider_quote_skips() {
    let mut stale_provider = provider(1_000, 10_000);
    stale_provider.observed_at_ms = NOW_MS - 5_001;
    assert_eq!(
        compare_route(&local(1_000, 10_000), &stale_provider, &policy(50), NOW_MS),
        Ok(BenchmarkVerdict::Skipped(BenchmarkSkip::ProviderStale))
    );
}

#[test]
fn boundary_ages_are_not_stale() {
    let mut edge_local = local(1_000, 10_000);
    edge_local.observed_at_ms = NOW_MS - 2_000;
    let mut edge_provider = provider(1_000, 10_000);
    edge_provider.observed_at_ms = NOW_MS - 5_000;
    assert_eq!(
        compare_route(&edge_local, &edge_provider, &policy(50), NOW_MS),
        Ok(BenchmarkVerdict::Agree {
            deviation_bps: 0,
            direction: BenchmarkDirection::LocalBetter,
        })
    );
}

// ---------------------------------------------------------------------------
// Exact arithmetic and overflow
// ---------------------------------------------------------------------------

#[test]
fn unrepresentable_deviation_fails_closed_without_panic() {
    assert_eq!(
        compare_route(
            &local(1_000, u128::MAX),
            &provider(1_000, 1),
            &policy(50),
            NOW_MS
        ),
        Err(BenchmarkError::ArithmeticOverflow)
    );
}

#[test]
fn quotient_above_u16_fails_closed() {
    // The 256-bit division succeeds here but the quotient exceeds `u16::MAX`.
    assert_eq!(
        compare_route(
            &local(1_000, 100_000),
            &provider(1_000, 1),
            &policy(50),
            NOW_MS
        ),
        Err(BenchmarkError::ArithmeticOverflow)
    );
}

#[test]
fn extreme_representable_deviation_is_exact() {
    let verdict = compare_route(
        &local(1_000, 20_000),
        &provider(1_000, 10_000),
        &policy(50),
        NOW_MS,
    )
    .expect("comparison");
    assert_eq!(
        verdict,
        BenchmarkVerdict::Disagree {
            deviation_bps: 10_000,
            direction: BenchmarkDirection::LocalBetter,
        }
    );
}

// ---------------------------------------------------------------------------
// Validation and determinism
// ---------------------------------------------------------------------------

#[test]
fn source_label_validation_is_strict() {
    assert_eq!(BenchmarkSource::new(""), Err(BenchmarkError::InvalidSource));
    assert_eq!(
        BenchmarkSource::new("has space"),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        BenchmarkSource::new(" leading"),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        BenchmarkSource::new("trailing "),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        BenchmarkSource::new("tab\tlabel"),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        BenchmarkSource::new("non-ascii-\u{00e9}"),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        BenchmarkSource::new("x".repeat(MAX_BENCHMARK_SOURCE_BYTES + 1)),
        Err(BenchmarkError::InvalidSource)
    );
    assert_eq!(
        source("x".repeat(MAX_BENCHMARK_SOURCE_BYTES))
            .as_str()
            .len(),
        MAX_BENCHMARK_SOURCE_BYTES
    );
    assert_eq!(source("okx").as_str(), "okx");
}

#[test]
fn provider_reference_validation_is_strict() {
    let build = |reference: String| {
        ProviderQuote::new(
            source("okx"),
            ChainId::Base,
            usdc(),
            weth(),
            1_000,
            10_000,
            NOW_MS,
            reference,
        )
    };
    assert_eq!(build(String::new()), Err(BenchmarkError::InvalidReference));
    assert_eq!(
        build("r".repeat(MAX_BENCHMARK_REFERENCE_BYTES + 1)),
        Err(BenchmarkError::InvalidReference)
    );
    let ok = build("r".repeat(MAX_BENCHMARK_REFERENCE_BYTES)).expect("valid provider quote");
    assert_eq!(ok.reference().len(), MAX_BENCHMARK_REFERENCE_BYTES);
}

#[test]
fn comparison_is_deterministic() {
    let local = local(1_000, 10_100);
    let provider = provider(1_000, 10_000);
    let expected = compare_route(&local, &provider, &policy(50), NOW_MS).expect("comparison");
    for _ in 0..8 {
        assert_eq!(
            compare_route(&local, &provider, &policy(50), NOW_MS).expect("comparison"),
            expected
        );
    }
}

#[test]
fn record_reports_verdict_fields_and_realized() {
    let local = local(1_000, 10_100);
    let provider = provider(1_000, 10_000);
    let verdict = compare_route(&local, &provider, &policy(50), NOW_MS).expect("comparison");
    let record = RouteComparisonRecord::new(&local, &provider, verdict);
    assert_eq!(record.deviation_bps(), 100);
    assert_eq!(record.direction(), BenchmarkDirection::LocalBetter);

    let realized = RealizedExecution {
        amount_in: 1_000,
        amount_out: 10_050,
    };
    let enriched = record.clone().with_realized(realized);
    assert_eq!(enriched.deviation_bps(), 100);
    assert_eq!(enriched.direction(), BenchmarkDirection::LocalBetter);
    // The original record is unchanged by the consuming builder.
    assert_eq!(record.deviation_bps(), 100);
}

#[test]
fn skipped_record_has_neutral_deviation() {
    let local = local(1_000, 10_000);
    let provider = provider(1_000, 10_000);
    let record = RouteComparisonRecord::new(
        &local,
        &provider,
        BenchmarkVerdict::Skipped(BenchmarkSkip::LocalStateStale),
    );
    assert_eq!(record.deviation_bps(), 0);
    assert_eq!(record.direction(), BenchmarkDirection::LocalBetter);
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

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

fn all_benchmark_errors() -> Vec<BenchmarkError> {
    vec![
        BenchmarkError::InvalidSource,
        BenchmarkError::InvalidReference,
        BenchmarkError::ChainMismatch,
        BenchmarkError::PairMismatch,
        BenchmarkError::InputMismatch,
        BenchmarkError::ZeroInput,
        BenchmarkError::ZeroLocalOutput,
        BenchmarkError::ZeroProviderOutput,
        BenchmarkError::ProviderFromFuture,
        BenchmarkError::LocalFromFuture,
        BenchmarkError::ArithmeticOverflow,
    ]
}

#[test]
fn every_error_variant_is_redacted() {
    for error in all_benchmark_errors() {
        assert_no_payload(&format!("{error}"));
        assert_no_payload(&format!("{error:?}"));
    }
}

#[test]
fn provider_record_and_realized_are_redacted() {
    let sentinel_asset_in = AssetId::new(ChainId::Base, "0xdeadbeefcafebabe").expect("asset");
    let sentinel_asset_out = AssetId::new(ChainId::Base, "0xdeadbeefcafebabe99").expect("asset");
    let sentinel_amount: u128 = 987_654_321;

    let provider = ProviderQuote::new(
        source("okx"),
        ChainId::Base,
        sentinel_asset_in.clone(),
        sentinel_asset_out.clone(),
        sentinel_amount,
        sentinel_amount,
        NOW_MS,
        format!("ref-{sentinel_amount}"),
    )
    .expect("valid provider quote");
    let local = LocalRouteQuote::new(
        ChainId::Base,
        sentinel_asset_in,
        sentinel_asset_out,
        sentinel_amount,
        sentinel_amount,
        NOW_MS,
    );
    let verdict = compare_route(&local, &provider, &policy(50), NOW_MS).expect("comparison");
    let record =
        RouteComparisonRecord::new(&local, &provider, verdict).with_realized(RealizedExecution {
            amount_in: sentinel_amount,
            amount_out: sentinel_amount,
        });

    // The opaque reference and all amount/asset values stay out of Debug.
    assert_no_payload(&format!("{provider:?}"));
    assert_no_payload(&format!("{record:?}"));
    assert_eq!(
        provider.reference(),
        format!("ref-{sentinel_amount}").as_str()
    );
}
