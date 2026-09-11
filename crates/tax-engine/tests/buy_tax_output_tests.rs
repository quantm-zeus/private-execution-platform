//! Deterministic unit tests for buy-side output-tax arithmetic.

use chain_types::{AssetId, ChainId};
use market_types::{AssetAmount, AtomicAmount, Bps, FreshnessStatus, SafeFreshnessMeta, Sequence};
use tax_engine::{
    apply_buy_tax, apply_buy_tax_to_output, calculate_buy_tax_output, BuyOutputTax, BuyTaxOutput,
    TaxAssessment, TaxSafetyEngine, TaxSafetyError,
};

fn sample_asset(chain: ChainId, address: &str) -> AssetId {
    AssetId::new(chain, address).expect("valid asset")
}

fn sample_assessment(
    chain: ChainId,
    address: &str,
    buy_tax_bps: u16,
    status: FreshnessStatus,
) -> TaxAssessment {
    let assessed_asset = sample_asset(chain.clone(), address);
    let freshness = SafeFreshnessMeta {
        status,
        observed_at_ms: 100_000,
        evaluated_at_ms: 105_000,
        age_ms: 5_000,
        sequence: Sequence::new(50_000),
    };
    TaxAssessment::new(
        assessed_asset,
        chain,
        Bps::new(buy_tax_bps).expect("valid buy tax bps"),
        Bps::new(0).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

fn sample_gross_output(chain: ChainId, address: &str, amount: u128) -> AssetAmount {
    AssetAmount {
        asset: sample_asset(chain, address),
        amount: AtomicAmount::new(amount),
    }
}

// =========================================================================
// 1. Known floor-rounding vectors (including sub-unit tax remainder)
//    and conservation gross = tax + net
// =========================================================================

#[test]
fn test_floor_rounding_vectors_and_conservation() {
    let address = "0x0000000000000000000000000000000000000002";

    // (gross_amount, buy_tax_bps, expected_tax, expected_net)
    let vectors: &[(u128, u16, u128, u128)] = &[
        // Sub-unit tax remainder: gross * bps < 10_000 => tax = 0
        (1, 1, 0, 1),
        (1, 500, 0, 1),
        (1, 5_000, 0, 1),
        (1, 9_999, 0, 1),
        (2, 4_999, 0, 2),
        (3, 3_333, 0, 3),
        (9, 1_111, 0, 9),
        // Exact integer tax boundary
        (2, 5_000, 1, 1),
        (4, 2_500, 1, 3),
        (10, 1_000, 1, 9),
        (100, 100, 1, 99),
        // Sub-unit remainders on non-trivial amounts
        (7, 1_500, 1, 6),             // 7 * 1500 / 10000 = 1.05 => floor = 1
        (100, 99, 0, 100),            // 100 * 99 / 10000 = 0.99 => floor = 0
        (100, 101, 1, 99),            // 100 * 101 / 10000 = 1.01 => floor = 1
        (100_003, 500, 5000, 95_003), // 100003 * 500 / 10000 = 5000.15 => 5000
        (10_000, 250, 250, 9_750),
        (1_000_000, 300, 30_000, 970_000),
        (1_000_000_000_000, 1_234, 123_400_000_000, 876_600_000_000),
        (999_999, 9_999, 999_899, 100), // 999999 * 9999 / 10000 = 999899.0001
    ];

    for &(gross, bps, exp_tax, exp_net) in vectors {
        let assessment = sample_assessment(ChainId::Base, address, bps, FreshnessStatus::Fresh);
        let gross_output = sample_gross_output(ChainId::Base, address, gross);

        let result = apply_buy_tax_to_output(&assessment, &gross_output)
            .unwrap_or_else(|e| panic!("failed for gross={}, bps={}: {:?}", gross, bps, e));

        assert_eq!(
            result.gross_output().amount.get(),
            gross,
            "gross output mismatch"
        );
        assert_eq!(
            result.tax_cost().amount.get(),
            exp_tax,
            "tax cost mismatch for gross={}, bps={}",
            gross,
            bps
        );
        assert_eq!(
            result.net_output().amount.get(),
            exp_net,
            "net output mismatch for gross={}, bps={}",
            gross,
            bps
        );
        assert_eq!(
            result.net_received_output().amount.get(),
            exp_net,
            "net received alias mismatch"
        );

        // Invariant: Conservation gross = tax + net
        assert_eq!(
            result.tax_cost().amount.get() + result.net_output().amount.get(),
            result.gross_output().amount.get(),
            "conservation violated for gross={}, bps={}",
            gross,
            bps
        );

        // Invariant: Exact asset preservation
        assert_eq!(result.gross_output().asset, gross_output.asset);
        assert_eq!(result.tax_cost().asset, gross_output.asset);
        assert_eq!(result.net_output().asset, gross_output.asset);

        // Verify convenience callers produce identical results
        let res_alias = apply_buy_tax(&assessment, &gross_output).unwrap();
        assert_eq!(result, res_alias);

        let res_calc = calculate_buy_tax_output(&assessment, &gross_output).unwrap();
        assert_eq!(result, res_calc);

        let res_engine = TaxSafetyEngine::apply_buy_tax(&assessment, &gross_output).unwrap();
        assert_eq!(result, res_engine);

        let res_engine_to =
            TaxSafetyEngine::apply_buy_tax_to_output(&assessment, &gross_output).unwrap();
        assert_eq!(result, res_engine_to);

        let res_method = assessment.apply_buy_tax(&gross_output).unwrap();
        assert_eq!(result, res_method);
    }
}

// =========================================================================
// 2. Zero-tax success and 100%-tax / zero-net rejection
// =========================================================================

#[test]
fn test_zero_tax_success() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 0, FreshnessStatus::Fresh);

    for gross in [1u128, 100, 10_000, 1_000_000_000, u128::MAX] {
        let gross_output = sample_gross_output(ChainId::Base, address, gross);
        let result = apply_buy_tax_to_output(&assessment, &gross_output)
            .expect("zero tax must succeed for positive gross amount");

        assert_eq!(result.tax_cost().amount.get(), 0);
        assert_eq!(result.net_output().amount.get(), gross);
        assert_eq!(
            result.gross_output().amount.get(),
            result.tax_cost().amount.get() + result.net_output().amount.get()
        );
    }
}

#[test]
fn test_100_percent_tax_zero_net_rejection() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 10_000, FreshnessStatus::Fresh);

    for gross in [1u128, 2, 100, 10_000, 1_000_000_000, u128::MAX] {
        let gross_output = sample_gross_output(ChainId::Base, address, gross);
        let err = apply_buy_tax_to_output(&assessment, &gross_output)
            .expect_err("100% tax must fail closed with ZeroNetOutput");

        assert_eq!(err, TaxSafetyError::ZeroNetOutput);
    }
}

// =========================================================================
// 3. Near-u128::MAX gross amounts proving exact bounded behavior without panic
// =========================================================================

#[test]
fn test_near_u128_max_gross_exact_bounded_arithmetic() {
    let address = "0x0000000000000000000000000000000000000002";

    let test_gross_amounts = [
        u128::MAX,
        u128::MAX - 1,
        u128::MAX - 2,
        u128::MAX - 10_000,
        u128::MAX - 1_000_000,
        (1u128 << 127) | ((1u128 << 127) - 1),
    ];

    let test_bps_rates: &[u16] = &[
        0, 1, 2, 10, 50, 100, 250, 500, 1_000, 2_500, 5_000, 7_500, 9_999,
    ];

    for &gross in &test_gross_amounts {
        for &bps in test_bps_rates {
            let assessment = sample_assessment(ChainId::Base, address, bps, FreshnessStatus::Fresh);
            let gross_output = sample_gross_output(ChainId::Base, address, gross);

            let result = apply_buy_tax_to_output(&assessment, &gross_output).unwrap_or_else(|e| {
                panic!("panic or error for gross={}, bps={}: {:?}", gross, bps, e)
            });

            // Conservation must hold exactly
            let tax = result.tax_cost().amount.get();
            let net = result.net_output().amount.get();
            assert_eq!(
                tax.checked_add(net),
                Some(gross),
                "conservation failed for gross={}, bps={}",
                gross,
                bps
            );

            // Bounded: tax <= gross and net > 0
            assert!(tax <= gross);
            assert!(net > 0);

            // Floor rounding property check:
            // For gross = q * 10_000 + r:
            // expected_tax = q * bps + (r * bps) / 10_000
            let q = gross / 10_000;
            let r = gross % 10_000;
            let exp_tax = q * (bps as u128) + (r * (bps as u128)) / 10_000;
            assert_eq!(tax, exp_tax);
            assert_eq!(net, gross - exp_tax);
        }

        // 10_000 bps (100%) on near-u128::MAX must reject fail closed with ZeroNetOutput
        let assessment_100pct =
            sample_assessment(ChainId::Base, address, 10_000, FreshnessStatus::Fresh);
        let gross_output = sample_gross_output(ChainId::Base, address, gross);
        let err = apply_buy_tax_to_output(&assessment_100pct, &gross_output)
            .expect_err("100% tax on near-u128::MAX must reject with ZeroNetOutput");
        assert_eq!(err, TaxSafetyError::ZeroNetOutput);
    }
}

// =========================================================================
// 4. Stale/resync rejection, mismatched asset/chain, zero gross rejection,
//    and input immutability for every error and success
// =========================================================================

#[test]
fn test_stale_assessment_rejection_and_immutability() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 300, FreshnessStatus::Stale);
    let gross_output = sample_gross_output(ChainId::Base, address, 1_000_000);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let err = apply_buy_tax_to_output(&assessment, &gross_output)
        .expect_err("stale assessment must fail closed");

    assert_eq!(err, TaxSafetyError::StaleObservation);
    assert_eq!(assessment, assessment_before, "assessment was mutated");
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated"
    );
}

#[test]
fn test_resync_required_assessment_rejection_and_immutability() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment =
        sample_assessment(ChainId::Base, address, 300, FreshnessStatus::ResyncRequired);
    let gross_output = sample_gross_output(ChainId::Base, address, 1_000_000);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let err = apply_buy_tax_to_output(&assessment, &gross_output)
        .expect_err("resync-required assessment must fail closed");

    assert_eq!(err, TaxSafetyError::ResyncRequired);
    assert_eq!(assessment, assessment_before, "assessment was mutated");
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated"
    );
}

#[test]
fn test_chain_mismatch_rejection_and_immutability() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 300, FreshnessStatus::Fresh);

    // Provide gross output on Ethereum instead of Base
    let gross_output = sample_gross_output(ChainId::Ethereum, address, 1_000_000);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let err = apply_buy_tax_to_output(&assessment, &gross_output)
        .expect_err("chain mismatch must fail closed");

    assert_eq!(err, TaxSafetyError::ChainMismatch);
    assert_eq!(assessment, assessment_before, "assessment was mutated");
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated"
    );
}

#[test]
fn test_assessed_asset_mismatch_rejection_and_immutability() {
    let address_a = "0x0000000000000000000000000000000000000001";
    let address_b = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address_a, 300, FreshnessStatus::Fresh);

    // Provide gross output with a different token address on the same chain
    let gross_output = sample_gross_output(ChainId::Base, address_b, 1_000_000);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let err = apply_buy_tax_to_output(&assessment, &gross_output)
        .expect_err("assessed asset mismatch must fail closed");

    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);
    assert_eq!(assessment, assessment_before, "assessment was mutated");
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated"
    );
}

#[test]
fn test_zero_gross_amount_rejection_and_immutability() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 300, FreshnessStatus::Fresh);
    let gross_output = sample_gross_output(ChainId::Base, address, 0);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let err = apply_buy_tax_to_output(&assessment, &gross_output)
        .expect_err("zero gross amount must fail closed");

    assert_eq!(err, TaxSafetyError::ZeroGrossOutput);
    assert_eq!(assessment, assessment_before, "assessment was mutated");
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated"
    );
}

#[test]
fn test_success_case_input_immutability() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 500, FreshnessStatus::Fresh);
    let gross_output = sample_gross_output(ChainId::Base, address, 1_000_000);

    let assessment_before = assessment.clone();
    let gross_output_before = gross_output.clone();

    let res = apply_buy_tax_to_output(&assessment, &gross_output).expect("valid buy tax");
    assert_eq!(res.tax_cost().amount.get(), 50_000);
    assert_eq!(res.net_output().amount.get(), 950_000);

    assert_eq!(
        assessment, assessment_before,
        "assessment was mutated on success"
    );
    assert_eq!(
        gross_output, gross_output_before,
        "gross_output was mutated on success"
    );
}

// =========================================================================
// 5. Redaction regressions: Display/Debug must NOT leak raw addresses,
//    timestamps, sequences, or tax values
// =========================================================================

#[test]
fn test_redaction_regression_mismatch_errors() {
    let raw_addr_expected = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw_addr_observed = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let assessment = sample_assessment(
        ChainId::Base,
        raw_addr_expected,
        300,
        FreshnessStatus::Fresh,
    );
    let gross_output = sample_gross_output(ChainId::Base, raw_addr_observed, 1_000_000);

    let err = apply_buy_tax_to_output(&assessment, &gross_output).unwrap_err();
    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);

    let display_str = err.to_string();
    let debug_str = format!("{:?}", err);

    assert_eq!(display_str, "assessed asset mismatch");
    assert_eq!(debug_str, "AssessedAssetMismatch");

    for s in [&display_str, &debug_str] {
        assert!(!s.contains(raw_addr_expected));
        assert!(!s.contains(raw_addr_observed));
        assert!(!s.contains("aaaa"));
        assert!(!s.contains("bbbb"));
        assert!(!s.contains("300"));
    }

    // Chain mismatch
    let gross_output_chain = sample_gross_output(
        ChainId::Other("custom-secret-chain-12345".to_string()),
        raw_addr_expected,
        1_000_000,
    );
    let err_chain = apply_buy_tax_to_output(&assessment, &gross_output_chain).unwrap_err();
    assert_eq!(err_chain, TaxSafetyError::ChainMismatch);

    let chain_display = err_chain.to_string();
    let chain_debug = format!("{:?}", err_chain);

    assert_eq!(chain_display, "chain mismatch");
    assert_eq!(chain_debug, "ChainMismatch");

    for s in [&chain_display, &chain_debug] {
        assert!(!s.contains("custom-secret-chain"));
        assert!(!s.contains("12345"));
        assert!(!s.contains("Base"));
    }
}

#[test]
fn test_redaction_regression_stale_and_resync_errors() {
    let distinct_address = "0x9876543210987654321098765432109876543210";
    let distinct_ts = 9876543210i64;
    let distinct_seq = 123456789u64;
    let distinct_bps = 789u16;

    let mut assessment_stale = sample_assessment(
        ChainId::Base,
        distinct_address,
        distinct_bps,
        FreshnessStatus::Stale,
    );
    assessment_stale.freshness.observed_at_ms = distinct_ts;
    assessment_stale.freshness.sequence = Sequence::new(distinct_seq);

    let gross_output = sample_gross_output(ChainId::Base, distinct_address, 1_000_000);

    let err_stale = apply_buy_tax_to_output(&assessment_stale, &gross_output).unwrap_err();
    assert_eq!(err_stale, TaxSafetyError::StaleObservation);

    let stale_display = err_stale.to_string();
    let stale_debug = format!("{:?}", err_stale);

    assert_eq!(stale_display, "tax observation is stale");
    assert_eq!(stale_debug, "StaleObservation");

    for s in [&stale_display, &stale_debug] {
        assert!(!s.contains("9876543210"));
        assert!(!s.contains("123456789"));
        assert!(!s.contains("789"));
        assert!(!s.contains(distinct_address));
    }

    let mut assessment_resync = sample_assessment(
        ChainId::Base,
        distinct_address,
        distinct_bps,
        FreshnessStatus::ResyncRequired,
    );
    assessment_resync.freshness.observed_at_ms = distinct_ts;
    assessment_resync.freshness.sequence = Sequence::new(distinct_seq);

    let err_resync = apply_buy_tax_to_output(&assessment_resync, &gross_output).unwrap_err();
    assert_eq!(err_resync, TaxSafetyError::ResyncRequired);

    let resync_display = err_resync.to_string();
    let resync_debug = format!("{:?}", err_resync);

    assert_eq!(
        resync_display,
        "tax observation requires resync or clock skew exceeded policy limit"
    );
    assert_eq!(resync_debug, "ResyncRequired");

    for s in [&resync_display, &resync_debug] {
        assert!(!s.contains("9876543210"));
        assert!(!s.contains("123456789"));
        assert!(!s.contains("789"));
        assert!(!s.contains(distinct_address));
    }
}

#[test]
fn test_redaction_regression_zero_net_and_zero_gross_errors() {
    let distinct_address = "0xfeedbeefcafebabefeedbeefcafebabefeedbeef";
    let distinct_gross = 777_888_999_000_111u128;

    // 1. Zero net output (100% tax on distinct gross amount)
    let assessment_100 = sample_assessment(
        ChainId::Base,
        distinct_address,
        10_000,
        FreshnessStatus::Fresh,
    );
    let gross_output = sample_gross_output(ChainId::Base, distinct_address, distinct_gross);

    let err_zero_net = apply_buy_tax_to_output(&assessment_100, &gross_output).unwrap_err();
    assert_eq!(err_zero_net, TaxSafetyError::ZeroNetOutput);

    let zero_net_display = err_zero_net.to_string();
    let zero_net_debug = format!("{:?}", err_zero_net);

    assert_eq!(
        zero_net_display,
        "net output amount must be greater than zero"
    );
    assert_eq!(zero_net_debug, "ZeroNetOutput");

    for s in [&zero_net_display, &zero_net_debug] {
        assert!(!s.contains("777888999"));
        assert!(!s.contains("10000"));
        assert!(!s.contains(distinct_address));
        assert!(!s.contains("feedbeef"));
        assert!(!s.contains("cafebabe"));
    }

    // 2. Zero gross output
    let assessment_normal =
        sample_assessment(ChainId::Base, distinct_address, 300, FreshnessStatus::Fresh);
    let gross_zero = sample_gross_output(ChainId::Base, distinct_address, 0);

    let err_zero_gross = apply_buy_tax_to_output(&assessment_normal, &gross_zero).unwrap_err();
    assert_eq!(err_zero_gross, TaxSafetyError::ZeroGrossOutput);

    let zero_gross_display = err_zero_gross.to_string();
    let zero_gross_debug = format!("{:?}", err_zero_gross);

    assert_eq!(
        zero_gross_display,
        "gross output amount must be greater than zero"
    );
    assert_eq!(zero_gross_debug, "ZeroGrossOutput");

    for s in [&zero_gross_display, &zero_gross_debug] {
        assert!(!s.contains(distinct_address));
        assert!(!s.contains("feedbeef"));
        assert!(!s.contains("300"));
    }
}

#[test]
fn test_buy_tax_output_serde_round_trip() {
    let address = "0x0000000000000000000000000000000000000002";
    let assessment = sample_assessment(ChainId::Base, address, 250, FreshnessStatus::Fresh);
    let gross_output = sample_gross_output(ChainId::Base, address, 1_000_000);

    let result: BuyOutputTax = apply_buy_tax_to_output(&assessment, &gross_output).unwrap();

    let json = serde_json::to_string(&result).expect("serialize BuyTaxOutput");
    let deserialized: BuyTaxOutput = serde_json::from_str(&json).expect("deserialize BuyTaxOutput");

    assert_eq!(result, deserialized);
}
