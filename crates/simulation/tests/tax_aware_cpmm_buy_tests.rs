//! Deterministic unit and integration tests for buy-side tax-aware CPMM simulation composition.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use simulation::{
    simulate_cpmm_exact_input_buy_tax, simulate_tax_aware_cpmm_buy,
    simulate_tax_aware_cpmm_buy_directed, simulate_tax_aware_cpmm_buy_exact_input,
    simulate_tax_aware_cpmm_buy_swap, CpmmExactInputRequest, CpmmSimulationErrorClass,
    CpmmSimulationKernel, TaxAwareCpmmBuyError, TaxAwareCpmmBuyQuote, TaxAwareCpmmBuyResult,
    TaxAwareSimulationError,
};
use tax_engine::{TaxAssessment, TaxSafetyError};

fn sample_asset(chain: ChainId, address: &str) -> AssetId {
    AssetId::new(chain, address).expect("valid asset")
}

fn sample_pool(
    chain: ChainId,
    token_0_addr: &str,
    token_1_addr: &str,
    reserve_0: u128,
    reserve_1: u128,
    fee_bps: u16,
) -> CpmmPoolState {
    CpmmPoolState {
        token_0: sample_asset(chain.clone(), token_0_addr),
        token_1: sample_asset(chain, token_1_addr),
        decimals_0: 6,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(reserve_0),
        reserve_1: AtomicAmount::new(reserve_1),
        total_lp_supply: Some(AtomicAmount::new(10_000_000)),
        fee_bps: Bps::new(fee_bps).expect("valid fee bps"),
    }
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

const USDC_ADDR: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WETH_ADDR: &str = "0x4200000000000000000000000000000000000006";

// =========================================================================
// 1. Known direct CPMM buy quote where output tax floor-rounding produces
//    expected gross/tax/net values and exact conservation: gross = tax + net
// =========================================================================

#[test]
fn test_known_cpmm_buy_quote_with_tax_and_conservation() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    ); // 30 bps CPMM fee

    // --- Direction 0 -> 1: Buying WETH with USDC ---
    // amount_in = 10_000 USDC
    // fee = floor(10_000 * 30 / 10_000) = 30
    // effective_input = 9_970
    // gross_output = floor(9_970 * 2_000_000 / (1_000_000 + 9_970)) = 19_743 WETH
    // Assessment on WETH: buy_tax_bps = 250 (2.5%)
    // tax_cost = floor(19_743 * 250 / 10_000) = floor(4_935_750 / 10_000) = 493
    // net_output = 19_743 - 493 = 19_250
    let assessment_weth = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Fresh);
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    let result: TaxAwareCpmmBuyResult =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_weth)
            .expect("simulation must succeed");

    // Exact gross quote validation
    assert_eq!(result.cpmm_quote.input.asset, pool.token_0);
    assert_eq!(result.cpmm_quote.input.amount.get(), 10_000);
    assert_eq!(result.cpmm_quote.pool_fee.amount.get(), 30);
    assert_eq!(result.cpmm_quote.effective_input.amount.get(), 9_970);
    assert_eq!(result.cpmm_quote.output.asset, pool.token_1);
    assert_eq!(result.cpmm_quote.output.amount.get(), 19_743);

    // Tax output economics
    assert_eq!(result.gross_output().asset, pool.token_1);
    assert_eq!(result.gross_output().amount.get(), 19_743);
    assert_eq!(result.tax_cost().asset, pool.token_1);
    assert_eq!(result.tax_cost().amount.get(), 493);
    assert_eq!(result.net_output().asset, pool.token_1);
    assert_eq!(result.net_output().amount.get(), 19_250);
    assert_eq!(result.net_received_output().amount.get(), 19_250);

    // Gross output strictly equals CPMM quote output
    assert_eq!(result.gross_output(), &result.cpmm_quote.output);

    // Output conservation: gross == tax + net
    assert_eq!(
        result.gross_output().amount.get(),
        result.tax_cost().amount.get() + result.net_output().amount.get()
    );

    // Reserves and fees preserved
    assert_eq!(result.cpmm_quote.resulting_reserve_0.get(), 1_010_000);
    assert_eq!(result.cpmm_quote.resulting_reserve_1.get(), 1_980_257);

    // --- Direction 1 -> 0: Buying USDC with WETH ---
    // amount_in = 20_000 WETH
    // fee = 60
    // effective_input = 19_940
    // gross_output = 9_871 USDC
    // Assessment on USDC: buy_tax_bps = 500 (5.0%)
    // tax_cost = floor(9_871 * 500 / 10_000) = floor(4_935_500 / 10_000) = 493
    // net_output = 9_871 - 493 = 9_378
    let assessment_usdc = sample_assessment(ChainId::Base, USDC_ADDR, 500, FreshnessStatus::Fresh);
    let req_rev = CpmmExactInputRequest::new(pool.token_1.clone(), AtomicAmount::new(20_000));

    let result_rev = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req_rev, &assessment_usdc)
        .expect("simulation must succeed");

    assert_eq!(result_rev.gross_output().asset, pool.token_0);
    assert_eq!(result_rev.gross_output().amount.get(), 9_871);
    assert_eq!(result_rev.tax_cost().asset, pool.token_0);
    assert_eq!(result_rev.tax_cost().amount.get(), 493);
    assert_eq!(result_rev.net_output().asset, pool.token_0);
    assert_eq!(result_rev.net_output().amount.get(), 9_378);

    assert_eq!(
        result_rev.gross_output().amount.get(),
        result_rev.tax_cost().amount.get() + result_rev.net_output().amount.get()
    );
}

#[test]
fn test_tax_floor_rounding_sub_unit_remainders_and_conservation() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    // Gross output is 19_743

    let tax_vectors: &[(u16, u128, u128)] = &[
        // (bps, expected_tax, expected_net)
        (1, 1, 19_742),         // 19743 * 1 / 10000 = 1.9743 -> floor = 1
        (5, 9, 19_734),         // 19743 * 5 / 10000 = 9.8715 -> floor = 9
        (10, 19, 19_724),       // 19743 * 10 / 10000 = 19.743 -> floor = 19
        (50, 98, 19_645),       // 19743 * 50 / 10000 = 98.715 -> floor = 98
        (100, 197, 19_546),     // 19743 * 100 / 10000 = 197.43 -> floor = 197
        (333, 657, 19_086),     // 19743 * 333 / 10000 = 657.4419 -> floor = 657
        (1_000, 1_974, 17_769), // 19743 * 1000 / 10000 = 1974.3 -> floor = 1974
        (9_999, 19_741, 2),     // 19743 * 9999 / 10000 = 19741.0257 -> floor = 19741
    ];

    for &(bps, exp_tax, exp_net) in tax_vectors {
        let assessment = sample_assessment(ChainId::Base, WETH_ADDR, bps, FreshnessStatus::Fresh);
        let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment)
            .unwrap_or_else(|e| panic!("failed for bps {}: {:?}", bps, e));

        assert_eq!(
            quote.tax_cost().amount.get(),
            exp_tax,
            "mismatch for bps {}",
            bps
        );
        assert_eq!(
            quote.net_output().amount.get(),
            exp_net,
            "mismatch for bps {}",
            bps
        );
        assert_eq!(
            quote.gross_output().amount.get(),
            quote.tax_cost().amount.get() + quote.net_output().amount.get(),
            "conservation failed for bps {}",
            bps
        );
    }
}

// =========================================================================
// 2. Zero buy-tax success and max-tax/zero-net rejection
// =========================================================================

#[test]
fn test_zero_buy_tax_success() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    let assessment_zero = sample_assessment(ChainId::Base, WETH_ADDR, 0, FreshnessStatus::Fresh);

    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_zero)
        .expect("zero-tax buy must succeed");

    assert_eq!(quote.gross_output().amount.get(), 19_743);
    assert_eq!(quote.tax_cost().amount.get(), 0);
    assert_eq!(quote.net_output().amount.get(), 19_743);
    assert_eq!(quote.net_output(), quote.gross_output());
    assert_eq!(
        quote.gross_output().amount.get(),
        quote.tax_cost().amount.get() + quote.net_output().amount.get()
    );
}

#[test]
fn test_max_tax_and_zero_net_rejection() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    // 100% tax = 10_000 bps -> net output = 0 -> must fail closed with ZeroNetOutput
    let assessment_100 =
        sample_assessment(ChainId::Base, WETH_ADDR, 10_000, FreshnessStatus::Fresh);
    let err: TaxAwareCpmmBuyError =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_100)
            .expect_err("100% tax must fail closed");

    assert_eq!(
        err,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetOutput)
    );

    // Small fill where gross = 1 and 100% tax yields net = 0
    let pool_large = sample_pool(ChainId::Base, USDC_ADDR, WETH_ADDR, 1_000_000, 2_000_000, 0);
    let req_tiny = CpmmExactInputRequest::new(pool_large.token_0.clone(), AtomicAmount::new(1));
    let quote_cpmm = simulation::simulate_cpmm_exact_input(&pool_large, &req_tiny).unwrap();
    assert_eq!(quote_cpmm.output.amount.get(), 1); // gross is 1

    let err_tiny = simulate_tax_aware_cpmm_buy_exact_input(&pool_large, &req_tiny, &assessment_100)
        .expect_err("gross=1 with 100% tax must fail closed");
    assert_eq!(
        err_tiny,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetOutput)
    );
}

// =========================================================================
// 3. Stale and resync-required assessments; assessed output asset/chain mismatch
// =========================================================================

#[test]
fn test_stale_and_resync_assessments_fail_closed() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    // 3A: Stale assessment
    let stale_assessment = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Stale);
    let err_stale = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &stale_assessment)
        .expect_err("stale assessment must fail closed");
    assert_eq!(
        err_stale,
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );

    // 3B: ResyncRequired assessment
    let resync_assessment = sample_assessment(
        ChainId::Base,
        WETH_ADDR,
        250,
        FreshnessStatus::ResyncRequired,
    );
    let err_resync = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &resync_assessment)
        .expect_err("resync-required assessment must fail closed");
    assert_eq!(
        err_resync,
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
}

#[test]
fn test_assessed_output_asset_and_chain_mismatch_fail_closed() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    // 3C: Assessment targets token_in instead of expected token_out (WETH)
    let assessment_wrong_asset =
        sample_assessment(ChainId::Base, USDC_ADDR, 250, FreshnessStatus::Fresh);
    let err_asset = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_wrong_asset)
        .expect_err("mismatched assessed asset must fail closed");
    assert_eq!(
        err_asset,
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // 3D: Assessment targets foreign asset
    let foreign_addr = "0x1111111111111111111111111111111111111111";
    let assessment_foreign =
        sample_assessment(ChainId::Base, foreign_addr, 250, FreshnessStatus::Fresh);
    let err_foreign = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_foreign)
        .expect_err("foreign assessed asset must fail closed");
    assert_eq!(
        err_foreign,
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // 3E: Assessment chain mismatch (e.g. Ethereum or Solana vs Base pool)
    let assessment_solana = sample_assessment(
        ChainId::Solana,
        "So11111111111111111111111111111111111111112",
        250,
        FreshnessStatus::Fresh,
    );
    let err_chain = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment_solana)
        .expect_err("chain mismatch must fail closed");
    assert_eq!(
        err_chain,
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
}

// =========================================================================
// 4. Underlying rejected CPMM request; verify pool/request/assessment
//    immutability across every error
// =========================================================================

#[test]
fn test_underlying_rejected_cpmm_requests_and_immutability() {
    let base_pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let base_req = CpmmExactInputRequest::new(base_pool.token_0.clone(), AtomicAmount::new(10_000));
    let base_assessment = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Fresh);

    // Error case 1: Zero input amount
    {
        let pool = base_pool.clone();
        let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::ZERO);
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroInputAmount)
        );
        assert_eq!(pool, base_pool);
        assert_eq!(req.amount_in, AtomicAmount::ZERO);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 2: Zero pool reserve
    {
        let mut pool = base_pool.clone();
        pool.reserve_0 = AtomicAmount::ZERO;
        let pool_before = pool.clone();
        let req = base_req.clone();
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroReserve)
        );
        assert_eq!(pool, pool_before);
        assert_eq!(req, base_req);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 3: Invalid pool fee bps (10_000 bps)
    {
        let mut pool = base_pool.clone();
        pool.fee_bps = Bps::new(10_000).unwrap();
        let pool_before = pool.clone();
        let req = base_req.clone();
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::InvalidFeeBps)
        );
        assert_eq!(pool, pool_before);
        assert_eq!(req, base_req);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 4: Asset not found in pool
    {
        let foreign_asset =
            sample_asset(ChainId::Base, "0x9999999999999999999999999999999999999999");
        let pool = base_pool.clone();
        let req = CpmmExactInputRequest::new(foreign_asset, AtomicAmount::new(10_000));
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool)
        );
        assert_eq!(pool, base_pool);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 5: Caller-asserted output asset mismatch
    {
        let foreign_asset =
            sample_asset(ChainId::Base, "0x9999999999999999999999999999999999999999");
        let pool = base_pool.clone();
        let req = CpmmExactInputRequest::new_directed(
            pool.token_0.clone(),
            AtomicAmount::new(10_000),
            foreign_asset,
        );
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch)
        );
        assert_eq!(pool, base_pool);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 6: CPMM chain mismatch
    {
        let solana_asset = sample_asset(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        );
        let pool = base_pool.clone();
        let req = CpmmExactInputRequest::new(solana_asset, AtomicAmount::new(10_000));
        let assessment = base_assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ChainMismatch)
        );
        assert_eq!(pool, base_pool);
        assert_eq!(assessment, base_assessment);
    }

    // Error case 7: Stale assessment immutability
    {
        let pool = base_pool.clone();
        let req = base_req.clone();
        let assessment = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Stale);
        let assessment_before = assessment.clone();

        let err = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap_err();
        assert_eq!(
            err,
            TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
        );
        assert_eq!(pool, base_pool);
        assert_eq!(req, base_req);
        assert_eq!(assessment, assessment_before);
    }

    // Success immutability
    {
        let pool = base_pool.clone();
        let req = base_req.clone();
        let assessment = base_assessment.clone();

        let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment).unwrap();
        assert_eq!(pool, base_pool);
        assert_eq!(req, base_req);
        assert_eq!(assessment, base_assessment);
        assert_eq!(quote.gross_output().amount.get(), 19_743);
    }
}

// =========================================================================
// 5. Large safe integer/vector demonstrating composed exact arithmetic
//    does not use floats or overflow
// =========================================================================

#[test]
fn test_large_safe_integer_vector_exact_arithmetic() {
    // Large reserves: 10^30 atomic units (exceeds u64 max by many orders of magnitude)
    let large_res_0 = 1_000_000_000_000_000_000_000_000_000_000u128;
    let large_res_1 = 2_000_000_000_000_000_000_000_000_000_000u128;
    let large_in = 10_000_000_000_000_000_000_000_000_000u128; // 10^28
    let pool_fee_bps = 300u16; // 3%
    let buy_tax_bps = 750u16; // 7.5%

    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        large_res_0,
        large_res_1,
        pool_fee_bps,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(large_in));
    let assessment = sample_assessment(
        ChainId::Base,
        WETH_ADDR,
        buy_tax_bps,
        FreshnessStatus::Fresh,
    );

    // Compute expected values mathematically with exact integer arithmetic
    let exp_fee = large_in * 300 / 10_000;
    let exp_eff_in = large_in - exp_fee;
    // Use simulation's wide mul & div helpers to calculate exact reference
    let (hi, lo) = simulation::mul_u128_wide(exp_eff_in, large_res_1);
    let den = large_res_0 + exp_eff_in;
    let exp_gross = simulation::div_u256_by_u128_floor(hi, lo, den).unwrap();

    // Tax calculation reference:
    // q = exp_gross / 10_000, r = exp_gross % 10_000
    // exp_tax = q * 750 + (r * 750) / 10_000
    let q = exp_gross / 10_000;
    let r = exp_gross % 10_000;
    let exp_tax = q * 750 + (r * 750) / 10_000;
    let exp_net = exp_gross - exp_tax;

    let quote = simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &assessment)
        .expect("large safe integer simulation must succeed without overflow");

    assert_eq!(quote.cpmm_quote.pool_fee.amount.get(), exp_fee);
    assert_eq!(quote.cpmm_quote.effective_input.amount.get(), exp_eff_in);
    assert_eq!(quote.gross_output().amount.get(), exp_gross);
    assert_eq!(quote.tax_cost().amount.get(), exp_tax);
    assert_eq!(quote.net_output().amount.get(), exp_net);

    // Conservation strictly holds on massive values
    assert_eq!(
        quote.gross_output().amount.get(),
        quote.tax_cost().amount.get() + quote.net_output().amount.get()
    );
    assert_ne!(quote.tax_cost().amount.get(), 0);
    assert_ne!(quote.net_output().amount.get(), 0);
}

// =========================================================================
// 6. Display / Debug redaction with distinct raw addresses, amounts,
//    reserve values, timestamps/sequences, and tax values
// =========================================================================

#[test]
fn test_display_and_debug_redaction_comprehensive() {
    let distinct_addr_0 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let distinct_addr_1 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let distinct_foreign_addr = "0xcccccccccccccccccccccccccccccccccccccccc";
    let distinct_amount_in = 777_888_999_000_111u128;
    let distinct_reserve_0 = 555_666_777_888_999u128;
    let distinct_reserve_1 = 444_333_222_111_000u128;
    let distinct_observed_ms = 12_345_678i64;
    let distinct_evaluated_ms = 12_399_999i64;
    let distinct_slot = 987_654_321u64;
    let distinct_tax_bps = 345u16;

    let pool = sample_pool(
        ChainId::Base,
        distinct_addr_0,
        distinct_addr_1,
        distinct_reserve_0,
        distinct_reserve_1,
        30,
    );

    let freshness_stale = SafeFreshnessMeta {
        status: FreshnessStatus::Stale,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 54_321,
        sequence: Sequence::new(distinct_slot),
    };
    let stale_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_1),
        ChainId::Base,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_stale,
        distinct_slot,
    );

    let freshness_fresh = SafeFreshnessMeta {
        status: FreshnessStatus::Fresh,
        observed_at_ms: distinct_observed_ms,
        evaluated_at_ms: distinct_evaluated_ms,
        age_ms: 5_000,
        sequence: Sequence::new(distinct_slot),
    };
    let normal_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_1),
        ChainId::Base,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        freshness_fresh,
        distinct_slot,
    );

    let sensitive_snippets = &[
        "aaaaaaaa",
        "bbbbbbbb",
        "cccccccc",
        "777888999",
        "555666777",
        "444333222",
        "12345678",
        "12399999",
        "987654321",
        "54321",
        "345",
        "10000",
    ];

    let assert_redacted = |err: &TaxAwareSimulationError, label: &str| {
        let display_str = err.to_string();
        let debug_str = format!("{:?}", err);

        for snippet in sensitive_snippets {
            assert!(
                !display_str.contains(snippet),
                "[{}] Display leaked '{}': {}",
                label,
                snippet,
                display_str
            );
            assert!(
                !debug_str.contains(snippet),
                "[{}] Debug leaked '{}': {}",
                label,
                snippet,
                debug_str
            );
        }
    };

    // 6A: Stale assessment error
    let req =
        CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(distinct_amount_in));
    let err_stale =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &stale_assessment).unwrap_err();
    assert_eq!(
        err_stale,
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );
    assert_redacted(&err_stale, "StaleObservation");

    // 6B: ResyncRequired assessment error
    let mut resync_assessment = stale_assessment.clone();
    resync_assessment.freshness.status = FreshnessStatus::ResyncRequired;
    let err_resync =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &resync_assessment).unwrap_err();
    assert_eq!(
        err_resync,
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_redacted(&err_resync, "ResyncRequired");

    // 6C: Assessed asset mismatch error
    let mismatched_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_foreign_addr),
        ChainId::Base,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_mismatch =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &mismatched_assessment).unwrap_err();
    assert_eq!(
        err_mismatch,
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );
    assert_redacted(&err_mismatch, "AssessedAssetMismatch");

    // 6D: Chain mismatch error
    let solana_assessment = TaxAssessment::new(
        sample_asset(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        ),
        ChainId::Solana,
        Bps::new(distinct_tax_bps).unwrap(),
        Bps::new(0).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_chain =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &solana_assessment).unwrap_err();
    assert_eq!(
        err_chain,
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
    assert_redacted(&err_chain, "ChainMismatch");

    // 6E: Zero net output error (100% tax)
    let max_tax_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_1),
        ChainId::Base,
        Bps::new(10_000).unwrap(),
        Bps::new(0).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_zero_net =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req, &max_tax_assessment).unwrap_err();
    assert_eq!(
        err_zero_net,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetOutput)
    );
    assert_redacted(&err_zero_net, "ZeroNetOutput");

    // 6F: CPMM AssetNotFoundInPool error
    let foreign_token = sample_asset(ChainId::Base, distinct_foreign_addr);
    let req_foreign =
        CpmmExactInputRequest::new(foreign_token, AtomicAmount::new(distinct_amount_in));
    let err_not_found =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req_foreign, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_not_found,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool)
    );
    assert_redacted(&err_not_found, "AssetNotFoundInPool");

    // 6G: CPMM OutputAssetMismatch error
    let req_out_mismatch = CpmmExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(distinct_amount_in),
        sample_asset(ChainId::Base, distinct_foreign_addr),
    );
    let err_out_mismatch =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req_out_mismatch, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_out_mismatch,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch)
    );
    assert_redacted(&err_out_mismatch, "OutputAssetMismatch");

    // 6H: CPMM ZeroInputAmount error
    let req_zero_in = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::ZERO);
    let err_zero_in =
        simulate_tax_aware_cpmm_buy_exact_input(&pool, &req_zero_in, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_zero_in,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroInputAmount)
    );
    assert_redacted(&err_zero_in, "ZeroInputAmount");

    // 6I: CPMM ZeroReserve error
    let mut zero_res_pool = pool.clone();
    zero_res_pool.reserve_0 = AtomicAmount::ZERO;
    let err_zero_res =
        simulate_tax_aware_cpmm_buy_exact_input(&zero_res_pool, &req, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_zero_res,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroReserve)
    );
    assert_redacted(&err_zero_res, "ZeroReserve");

    // 6J: CPMM InvalidFeeBps error
    let mut invalid_fee_pool = pool.clone();
    invalid_fee_pool.fee_bps = Bps::new(10_000).unwrap();
    let err_fee =
        simulate_tax_aware_cpmm_buy_exact_input(&invalid_fee_pool, &req, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_fee,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::InvalidFeeBps)
    );
    assert_redacted(&err_fee, "InvalidFeeBps");
}

// =========================================================================
// 7. Convenience helpers and Serde round-trip
// =========================================================================

#[test]
fn test_convenience_helpers_and_serde_round_trip() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    let assessment = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Fresh);

    // 7A: simulate_tax_aware_cpmm_buy
    let q1 = simulate_tax_aware_cpmm_buy(&pool, &req, &assessment).unwrap();

    // 7B: simulate_tax_aware_cpmm_buy_swap
    let q2 = simulate_tax_aware_cpmm_buy_swap(
        &pool,
        &pool.token_0,
        AtomicAmount::new(10_000),
        &assessment,
    )
    .unwrap();

    // 7C: simulate_tax_aware_cpmm_buy_directed
    let q3 = simulate_tax_aware_cpmm_buy_directed(
        &pool,
        &pool.token_0,
        AtomicAmount::new(10_000),
        &pool.token_1,
        &assessment,
    )
    .unwrap();

    // 7D: simulate_cpmm_exact_input_buy_tax
    let q4 = simulate_cpmm_exact_input_buy_tax(&pool, &req, &assessment).unwrap();

    // 7E: req.simulate_with_buy_tax
    let q5 = req.simulate_with_buy_tax(&pool, &assessment).unwrap();

    // 7F: CpmmSimulationKernel::simulate_tax_aware_buy_exact_input
    let q6 =
        CpmmSimulationKernel::simulate_tax_aware_buy_exact_input(&pool, &req, &assessment).unwrap();

    assert_eq!(q1, q2);
    assert_eq!(q1, q3);
    assert_eq!(q1, q4);
    assert_eq!(q1, q5);
    assert_eq!(q1, q6);

    // Serde round-trip
    let json = serde_json::to_string(&q1).expect("serialize TaxAwareCpmmBuyQuote");
    let deserialized: TaxAwareCpmmBuyQuote =
        serde_json::from_str(&json).expect("deserialize TaxAwareCpmmBuyQuote");
    assert_eq!(q1, deserialized);
}
