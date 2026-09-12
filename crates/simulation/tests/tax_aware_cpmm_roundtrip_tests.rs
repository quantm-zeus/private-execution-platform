//! Deterministic unit and integration tests for tax-aware CPMM buy/sell round-trip simulation.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use simulation::{
    simulate_tax_aware_cpmm_roundtrip_exact_input, simulate_tax_aware_cpmm_sell_exact_input,
    CpmmExactInputRequest, CpmmSimulationErrorClass, TaxAwareCpmmRoundtripQuote,
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
    sell_tax_bps: u16,
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
        Bps::new(sell_tax_bps).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

const USDC_ADDR: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WETH_ADDR: &str = "0x4200000000000000000000000000000000000006";

// =========================================================================
// 1. Known round-trip vector: buy -> post-buy staged reserves -> sell
//    Sell quote must differ from an incorrect original-reserves sell.
//    Exact conservation of output on buy, input on sell, and fee arithmetic.
// =========================================================================

#[test]
fn test_known_roundtrip_vector_staged_reserves_and_conservation() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    ); // 30 bps CPMM pool fee

    // --- Direction 0 -> 1 -> 0: Buy WETH with USDC, sell acquired WETH back for USDC ---
    //
    // 1. Buy leg:
    //    amount_in = 10_000 USDC
    //    fee = floor(10_000 * 30 / 10_000) = 30 USDC
    //    effective_input = 9_970 USDC
    //    gross_output = floor(9_970 * 2_000_000 / (1_000_000 + 9_970)) = 19_743 WETH
    //    buy_tax (250 bps = 2.5%):
    //      tax_cost = floor(19_743 * 250 / 10_000) = 493 WETH
    //      net_output = 19_743 - 493 = 19_250 WETH
    //    resulting_reserves:
    //      reserve_0 = 1_000_000 + 10_000 = 1_010_000 USDC
    //      reserve_1 = 2_000_000 - 19_743 = 1_980_257 WETH
    //
    // 2. Sell leg executed on staged reserves (reserve_0: 1_010_000, reserve_1: 1_980_257):
    //    gross_input = 19_250 WETH
    //    sell_tax (200 bps = 2.0%):
    //      tax_cost = floor(19_250 * 200 / 10_000) = 385 WETH
    //      net_transferable_input = 19_250 - 385 = 18_865 WETH
    //    CPMM swap on staged reserves:
    //      fee = floor(18_865 * 30 / 10_000) = 56 WETH
    //      effective_input = 18_865 - 56 = 18_809 WETH
    //      gross_output = floor(18_809 * 1_010_000 / (1_980_257 + 18_809))
    //                   = floor(18_997_090_000 / 1_999_066) = 9_502 USDC
    //      resulting_reserve_1 = 1_980_257 + 18_865 = 1_999_122 WETH
    //      resulting_reserve_0 = 1_010_000 - 9_502 = 1_000_498 USDC
    let buy_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 250, 0, FreshnessStatus::Fresh);
    let sell_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 0, 200, FreshnessStatus::Fresh);
    let buy_req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    let rt = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &buy_req,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("roundtrip simulation must succeed");

    // Buy leg checks
    assert_eq!(rt.buy_quote.cpmm_quote.input.asset, pool.token_0);
    assert_eq!(rt.buy_quote.cpmm_quote.input.amount.get(), 10_000);
    assert_eq!(rt.buy_quote.cpmm_quote.pool_fee.amount.get(), 30);
    assert_eq!(rt.buy_quote.cpmm_quote.effective_input.amount.get(), 9_970);
    assert_eq!(
        rt.buy_quote.cpmm_quote.input.amount.get(),
        rt.buy_quote.cpmm_quote.pool_fee.amount.get()
            + rt.buy_quote.cpmm_quote.effective_input.amount.get()
    );
    assert_eq!(rt.buy_quote.cpmm_quote.output.asset, pool.token_1);
    assert_eq!(rt.buy_quote.cpmm_quote.output.amount.get(), 19_743);
    assert_eq!(
        rt.buy_quote.tax_output.gross_output,
        rt.buy_quote.cpmm_quote.output
    );
    assert_eq!(rt.buy_quote.tax_output.tax_cost.amount.get(), 493);
    assert_eq!(rt.buy_quote.tax_output.net_output.amount.get(), 19_250);

    // Buy conservation: gross == tax_cost + net_output
    assert_eq!(
        rt.buy_quote.tax_output.gross_output.amount.get(),
        rt.buy_quote.tax_output.tax_cost.amount.get()
            + rt.buy_quote.tax_output.net_output.amount.get()
    );

    // Staged reserves from buy quote
    assert_eq!(rt.buy_quote.cpmm_quote.resulting_reserve_0.get(), 1_010_000);
    assert_eq!(rt.buy_quote.cpmm_quote.resulting_reserve_1.get(), 1_980_257);

    // Hand-off: sell gross input exactly equals buy net output
    assert_eq!(
        rt.sell_quote.tax_input.gross_input,
        rt.buy_quote.tax_output.net_output
    );
    assert_eq!(rt.sell_quote.tax_input.gross_input.asset, pool.token_1);
    assert_eq!(rt.sell_quote.tax_input.gross_input.amount.get(), 19_250);

    // Sell tax economics: tax is deducted BEFORE CPMM simulation
    assert_eq!(rt.sell_quote.tax_input.tax_cost.amount.get(), 385);
    assert_eq!(
        rt.sell_quote.tax_input.net_transferable_input.amount.get(),
        18_865
    );

    // Sell conservation: gross == tax_cost + net_transferable_input
    assert_eq!(
        rt.sell_quote.tax_input.gross_input.amount.get(),
        rt.sell_quote.tax_input.tax_cost.amount.get()
            + rt.sell_quote.tax_input.net_transferable_input.amount.get()
    );

    // CPMM sell quote economics executed on staged reserves
    assert_eq!(
        rt.sell_quote.cpmm_quote.input,
        rt.sell_quote.tax_input.net_transferable_input
    );
    assert_eq!(rt.sell_quote.cpmm_quote.pool_fee.amount.get(), 56);
    assert_eq!(
        rt.sell_quote.cpmm_quote.effective_input.amount.get(),
        18_809
    );
    assert_eq!(
        rt.sell_quote.cpmm_quote.input.amount.get(),
        rt.sell_quote.cpmm_quote.pool_fee.amount.get()
            + rt.sell_quote.cpmm_quote.effective_input.amount.get()
    );

    // Output returned in the original buy input asset
    assert_eq!(rt.sell_quote.cpmm_quote.output.asset, pool.token_0);
    assert_eq!(rt.sell_quote.cpmm_quote.output.amount.get(), 9_502);

    // Staged resulting reserves after sell
    assert_eq!(
        rt.sell_quote.cpmm_quote.resulting_reserve_1.get(),
        1_999_122
    );
    assert_eq!(
        rt.sell_quote.cpmm_quote.resulting_reserve_0.get(),
        1_000_498
    );

    // CRITICAL: Prove that the sell quote MUST differ from an incorrect original-reserves sell!
    let incorrect_sell_req = CpmmExactInputRequest::new_directed(
        rt.buy_quote.tax_output.net_output.asset.clone(),
        rt.buy_quote.tax_output.net_output.amount,
        pool.token_0.clone(),
    );
    let incorrect_sell =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &incorrect_sell_req, &sell_assessment)
            .expect("incorrect simulation against original pool");
    // Against original reserves (reserve_0: 1_000_000, reserve_1: 2_000_000):
    // Output is 9_316 USDC, whereas against staged reserves it is 9_502 USDC!
    assert_eq!(incorrect_sell.cpmm_quote.output.amount.get(), 9_316);
    assert_ne!(
        rt.sell_quote.cpmm_quote.output.amount.get(),
        incorrect_sell.cpmm_quote.output.amount.get()
    );

    // --- Reverse direction 1 -> 0 -> 1: Buy USDC with WETH, sell acquired USDC back for WETH ---
    let buy_assessment_usdc =
        sample_assessment(ChainId::Base, USDC_ADDR, 300, 0, FreshnessStatus::Fresh);
    let sell_assessment_usdc =
        sample_assessment(ChainId::Base, USDC_ADDR, 0, 150, FreshnessStatus::Fresh);
    let buy_req_rev = CpmmExactInputRequest::new(pool.token_1.clone(), AtomicAmount::new(20_000));

    let rt_rev = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &buy_req_rev,
        &buy_assessment_usdc,
        &sell_assessment_usdc,
    )
    .expect("reverse roundtrip simulation must succeed");

    assert_eq!(rt_rev.buy_quote.cpmm_quote.input.asset, pool.token_1);
    assert_eq!(rt_rev.buy_quote.cpmm_quote.output.asset, pool.token_0);
    assert_eq!(
        rt_rev.sell_quote.tax_input.gross_input,
        rt_rev.buy_quote.tax_output.net_output
    );
    assert_eq!(rt_rev.sell_quote.cpmm_quote.output.asset, pool.token_1);

    // Reverse sell output also strictly differs from incorrect original-reserves sell
    let incorrect_rev_sell = simulate_tax_aware_cpmm_sell_exact_input(
        &pool,
        &CpmmExactInputRequest::new_directed(
            rt_rev.buy_quote.tax_output.net_output.asset.clone(),
            rt_rev.buy_quote.tax_output.net_output.amount,
            pool.token_1.clone(),
        ),
        &sell_assessment_usdc,
    )
    .expect("incorrect reverse simulation against original pool");
    assert_ne!(
        rt_rev.sell_quote.cpmm_quote.output.amount.get(),
        incorrect_rev_sell.cpmm_quote.output.amount.get()
    );
}

// =========================================================================
// 2. Zero-tax success and 100% max-tax zero-net rejection
// =========================================================================

#[test]
fn test_zero_tax_and_max_tax_fail_closed() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    // 2A: Zero tax on both buy and sell
    let assessment_zero = sample_assessment(ChainId::Base, WETH_ADDR, 0, 0, FreshnessStatus::Fresh);
    let rt_zero = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &assessment_zero,
        &assessment_zero,
    )
    .expect("zero tax roundtrip must succeed");

    assert_eq!(rt_zero.buy_quote.tax_output.tax_cost.amount.get(), 0);
    assert_eq!(
        rt_zero.buy_quote.tax_output.net_output.amount.get(),
        rt_zero.buy_quote.tax_output.gross_output.amount.get()
    );
    assert_eq!(rt_zero.sell_quote.tax_input.tax_cost.amount.get(), 0);
    assert_eq!(
        rt_zero
            .sell_quote
            .tax_input
            .net_transferable_input
            .amount
            .get(),
        rt_zero.sell_quote.tax_input.gross_input.amount.get()
    );

    // 2B: 100% buy tax (10,000 bps) -> fails closed with ZeroNetOutput
    let assessment_100_buy =
        sample_assessment(ChainId::Base, WETH_ADDR, 10_000, 0, FreshnessStatus::Fresh);
    let err_buy_100 = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &assessment_100_buy,
        &assessment_zero,
    )
    .unwrap_err();
    assert_eq!(
        err_buy_100,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetOutput)
    );

    // 2C: 100% sell tax (10,000 bps) -> fails closed with ZeroNetInput
    let assessment_100_sell =
        sample_assessment(ChainId::Base, WETH_ADDR, 0, 10_000, FreshnessStatus::Fresh);
    let err_sell_100 = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &assessment_zero,
        &assessment_100_sell,
    )
    .unwrap_err();
    assert_eq!(
        err_sell_100,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );
}

// =========================================================================
// 3. Immutability of pool, request, and both assessments across success & failures
// =========================================================================

#[test]
fn test_immutability_across_success_and_all_failures() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    let buy_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 200, 0, FreshnessStatus::Fresh);
    let sell_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 0, 200, FreshnessStatus::Fresh);

    let pool_before = pool.clone();
    let req_before = req.clone();
    let buy_assessment_before = buy_assessment.clone();
    let sell_assessment_before = sell_assessment.clone();

    // 3A: On success
    let _ = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("success");

    assert_eq!(pool, pool_before);
    assert_eq!(req, req_before);
    assert_eq!(buy_assessment, buy_assessment_before);
    assert_eq!(sell_assessment, sell_assessment_before);

    // 3B: On failure - Stale buy assessment
    let stale_buy = sample_assessment(ChainId::Base, WETH_ADDR, 200, 0, FreshnessStatus::Stale);
    let stale_buy_before = stale_buy.clone();
    let _ =
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &stale_buy, &sell_assessment)
            .unwrap_err();
    assert_eq!(pool, pool_before);
    assert_eq!(req, req_before);
    assert_eq!(stale_buy, stale_buy_before);
    assert_eq!(sell_assessment, sell_assessment_before);

    // 3C: On failure - Stale sell assessment
    let stale_sell = sample_assessment(ChainId::Base, WETH_ADDR, 0, 200, FreshnessStatus::Stale);
    let stale_sell_before = stale_sell.clone();
    let _ =
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &buy_assessment, &stale_sell)
            .unwrap_err();
    assert_eq!(pool, pool_before);
    assert_eq!(req, req_before);
    assert_eq!(buy_assessment, buy_assessment_before);
    assert_eq!(stale_sell, stale_sell_before);

    // 3D: On failure - Zero input amount
    let zero_req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(0));
    let zero_req_before = zero_req.clone();
    let _ = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &zero_req,
        &buy_assessment,
        &sell_assessment,
    )
    .unwrap_err();
    assert_eq!(pool, pool_before);
    assert_eq!(zero_req, zero_req_before);
    assert_eq!(buy_assessment, buy_assessment_before);
    assert_eq!(sell_assessment, sell_assessment_before);
}

// =========================================================================
// 4. Stale, resync, malformed, and chain/asset mismatch assessments fail closed
// =========================================================================

#[test]
fn test_stale_resync_and_mismatched_assessments_fail_closed() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    let valid_buy = sample_assessment(ChainId::Base, WETH_ADDR, 100, 0, FreshnessStatus::Fresh);
    let valid_sell = sample_assessment(ChainId::Base, WETH_ADDR, 0, 100, FreshnessStatus::Fresh);

    // 4A: Buy assessment stale
    let stale_buy = sample_assessment(ChainId::Base, WETH_ADDR, 100, 0, FreshnessStatus::Stale);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &stale_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );

    // 4B: Buy assessment resync required
    let resync_buy = sample_assessment(
        ChainId::Base,
        WETH_ADDR,
        100,
        0,
        FreshnessStatus::ResyncRequired,
    );
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &resync_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );

    // 4C: Sell assessment stale
    let stale_sell = sample_assessment(ChainId::Base, WETH_ADDR, 0, 100, FreshnessStatus::Stale);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &valid_buy, &stale_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );

    // 4D: Sell assessment resync required
    let resync_sell = sample_assessment(
        ChainId::Base,
        WETH_ADDR,
        0,
        100,
        FreshnessStatus::ResyncRequired,
    );
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &valid_buy, &resync_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );

    // 4E: Buy assessment wrong asset (e.g. assessing input token instead of output token)
    let wrong_asset_buy =
        sample_assessment(ChainId::Base, USDC_ADDR, 100, 0, FreshnessStatus::Fresh);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &wrong_asset_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // 4F: Sell assessment wrong asset (e.g. assessing pool.token_0 instead of acquired pool.token_1)
    let wrong_asset_sell =
        sample_assessment(ChainId::Base, USDC_ADDR, 0, 100, FreshnessStatus::Fresh);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &valid_buy, &wrong_asset_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );

    // 4G: Buy assessment foreign chain
    let foreign_buy =
        sample_assessment(ChainId::Ethereum, WETH_ADDR, 100, 0, FreshnessStatus::Fresh);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &foreign_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );

    // 4H: Sell assessment foreign chain
    let foreign_sell =
        sample_assessment(ChainId::Ethereum, WETH_ADDR, 0, 100, FreshnessStatus::Fresh);
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &req, &valid_buy, &foreign_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
}

// =========================================================================
// 5. Underlying CPMM validation failures fail closed and stay redacted
// =========================================================================

#[test]
fn test_underlying_cpmm_failures_fail_closed_and_redacted() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let valid_buy = sample_assessment(ChainId::Base, WETH_ADDR, 100, 0, FreshnessStatus::Fresh);
    let valid_sell = sample_assessment(ChainId::Base, WETH_ADDR, 0, 100, FreshnessStatus::Fresh);

    // 5A: Zero input amount
    let zero_req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(0));
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &zero_req, &valid_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroInputAmount)
    );

    // 5B: Asset not in pool
    let foreign_asset = sample_asset(ChainId::Base, "0x1111111111111111111111111111111111111111");
    let unk_req = CpmmExactInputRequest::new(foreign_asset, AtomicAmount::new(10_000));
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &unk_req, &valid_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool)
    );

    // 5C: Output asset mismatch
    let bad_out_req = CpmmExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(10_000),
        pool.token_0.clone(), // output cannot equal input
    );
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &bad_out_req, &valid_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch)
    );

    // 5D: Chain mismatch between request and pool
    let eth_req = CpmmExactInputRequest::new(
        sample_asset(ChainId::Ethereum, USDC_ADDR),
        AtomicAmount::new(10_000),
    );
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&pool, &eth_req, &valid_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ChainMismatch)
    );

    // 5E: Zero pool reserve
    let mut zero_pool = pool.clone();
    zero_pool.reserve_0 = AtomicAmount::new(0);
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(&zero_pool, &req, &valid_buy, &valid_sell)
            .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroReserve)
    );

    // 5F: Invalid fee bps (>= 10,000)
    let invalid_fee_pool = CpmmPoolState {
        token_0: pool.token_0.clone(),
        token_1: pool.token_1.clone(),
        decimals_0: 6,
        decimals_1: 18,
        reserve_0: AtomicAmount::new(1_000_000),
        reserve_1: AtomicAmount::new(2_000_000),
        total_lp_supply: Some(AtomicAmount::new(10_000_000)),
        fee_bps: Bps::new(10_000).expect("10000 bps"),
    };
    assert_eq!(
        simulate_tax_aware_cpmm_roundtrip_exact_input(
            &invalid_fee_pool,
            &req,
            &valid_buy,
            &valid_sell
        )
        .unwrap_err(),
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::InvalidFeeBps)
    );
}

// =========================================================================
// 6. Comprehensive Display and Debug redaction (no leaked values/secrets)
// =========================================================================

#[test]
fn test_display_and_debug_redaction_comprehensive() {
    let err_cpmm = TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool);
    let disp_cpmm = format!("{err_cpmm}");
    let dbg_cpmm = format!("{err_cpmm:?}");

    assert!(!disp_cpmm.contains("0x"));
    assert!(!disp_cpmm.contains("10000"));
    assert!(!dbg_cpmm.contains("0x"));
    assert!(!dbg_cpmm.contains("10000"));

    let err_tax = TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation);
    let disp_tax = format!("{err_tax}");
    let dbg_tax = format!("{err_tax:?}");

    assert!(!disp_tax.contains("0x"));
    assert!(!disp_tax.contains("10000"));
    assert!(!dbg_tax.contains("0x"));
    assert!(!dbg_tax.contains("10000"));
}

// =========================================================================
// 7. Bounded arithmetic, large integer vectors, and reserve reconstruction
// =========================================================================

#[test]
fn test_large_safe_integer_vector_exact_arithmetic() {
    let large_reserve_0 = 100_000_000_000_000_000_000_000_000u128; // 10^26
    let large_reserve_1 = 200_000_000_000_000_000_000_000_000u128; // 2 * 10^26
    let gross_in = 10_000_000_000_000_000_000_000_000u128; // 10^25

    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        large_reserve_0,
        large_reserve_1,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(gross_in));
    let buy_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 500, 0, FreshnessStatus::Fresh); // 5%
    let sell_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 0, 750, FreshnessStatus::Fresh); // 7.5%

    let rt = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("large integer roundtrip must succeed without overflow");

    // Conservation on buy
    assert_eq!(
        rt.buy_quote.tax_output.gross_output.amount.get(),
        rt.buy_quote.tax_output.tax_cost.amount.get()
            + rt.buy_quote.tax_output.net_output.amount.get()
    );

    // Sell input equals buy net output
    assert_eq!(
        rt.sell_quote.tax_input.gross_input,
        rt.buy_quote.tax_output.net_output
    );

    // Conservation on sell
    assert_eq!(
        rt.sell_quote.tax_input.gross_input.amount.get(),
        rt.sell_quote.tax_input.tax_cost.amount.get()
            + rt.sell_quote.tax_input.net_transferable_input.amount.get()
    );

    // Output returned in original input asset and strictly positive
    assert_eq!(rt.sell_quote.cpmm_quote.output.asset, pool.token_0);
    assert!(rt.sell_quote.cpmm_quote.output.amount.get() > 0);
    assert!(rt.sell_quote.cpmm_quote.output.amount.get() < gross_in);
}

// =========================================================================
// 8. Serde round trip
// =========================================================================

#[test]
fn test_serde_round_trip() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));
    let buy_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 250, 0, FreshnessStatus::Fresh);
    let sell_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 0, 200, FreshnessStatus::Fresh);

    let rt = simulate_tax_aware_cpmm_roundtrip_exact_input(
        &pool,
        &req,
        &buy_assessment,
        &sell_assessment,
    )
    .expect("simulation must succeed");

    let serialized = serde_json::to_string(&rt).expect("serialize roundtrip quote");
    let deserialized: TaxAwareCpmmRoundtripQuote =
        serde_json::from_str(&serialized).expect("deserialize roundtrip quote");

    assert_eq!(rt, deserialized);
}
