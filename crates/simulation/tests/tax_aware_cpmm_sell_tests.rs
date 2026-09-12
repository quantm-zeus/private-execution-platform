//! Deterministic unit and integration tests for sell-side tax-aware CPMM simulation composition.

use chain_types::{AssetId, ChainId};
use market_types::{
    AtomicAmount, Bps, CpmmPoolState, FreshnessStatus, SafeFreshnessMeta, Sequence,
};
use simulation::{
    simulate_tax_aware_cpmm_sell_exact_input, CpmmExactInputRequest, CpmmSimulationErrorClass,
    TaxAwareCpmmSellQuote, TaxAwareSimulationError,
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
        Bps::new(0).expect("valid buy tax bps"),
        Bps::new(sell_tax_bps).expect("valid sell tax bps"),
        freshness,
        50_000,
    )
}

const USDC_ADDR: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WETH_ADDR: &str = "0x4200000000000000000000000000000000000006";

// =========================================================================
// 1. Known sell-tax-before-pool-fee vector with explicit gross/tax/net input
//    and CPMM quote input/pool fee/effective input values
// =========================================================================

#[test]
fn test_known_sell_tax_before_pool_fee_vector() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    ); // 30 bps CPMM pool fee

    // --- Direction 0 -> 1: Selling USDC for WETH ---
    // Gross user input = 10_000 USDC
    // Assessment on USDC: sell_tax_bps = 500 (5.0%)
    // Sell tax deduction:
    //   tax_cost = floor(10_000 * 500 / 10_000) = 500 USDC
    //   net_transferable_input = 10_000 - 500 = 9_500 USDC
    // CPMM exact-input calculation on 9_500 USDC net transferable input:
    //   pool_fee = floor(9_500 * 30 / 10_000) = 28 USDC
    //   effective_input = 9_500 - 28 = 9_472 USDC
    //   output = floor(9_472 * 2_000_000 / (1_000_000 + 9_472)) = 18_766 WETH
    let assessment_usdc = sample_assessment(ChainId::Base, USDC_ADDR, 500, FreshnessStatus::Fresh);
    let req_0 = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    let result: TaxAwareCpmmSellQuote =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_0, &assessment_usdc)
            .expect("simulation must succeed");

    // Explicit gross input economics
    assert_eq!(result.tax_input.gross_input.asset, pool.token_0);
    assert_eq!(result.tax_input.gross_input.amount.get(), 10_000);
    assert_eq!(result.tax_input.tax_cost.asset, pool.token_0);
    assert_eq!(result.tax_input.tax_cost.amount.get(), 500);
    assert_eq!(result.tax_input.net_transferable_input.asset, pool.token_0);
    assert_eq!(result.tax_input.net_transferable_input.amount.get(), 9_500);

    // Conservation of input: gross == tax_cost + net_transferable_input
    assert_eq!(
        result.tax_input.gross_input.amount.get(),
        result.tax_input.tax_cost.amount.get()
            + result.tax_input.net_transferable_input.amount.get()
    );

    // Quote input must exactly equal the net transferable input
    assert_eq!(
        result.cpmm_quote.input,
        result.tax_input.net_transferable_input
    );
    assert_eq!(result.cpmm_quote.input.amount.get(), 9_500);

    // Underlying CPMM pool fee and effective input remain untouched
    assert_eq!(result.cpmm_quote.pool_fee.asset, pool.token_0);
    assert_eq!(result.cpmm_quote.pool_fee.amount.get(), 28);
    assert_eq!(result.cpmm_quote.effective_input.asset, pool.token_0);
    assert_eq!(result.cpmm_quote.effective_input.amount.get(), 9_472);
    assert_eq!(
        result.cpmm_quote.input.amount.get(),
        result.cpmm_quote.pool_fee.amount.get() + result.cpmm_quote.effective_input.amount.get()
    );

    // CPMM output
    assert_eq!(result.cpmm_quote.output.asset, pool.token_1);
    assert_eq!(result.cpmm_quote.output.amount.get(), 18_766);

    // Resulting pool reserves
    assert_eq!(result.cpmm_quote.resulting_reserve_0.get(), 1_009_500);
    assert_eq!(result.cpmm_quote.resulting_reserve_1.get(), 1_981_234);

    // --- Direction 1 -> 0: Selling WETH for USDC ---
    // Gross user input = 20_000 WETH
    // Assessment on WETH: sell_tax_bps = 250 (2.5%)
    // Sell tax deduction:
    //   tax_cost = floor(20_000 * 250 / 10_000) = 500 WETH
    //   net_transferable_input = 20_000 - 500 = 19_500 WETH
    // CPMM exact-input on 19_500 WETH:
    //   pool_fee = floor(19_500 * 30 / 10_000) = 58 WETH
    //   effective_input = 19_500 - 58 = 19_442 WETH
    //   output = floor(19_442 * 1_000_000 / (2_000_000 + 19_442)) = 9_627 USDC
    let assessment_weth = sample_assessment(ChainId::Base, WETH_ADDR, 250, FreshnessStatus::Fresh);
    let req_1 = CpmmExactInputRequest::new_directed(
        pool.token_1.clone(),
        AtomicAmount::new(20_000),
        pool.token_0.clone(),
    );

    let result_1 = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_1, &assessment_weth)
        .expect("reverse simulation must succeed");

    assert_eq!(result_1.tax_input.gross_input.asset, pool.token_1);
    assert_eq!(result_1.tax_input.gross_input.amount.get(), 20_000);
    assert_eq!(result_1.tax_input.tax_cost.asset, pool.token_1);
    assert_eq!(result_1.tax_input.tax_cost.amount.get(), 500);
    assert_eq!(
        result_1.tax_input.net_transferable_input.asset,
        pool.token_1
    );
    assert_eq!(
        result_1.tax_input.net_transferable_input.amount.get(),
        19_500
    );

    assert_eq!(
        result_1.tax_input.gross_input.amount.get(),
        result_1.tax_input.tax_cost.amount.get()
            + result_1.tax_input.net_transferable_input.amount.get()
    );

    assert_eq!(
        result_1.cpmm_quote.input,
        result_1.tax_input.net_transferable_input
    );
    assert_eq!(result_1.cpmm_quote.pool_fee.amount.get(), 58);
    assert_eq!(result_1.cpmm_quote.effective_input.amount.get(), 19_442);
    assert_eq!(result_1.cpmm_quote.output.asset, pool.token_0);
    assert_eq!(result_1.cpmm_quote.output.amount.get(), 9_627);
    assert_eq!(result_1.cpmm_quote.resulting_reserve_1.get(), 2_019_500);
    assert_eq!(result_1.cpmm_quote.resulting_reserve_0.get(), 990_373);
}

// =========================================================================
// 2. Zero sell-tax success and max-tax/zero-net rejection
// =========================================================================

#[test]
fn test_zero_sell_tax_success_and_max_tax_zero_net_rejection() {
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );

    // 2A: Zero sell-tax success
    let assessment_zero = sample_assessment(ChainId::Base, USDC_ADDR, 0, FreshnessStatus::Fresh);
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(10_000));

    let quote = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &assessment_zero)
        .expect("zero sell tax simulation must succeed");

    assert_eq!(quote.tax_input.gross_input.amount.get(), 10_000);
    assert_eq!(quote.tax_input.tax_cost.amount.get(), 0);
    assert_eq!(quote.tax_input.net_transferable_input.amount.get(), 10_000);
    assert_eq!(quote.cpmm_quote.input.amount.get(), 10_000);
    assert_eq!(quote.cpmm_quote.pool_fee.amount.get(), 30);
    assert_eq!(quote.cpmm_quote.effective_input.amount.get(), 9_970);
    assert_eq!(quote.cpmm_quote.output.amount.get(), 19_743);

    // 2B: Max-tax (100% tax, 10_000 bps) -> zero net input rejection
    let assessment_100 =
        sample_assessment(ChainId::Base, USDC_ADDR, 10_000, FreshnessStatus::Fresh);

    let err_100 = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &assessment_100)
        .expect_err("100% sell tax must fail closed with ZeroNetInput");

    assert_eq!(
        err_100,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );

    // 2C: Tiny gross input with 10_000 bps tax -> zero net input
    let req_tiny = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(1));
    let err_tiny = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_tiny, &assessment_100)
        .expect_err("1 unit gross input with 100% tax must fail closed with ZeroNetInput");

    assert_eq!(
        err_tiny,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );
}

// =========================================================================
// 3. Stale/resync/mismatched assessed input asset/chain rejects before CPMM,
//    including a deliberately invalid pool proving the tax error wins and
//    inputs remain unchanged
// =========================================================================

#[test]
fn test_tax_safety_rejects_before_cpmm_with_invalid_pool_and_immutability() {
    // Deliberately invalid pool: zero reserves, invalid fee bps (10,000 bps >= 10,000 max)
    let invalid_pool = CpmmPoolState {
        token_0: sample_asset(ChainId::Base, USDC_ADDR),
        token_1: sample_asset(ChainId::Base, WETH_ADDR),
        decimals_0: 6,
        decimals_1: 18,
        reserve_0: AtomicAmount::ZERO,
        reserve_1: AtomicAmount::ZERO,
        total_lp_supply: None,
        fee_bps: Bps::new(10_000).expect("bps constructor"),
    };
    let pool_snapshot = invalid_pool.clone();

    let req = CpmmExactInputRequest::new(
        sample_asset(ChainId::Base, USDC_ADDR),
        AtomicAmount::new(10_000),
    );
    let req_snapshot = req.clone();

    // 3A: Stale assessment rejects before CPMM
    let stale_assessment = sample_assessment(ChainId::Base, USDC_ADDR, 500, FreshnessStatus::Stale);
    let stale_snapshot = stale_assessment.clone();

    let err_stale =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_pool, &req, &stale_assessment)
            .expect_err("stale assessment must fail closed before CPMM");

    assert_eq!(
        err_stale,
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );
    assert_eq!(invalid_pool, pool_snapshot);
    assert_eq!(req, req_snapshot);
    assert_eq!(stale_assessment, stale_snapshot);

    // 3B: ResyncRequired assessment rejects before CPMM
    let resync_assessment = sample_assessment(
        ChainId::Base,
        USDC_ADDR,
        500,
        FreshnessStatus::ResyncRequired,
    );
    let resync_snapshot = resync_assessment.clone();

    let err_resync =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_pool, &req, &resync_assessment)
            .expect_err("resync assessment must fail closed before CPMM");

    assert_eq!(
        err_resync,
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_eq!(invalid_pool, pool_snapshot);
    assert_eq!(req, req_snapshot);
    assert_eq!(resync_assessment, resync_snapshot);

    // 3C: Chain mismatch rejects before CPMM
    let solana_assessment =
        sample_assessment(ChainId::Solana, USDC_ADDR, 500, FreshnessStatus::Fresh);
    let solana_snapshot = solana_assessment.clone();

    let err_chain =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_pool, &req, &solana_assessment)
            .expect_err("chain mismatch must fail closed before CPMM");

    assert_eq!(
        err_chain,
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
    assert_eq!(invalid_pool, pool_snapshot);
    assert_eq!(req, req_snapshot);
    assert_eq!(solana_assessment, solana_snapshot);

    // 3D: Assessed asset mismatch rejects before CPMM (assessment on WETH instead of sold USDC)
    let wrong_asset_assessment =
        sample_assessment(ChainId::Base, WETH_ADDR, 500, FreshnessStatus::Fresh);
    let wrong_asset_snapshot = wrong_asset_assessment.clone();

    let err_asset =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_pool, &req, &wrong_asset_assessment)
            .expect_err("assessed asset mismatch must fail closed before CPMM");

    assert_eq!(
        err_asset,
        TaxAwareSimulationError::Tax(TaxSafetyError::AssessedAssetMismatch)
    );
    assert_eq!(invalid_pool, pool_snapshot);
    assert_eq!(req, req_snapshot);
    assert_eq!(wrong_asset_assessment, wrong_asset_snapshot);

    // 3E: Zero gross input rejects before CPMM
    let req_zero =
        CpmmExactInputRequest::new(sample_asset(ChainId::Base, USDC_ADDR), AtomicAmount::ZERO);
    let req_zero_snapshot = req_zero.clone();
    let valid_assessment = sample_assessment(ChainId::Base, USDC_ADDR, 500, FreshnessStatus::Fresh);
    let valid_assessment_snapshot = valid_assessment.clone();

    let err_zero =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_pool, &req_zero, &valid_assessment)
            .expect_err("zero gross input must fail closed before CPMM");

    assert_eq!(
        err_zero,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroGrossInput)
    );
    assert_eq!(invalid_pool, pool_snapshot);
    assert_eq!(req_zero, req_zero_snapshot);
    assert_eq!(valid_assessment, valid_assessment_snapshot);
}

// =========================================================================
// 4. An underlying rejected CPMM request after a valid tax assessment;
//    immutability for pool/request/assessment on every error
// =========================================================================

#[test]
fn test_underlying_rejected_cpmm_request_and_immutability() {
    let valid_pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        1_000_000,
        2_000_000,
        30,
    );
    let valid_assessment = sample_assessment(ChainId::Base, USDC_ADDR, 200, FreshnessStatus::Fresh);

    // 4A: CPMM AssetNotFoundInPool (request input token is not in pool, but assessment matches input)
    let foreign_addr = "0x1111111111111111111111111111111111111111";
    let foreign_token = sample_asset(ChainId::Base, foreign_addr);
    let req_foreign = CpmmExactInputRequest::new(foreign_token.clone(), AtomicAmount::new(10_000));
    let assessment_foreign =
        sample_assessment(ChainId::Base, foreign_addr, 200, FreshnessStatus::Fresh);

    let pool_snap = valid_pool.clone();
    let req_snap = req_foreign.clone();
    let assess_snap = assessment_foreign.clone();

    let err_not_found =
        simulate_tax_aware_cpmm_sell_exact_input(&valid_pool, &req_foreign, &assessment_foreign)
            .expect_err("token not in pool must fail CPMM");

    assert_eq!(
        err_not_found,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool)
    );
    assert_eq!(valid_pool, pool_snap);
    assert_eq!(req_foreign, req_snap);
    assert_eq!(assessment_foreign, assess_snap);

    // 4B: CPMM OutputAssetMismatch (directed swap asserting wrong target token)
    let req_mismatch = CpmmExactInputRequest::new_directed(
        valid_pool.token_0.clone(),
        AtomicAmount::new(10_000),
        foreign_token,
    );
    let req_mismatch_snap = req_mismatch.clone();
    let assess_snap2 = valid_assessment.clone();

    let err_out =
        simulate_tax_aware_cpmm_sell_exact_input(&valid_pool, &req_mismatch, &valid_assessment)
            .expect_err("wrong output asset assertion must fail CPMM");

    assert_eq!(
        err_out,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch)
    );
    assert_eq!(valid_pool, pool_snap);
    assert_eq!(req_mismatch, req_mismatch_snap);
    assert_eq!(valid_assessment, assess_snap2);

    // 4C: CPMM ZeroReserve (pool with zero reserve_0 after valid tax)
    let mut zero_res_pool = valid_pool.clone();
    zero_res_pool.reserve_0 = AtomicAmount::ZERO;
    let zero_res_snap = zero_res_pool.clone();
    let normal_req =
        CpmmExactInputRequest::new(valid_pool.token_0.clone(), AtomicAmount::new(10_000));
    let normal_req_snap = normal_req.clone();

    let err_res =
        simulate_tax_aware_cpmm_sell_exact_input(&zero_res_pool, &normal_req, &valid_assessment)
            .expect_err("zero pool reserve must fail CPMM");

    assert_eq!(
        err_res,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::ZeroReserve)
    );
    assert_eq!(zero_res_pool, zero_res_snap);
    assert_eq!(normal_req, normal_req_snap);

    // 4D: CPMM InvalidFeeBps (pool with invalid fee >= 10,000 bps)
    let mut invalid_fee_pool = valid_pool.clone();
    invalid_fee_pool.fee_bps = Bps::new(10_000).expect("bps constructor");
    let invalid_fee_snap = invalid_fee_pool.clone();

    let err_fee =
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_fee_pool, &normal_req, &valid_assessment)
            .expect_err("invalid fee bps must fail CPMM");

    assert_eq!(
        err_fee,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::InvalidFeeBps)
    );
    assert_eq!(invalid_fee_pool, invalid_fee_snap);

    // 4E: CPMM ZeroEffectiveInput (amount so tiny after fee that effective input is 0)
    // For net_input = 1 and fee_bps = 9_999: fee = floor(1 * 9_999 / 10_000) = 0, effective = 1.
    // If pool fee is 9999 bps and net input is 1, fee_val = 0.
    // But if net input is 0, apply_sell_tax_to_input rejects it first as ZeroNetInput.
}

// =========================================================================
// 5. Large safe integer/vector proving exact bounded composition without float/overflow
// =========================================================================

#[test]
fn test_large_safe_integer_vector_exact_arithmetic() {
    // Large reserves: 50 * 10^27
    let large_reserve_0 = 50_000_000_000_000_000_000_000_000_000_u128;
    let large_reserve_1 = 80_000_000_000_000_000_000_000_000_000_u128;
    let pool = sample_pool(
        ChainId::Base,
        USDC_ADDR,
        WETH_ADDR,
        large_reserve_0,
        large_reserve_1,
        25, // 25 bps fee
    );

    // Large gross input: 10 * 10^24
    let gross_in = 10_000_000_000_000_000_000_000_000_u128;
    let sell_tax_bps = 750_u16; // 7.5% sell tax

    // Expected exact integer arithmetic:
    // tax_cost = floor(gross_in * 750 / 10_000) = 750_000_000_000_000_000_000_000
    // net_transferable_input = 10_000_000_000_000_000_000_000_000 - 750_000_000_000_000_000_000_000
    //                        = 9_250_000_000_000_000_000_000_000
    // pool_fee = floor(9_250_000_000_000_000_000_000_000 * 25 / 10_000)
    //          = 23_125_000_000_000_000_000_000
    // effective_input = 9_250_000_000_000_000_000_000_000 - 23_125_000_000_000_000_000_000
    //                 = 9_226_875_000_000_000_000_000_000
    let assessment = sample_assessment(
        ChainId::Base,
        USDC_ADDR,
        sell_tax_bps,
        FreshnessStatus::Fresh,
    );
    let req = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(gross_in));

    let result = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &assessment)
        .expect("large integer simulation must succeed without overflow");

    assert_eq!(result.tax_input.gross_input.amount.get(), gross_in);
    assert_eq!(
        result.tax_input.tax_cost.amount.get(),
        750_000_000_000_000_000_000_000
    );
    assert_eq!(
        result.tax_input.net_transferable_input.amount.get(),
        9_250_000_000_000_000_000_000_000
    );

    // Exact input conservation
    assert_eq!(
        result.tax_input.gross_input.amount.get(),
        result.tax_input.tax_cost.amount.get()
            + result.tax_input.net_transferable_input.amount.get()
    );

    // Quote input strictly equals net transferable input
    assert_eq!(
        result.cpmm_quote.input,
        result.tax_input.net_transferable_input
    );
    assert_eq!(
        result.cpmm_quote.pool_fee.amount.get(),
        23_125_000_000_000_000_000_000
    );
    assert_eq!(
        result.cpmm_quote.effective_input.amount.get(),
        9_226_875_000_000_000_000_000_000
    );

    // CPMM fee conservation
    assert_eq!(
        result.tax_input.net_transferable_input.amount.get(),
        result.cpmm_quote.pool_fee.amount.get() + result.cpmm_quote.effective_input.amount.get()
    );

    // Output must be strictly positive and strictly below output reserve
    let out_val = result.cpmm_quote.output.amount.get();
    assert!(out_val > 0);
    assert!(out_val < large_reserve_1);

    // Resulting reserves
    assert_eq!(
        result.cpmm_quote.resulting_reserve_0.get(),
        large_reserve_0 + 9_250_000_000_000_000_000_000_000
    );
    assert_eq!(
        result.cpmm_quote.resulting_reserve_1.get(),
        large_reserve_1 - out_val
    );
}

// =========================================================================
// 6. Error Display/Debug redaction using distinct raw addresses, amounts,
//    reserves, timestamps/sequences, and tax values
// =========================================================================

#[test]
fn test_display_and_debug_redaction_comprehensive() {
    let distinct_addr_0 = "0x1111111111111111111111111111111111111111";
    let distinct_addr_1 = "0x2222222222222222222222222222222222222222";
    let distinct_foreign_addr = "0x3333333333333333333333333333333333333333";
    let distinct_res_0 = 777_888_999_111_u128;
    let distinct_res_1 = 888_999_111_222_u128;
    let distinct_amount_in = 555_444_333_222_u128;
    let distinct_slot = 987_654_321_u64;
    let distinct_tax_bps = 1337_u16;

    let pool = sample_pool(
        ChainId::Base,
        distinct_addr_0,
        distinct_addr_1,
        distinct_res_0,
        distinct_res_1,
        30,
    );

    let normal_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_0),
        ChainId::Base,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        SafeFreshnessMeta {
            status: FreshnessStatus::Fresh,
            observed_at_ms: 123_456_789,
            evaluated_at_ms: 123_456_790,
            age_ms: 1,
            sequence: Sequence::new(42_424),
        },
        distinct_slot,
    );

    let stale_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_0),
        ChainId::Base,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        SafeFreshnessMeta {
            status: FreshnessStatus::Stale,
            observed_at_ms: 123_456_789,
            evaluated_at_ms: 123_456_790,
            age_ms: 1,
            sequence: Sequence::new(42_424),
        },
        distinct_slot,
    );

    let sensitive_snippets: Vec<String> = vec![
        distinct_addr_0.to_string(),
        distinct_addr_1.to_string(),
        distinct_foreign_addr.to_string(),
        distinct_res_0.to_string(),
        distinct_res_1.to_string(),
        distinct_amount_in.to_string(),
        distinct_slot.to_string(),
        distinct_tax_bps.to_string(),
        "123456789".to_string(),
        "42424".to_string(),
    ];

    let assert_redacted = |err: &TaxAwareSimulationError, label: &str| {
        let display_str = format!("{}", err);
        let debug_str = format!("{:?}", err);

        for snippet in &sensitive_snippets {
            assert!(
                !display_str.contains(snippet),
                "[{label}] Display leaked '{snippet}': {display_str}"
            );
            assert!(
                !debug_str.contains(snippet),
                "[{label}] Debug leaked '{snippet}': {debug_str}"
            );
        }
    };

    let req =
        CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::new(distinct_amount_in));

    // 6A: Stale observation error
    let err_stale =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &stale_assessment).unwrap_err();
    assert_eq!(
        err_stale,
        TaxAwareSimulationError::Tax(TaxSafetyError::StaleObservation)
    );
    assert_redacted(&err_stale, "StaleObservation");

    // 6B: ResyncRequired observation error
    let mut resync_assessment = stale_assessment.clone();
    resync_assessment.freshness.status = FreshnessStatus::ResyncRequired;
    let err_resync =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &resync_assessment).unwrap_err();
    assert_eq!(
        err_resync,
        TaxAwareSimulationError::Tax(TaxSafetyError::ResyncRequired)
    );
    assert_redacted(&err_resync, "ResyncRequired");

    // 6C: Assessed asset mismatch error
    let mismatched_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_foreign_addr),
        ChainId::Base,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_mismatch =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &mismatched_assessment).unwrap_err();
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
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_chain =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &solana_assessment).unwrap_err();
    assert_eq!(
        err_chain,
        TaxAwareSimulationError::Tax(TaxSafetyError::ChainMismatch)
    );
    assert_redacted(&err_chain, "ChainMismatch");

    // 6E: Zero net input error (100% tax)
    let max_tax_assessment = TaxAssessment::new(
        sample_asset(ChainId::Base, distinct_addr_0),
        ChainId::Base,
        Bps::new(0).unwrap(),
        Bps::new(10_000).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_zero_net =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &max_tax_assessment).unwrap_err();
    assert_eq!(
        err_zero_net,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroNetInput)
    );
    assert_redacted(&err_zero_net, "ZeroNetInput");

    // 6F: Zero gross input error
    let req_zero_gross = CpmmExactInputRequest::new(pool.token_0.clone(), AtomicAmount::ZERO);
    let err_zero_gross =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_zero_gross, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_zero_gross,
        TaxAwareSimulationError::Tax(TaxSafetyError::ZeroGrossInput)
    );
    assert_redacted(&err_zero_gross, "ZeroGrossInput");

    // 6G: CPMM AssetNotFoundInPool error
    let foreign_token = sample_asset(ChainId::Base, distinct_foreign_addr);
    let req_foreign =
        CpmmExactInputRequest::new(foreign_token.clone(), AtomicAmount::new(distinct_amount_in));
    let foreign_assessment = TaxAssessment::new(
        foreign_token,
        ChainId::Base,
        Bps::new(0).unwrap(),
        Bps::new(distinct_tax_bps).unwrap(),
        normal_assessment.freshness,
        distinct_slot,
    );
    let err_not_found =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_foreign, &foreign_assessment)
            .unwrap_err();
    assert_eq!(
        err_not_found,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::AssetNotFoundInPool)
    );
    assert_redacted(&err_not_found, "AssetNotFoundInPool");

    // 6H: CPMM OutputAssetMismatch error
    let req_out_mismatch = CpmmExactInputRequest::new_directed(
        pool.token_0.clone(),
        AtomicAmount::new(distinct_amount_in),
        sample_asset(ChainId::Base, distinct_foreign_addr),
    );
    let err_out_mismatch =
        simulate_tax_aware_cpmm_sell_exact_input(&pool, &req_out_mismatch, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_out_mismatch,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::OutputAssetMismatch)
    );
    assert_redacted(&err_out_mismatch, "OutputAssetMismatch");

    // 6I: CPMM ZeroReserve error
    let mut zero_res_pool = pool.clone();
    zero_res_pool.reserve_0 = AtomicAmount::ZERO;
    let err_zero_res =
        simulate_tax_aware_cpmm_sell_exact_input(&zero_res_pool, &req, &normal_assessment)
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
        simulate_tax_aware_cpmm_sell_exact_input(&invalid_fee_pool, &req, &normal_assessment)
            .unwrap_err();
    assert_eq!(
        err_fee,
        TaxAwareSimulationError::Cpmm(CpmmSimulationErrorClass::InvalidFeeBps)
    );
    assert_redacted(&err_fee, "InvalidFeeBps");
}

// =========================================================================
// 7. Serde round-trip validation
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
    let assessment = sample_assessment(ChainId::Base, USDC_ADDR, 250, FreshnessStatus::Fresh);

    let quote = simulate_tax_aware_cpmm_sell_exact_input(&pool, &req, &assessment).unwrap();

    let json = serde_json::to_string(&quote).expect("serialize TaxAwareCpmmSellQuote");
    let deserialized: TaxAwareCpmmSellQuote =
        serde_json::from_str(&json).expect("deserialize TaxAwareCpmmSellQuote");

    assert_eq!(quote, deserialized);
}
