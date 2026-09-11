//! Comprehensive deterministic tests for tax and safety assessment contracts.

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, DomainError, IdempotencyKey, IntentId, OrderType, RiskConstraints, TaxObservation,
    TradeIntent, TradeSide, TradeSource, UserId, WalletRef,
};
use market_types::{AtomicAmount, Bps, FreshnessPolicy, FreshnessStatus};
use tax_engine::{
    assess_tax_safety, assessed_asset_for_intent, evaluate_tax_safety, TaxAssessment,
    TaxSafetyEngine, TaxSafetyError,
};

fn sample_asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid asset")
}

fn sample_risk(max_buy: u16, max_sell: u16) -> RiskConstraints {
    RiskConstraints {
        max_buy_tax: Bps::new(max_buy).expect("valid bps"),
        max_sell_tax: Bps::new(max_sell).expect("valid bps"),
        max_price_impact: Bps::new(100).expect("valid bps"),
        max_slippage: Bps::new(50).expect("valid bps"),
        max_total_cost: None,
    }
}

fn sample_intent(side: TradeSide, max_buy_tax: u16, max_sell_tax: u16) -> TradeIntent {
    let token_in = sample_asset("0x0000000000000000000000000000000000000001");
    let token_out = sample_asset("0x0000000000000000000000000000000000000002");
    TradeIntent {
        id: IntentId::new("intent_123").expect("valid intent id"),
        source: TradeSource::Web,
        user_id: UserId::new("user_123").expect("valid user id"),
        wallet_ref: WalletRef::new("wallet_123").expect("valid wallet ref"),
        chain: ChainId::Base,
        token_in,
        token_out,
        side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: sample_risk(max_buy_tax, max_sell_tax),
        allow_partial_fill: false,
        expiry_ms: Some(200_000),
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem_123").expect("valid idempotency key"),
    }
}

fn sample_observation(
    token: AssetId,
    buy_tax: u16,
    sell_tax: u16,
    buy_succeeds: bool,
    sell_succeeds: bool,
    sellable: bool,
    observed_at_ms: i64,
) -> TaxObservation {
    TaxObservation {
        chain: ChainId::Base,
        token,
        pool_ref: "0xpool_123".to_string(),
        router_ref: "0xrouter_123".to_string(),
        wallet_ref: WalletRef::new("wallet_123").expect("valid wallet ref"),
        amount: AtomicAmount::new(1_000_000),
        block_or_slot: 50_000,
        buy_tax: Bps::new(buy_tax).expect("valid bps"),
        sell_tax: Bps::new(sell_tax).expect("valid bps"),
        buy_succeeds,
        sell_succeeds,
        sellable,
        confidence: Bps::new(9900).expect("valid bps"),
        observed_at_ms,
        expires_at_ms: observed_at_ms + 60_000,
    }
}

fn sample_policy() -> FreshnessPolicy {
    FreshnessPolicy::new(10_000, 2_000).expect("valid policy")
}

// =========================================================================
// 1. Accepted within-cap and equality-at-cap tests for Buy & Sell bindings
// =========================================================================

#[test]
fn test_accepted_within_cap_buy_intent() {
    let intent = sample_intent(TradeSide::Buy, 500, 600);
    let assessed_token = assessed_asset_for_intent(&intent).clone();
    assert_eq!(assessed_token, intent.token_out);

    let obs = sample_observation(assessed_token.clone(), 300, 400, true, true, true, 100_000);
    let policy = sample_policy();
    let eval_time_ms = 105_000; // age = 5_000 <= 10_000

    let result = evaluate_tax_safety(&intent, Some(&obs), eval_time_ms, &policy)
        .expect("should accept within-cap observation for Buy");

    assert_eq!(result.assessed_asset(), &assessed_token);
    assert_eq!(result.chain(), ChainId::Base);
    assert_eq!(result.buy_tax().get(), 300);
    assert_eq!(result.sell_tax().get(), 400);
    assert_eq!(result.block_or_slot(), 50_000);
    assert!(result.freshness().is_fresh());
    assert_eq!(result.freshness().age_ms, 5_000);
    assert!(!result.is_zero_tax());
}

#[test]
fn test_accepted_equality_at_cap_buy_intent() {
    let intent = sample_intent(TradeSide::Buy, 500, 600);
    let assessed_token = intent.token_out.clone();

    // Exactly equal to caps: buy_tax == 500, sell_tax == 600
    let obs = sample_observation(assessed_token.clone(), 500, 600, true, true, true, 100_000);
    let policy = sample_policy();
    let eval_time_ms = 100_000; // age = 0

    let result = evaluate_tax_safety(&intent, Some(&obs), eval_time_ms, &policy)
        .expect("should accept equality-at-cap observation for Buy");

    assert_eq!(result.buy_tax().get(), 500);
    assert_eq!(result.sell_tax().get(), 600);
    assert_eq!(result.assessed_asset(), &assessed_token);
}

#[test]
fn test_accepted_within_cap_sell_intent() {
    let intent = sample_intent(TradeSide::Sell, 500, 600);
    let assessed_token = assessed_asset_for_intent(&intent).clone();
    assert_eq!(assessed_token, intent.token_in);

    let obs = sample_observation(assessed_token.clone(), 200, 350, true, true, true, 100_000);
    let policy = sample_policy();
    let eval_time_ms = 108_000; // age = 8_000 <= 10_000

    let result = evaluate_tax_safety(&intent, Some(&obs), eval_time_ms, &policy)
        .expect("should accept within-cap observation for Sell");

    assert_eq!(result.assessed_asset(), &assessed_token);
    assert_eq!(result.chain(), ChainId::Base);
    assert_eq!(result.buy_tax().get(), 200);
    assert_eq!(result.sell_tax().get(), 350);
    assert!(result.freshness().is_fresh());
}

#[test]
fn test_accepted_equality_at_cap_sell_intent() {
    let intent = sample_intent(TradeSide::Sell, 500, 600);
    let assessed_token = intent.token_in.clone();

    // Exactly equal to caps: buy_tax == 500, sell_tax == 600
    let obs = sample_observation(assessed_token.clone(), 500, 600, true, true, true, 100_000);
    let policy = sample_policy();
    let eval_time_ms = 102_000;

    let result = assess_tax_safety(&intent, Some(&obs), eval_time_ms, &policy)
        .expect("should accept equality-at-cap observation for Sell");

    assert_eq!(result.buy_tax().get(), 500);
    assert_eq!(result.sell_tax().get(), 600);
    assert_eq!(result.assessed_asset(), &assessed_token);
}

#[test]
fn test_accepted_zero_tax() {
    let intent = sample_intent(TradeSide::Buy, 100, 100);
    let assessed_token = intent.token_out.clone();
    let obs = sample_observation(assessed_token, 0, 0, true, true, true, 100_000);
    let policy = sample_policy();

    let result = TaxSafetyEngine::evaluate(&intent, Some(&obs), 100_000, &policy)
        .expect("should accept zero-tax observation");

    assert!(result.is_zero_tax());
    assert_eq!(result.buy_tax().get(), 0);
    assert_eq!(result.sell_tax().get(), 0);
}

// =========================================================================
// 2. Missing observation tests
// =========================================================================

#[test]
fn test_missing_observation_fails_closed() {
    let policy = sample_policy();

    // Buy side
    let buy_intent = sample_intent(TradeSide::Buy, 500, 500);
    let err_buy = evaluate_tax_safety(&buy_intent, None, 100_000, &policy)
        .expect_err("missing observation must fail closed");
    assert_eq!(err_buy, TaxSafetyError::MissingObservation);

    // Sell side
    let sell_intent = sample_intent(TradeSide::Sell, 500, 500);
    let err_sell = evaluate_tax_safety(&sell_intent, None, 100_000, &policy)
        .expect_err("missing observation must fail closed");
    assert_eq!(err_sell, TaxSafetyError::MissingObservation);
}

// =========================================================================
// 3. Chain and assessed-token mismatch tests
// =========================================================================

#[test]
fn test_chain_mismatch_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let mut obs = sample_observation(
        AssetId::new(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        )
        .unwrap(),
        300,
        300,
        true,
        true,
        true,
        100_000,
    );
    obs.chain = ChainId::Solana;
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("chain mismatch must fail closed");

    assert_eq!(err, TaxSafetyError::ChainMismatch);
}

#[test]
fn test_assessed_token_mismatch_for_buy_intent() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    // Buy intent must assess token_out; provide token_in instead
    let wrong_token = intent.token_in.clone();
    let obs = sample_observation(wrong_token, 300, 300, true, true, true, 100_000);
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("assessed token mismatch for Buy must fail closed");

    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);
}

#[test]
fn test_assessed_token_mismatch_for_sell_intent() {
    let intent = sample_intent(TradeSide::Sell, 500, 500);
    // Sell intent must assess token_in; provide token_out instead
    let wrong_token = intent.token_out.clone();
    let obs = sample_observation(wrong_token, 300, 300, true, true, true, 100_000);
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("assessed token mismatch for Sell must fail closed");

    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);
}

#[test]
fn test_unrelated_assessed_token_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let random_token = sample_asset("0x9999999999999999999999999999999999999999");
    let obs = sample_observation(random_token, 300, 300, true, true, true, 100_000);
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("unrelated token must fail closed");

    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);
}

// =========================================================================
// 4. Stale and excessive-future timestamps via injected time/policy
// =========================================================================

#[test]
fn test_stale_observation_timestamp_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = FreshnessPolicy::new(10_000, 2_000).unwrap();

    // observed_at = 89_999, evaluation_time = 100_000 => age = 10_001 > max_staleness 10_000
    let obs = sample_observation(intent.token_out.clone(), 300, 300, true, true, true, 89_999);
    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("stale observation must fail closed");

    assert_eq!(err, TaxSafetyError::StaleObservation);
}

#[test]
fn test_exact_boundary_freshness_accepted() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = FreshnessPolicy::new(10_000, 2_000).unwrap();

    // Exact staleness limit: age = 10_000 == max_staleness
    let obs_stale_limit =
        sample_observation(intent.token_out.clone(), 300, 300, true, true, true, 90_000);
    let res = evaluate_tax_safety(&intent, Some(&obs_stale_limit), 100_000, &policy)
        .expect("exact staleness limit should be fresh");
    assert_eq!(res.freshness().age_ms, 10_000);
    assert_eq!(res.freshness().status, FreshnessStatus::Fresh);

    // Exact future skew limit: skew = 2_000 == max_future_skew
    let obs_skew_limit = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        true,
        true,
        102_000,
    );
    let res = evaluate_tax_safety(&intent, Some(&obs_skew_limit), 100_000, &policy)
        .expect("exact future skew limit should be fresh");
    assert_eq!(res.freshness().age_ms, 0);
    assert_eq!(res.freshness().status, FreshnessStatus::Fresh);
}

#[test]
fn test_excessive_future_observation_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = FreshnessPolicy::new(10_000, 2_000).unwrap();

    // observed_at = 102_001, evaluation_time = 100_000 => future skew = 2_001 > max_skew 2_000
    let obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        true,
        true,
        102_001,
    );
    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("excessive future skew must fail closed");

    assert_eq!(err, TaxSafetyError::ResyncRequired);
}

// =========================================================================
// 5. Each failure flag (buy_succeeds, sell_succeeds, sellable)
// =========================================================================

#[test]
fn test_failure_flag_buy_succeeds_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = sample_policy();

    // buy_succeeds = false
    let obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        false,
        true,
        true,
        100_000,
    );
    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("buy_succeeds = false must fail closed");
    assert_eq!(err, TaxSafetyError::BuySimulationFailed);
}

#[test]
fn test_failure_flag_sellable_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = sample_policy();

    // sellable = false (sell_succeeds must be false to pass TaxObservation::validate coherent sellability)
    let obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        false,
        false,
        100_000,
    );
    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("sellable = false must fail closed");
    assert_eq!(err, TaxSafetyError::TokenNotSellable);
}

#[test]
fn test_failure_flag_sell_succeeds_fails_closed() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let policy = sample_policy();

    // sell_succeeds = false, sellable = true
    let obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        false,
        true,
        100_000,
    );
    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("sell_succeeds = false must fail closed");
    assert_eq!(err, TaxSafetyError::SellSimulationFailed);
}

// =========================================================================
// 6. Separate buy-tax and sell-tax cap rejection
// =========================================================================

#[test]
fn test_separate_buy_tax_cap_rejection() {
    let policy = sample_policy();

    // Buy intent: buy_tax exceeds cap (501 > 500), sell_tax is within cap (300 <= 600)
    let buy_intent = sample_intent(TradeSide::Buy, 500, 600);
    let obs_buy_exceeds = sample_observation(
        buy_intent.token_out.clone(),
        501,
        300,
        true,
        true,
        true,
        100_000,
    );
    let err_buy = evaluate_tax_safety(&buy_intent, Some(&obs_buy_exceeds), 100_000, &policy)
        .expect_err("buy_tax > max_buy_tax must fail");
    assert_eq!(err_buy, TaxSafetyError::BuyTaxExceedsCap);

    // Sell intent: both caps must still be enforced!
    let sell_intent = sample_intent(TradeSide::Sell, 500, 600);
    let obs_sell_side_buy_exceeds = sample_observation(
        sell_intent.token_in.clone(),
        501,
        300,
        true,
        true,
        true,
        100_000,
    );
    let err_sell_intent = evaluate_tax_safety(
        &sell_intent,
        Some(&obs_sell_side_buy_exceeds),
        100_000,
        &policy,
    )
    .expect_err("buy_tax > max_buy_tax must fail on Sell intent too");
    assert_eq!(err_sell_intent, TaxSafetyError::BuyTaxExceedsCap);
}

#[test]
fn test_separate_sell_tax_cap_rejection() {
    let policy = sample_policy();

    // Buy intent: buy_tax is within cap (300 <= 500), sell_tax exceeds cap (601 > 600)
    let buy_intent = sample_intent(TradeSide::Buy, 500, 600);
    let obs_sell_exceeds = sample_observation(
        buy_intent.token_out.clone(),
        300,
        601,
        true,
        true,
        true,
        100_000,
    );
    let err_buy = evaluate_tax_safety(&buy_intent, Some(&obs_sell_exceeds), 100_000, &policy)
        .expect_err("sell_tax > max_sell_tax must fail on Buy intent");
    assert_eq!(err_buy, TaxSafetyError::SellTaxExceedsCap);

    // Sell intent: sell_tax exceeds cap (601 > 600)
    let sell_intent = sample_intent(TradeSide::Sell, 500, 600);
    let obs_sell_intent_sell_exceeds = sample_observation(
        sell_intent.token_in.clone(),
        300,
        601,
        true,
        true,
        true,
        100_000,
    );
    let err_sell = evaluate_tax_safety(
        &sell_intent,
        Some(&obs_sell_intent_sell_exceeds),
        100_000,
        &policy,
    )
    .expect_err("sell_tax > max_sell_tax must fail on Sell intent");
    assert_eq!(err_sell, TaxSafetyError::SellTaxExceedsCap);
}

// =========================================================================
// 7. Pure-input immutability/no partial mutation on every rejected case
// =========================================================================

#[test]
fn test_pure_input_immutability_on_every_rejected_case() {
    let policy = sample_policy();
    let base_intent = sample_intent(TradeSide::Buy, 500, 500);
    let base_obs = sample_observation(
        base_intent.token_out.clone(),
        300,
        300,
        true,
        true,
        true,
        100_000,
    );

    // List of negative scenarios
    struct NegativeCase {
        name: &'static str,
        intent: TradeIntent,
        observation: Option<TaxObservation>,
        eval_time_ms: i64,
    }

    let mut cases = Vec::new();

    // 1. Missing observation
    cases.push(NegativeCase {
        name: "missing observation",
        intent: base_intent.clone(),
        observation: None,
        eval_time_ms: 100_000,
    });

    // 2. Expired intent
    let mut expired_intent = base_intent.clone();
    expired_intent.expiry_ms = Some(90_000);
    cases.push(NegativeCase {
        name: "expired intent",
        intent: expired_intent,
        observation: Some(base_obs.clone()),
        eval_time_ms: 100_000,
    });

    // 3. Invalid observation (zero amount)
    let mut invalid_obs = base_obs.clone();
    invalid_obs.amount = AtomicAmount::new(0);
    cases.push(NegativeCase {
        name: "invalid observation with zero amount",
        intent: base_intent.clone(),
        observation: Some(invalid_obs),
        eval_time_ms: 100_000,
    });

    // 4. Chain mismatch
    let mut chain_mismatch_obs = sample_observation(
        AssetId::new(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        )
        .unwrap(),
        300,
        300,
        true,
        true,
        true,
        100_000,
    );
    chain_mismatch_obs.chain = ChainId::Solana;
    cases.push(NegativeCase {
        name: "chain mismatch",
        intent: base_intent.clone(),
        observation: Some(chain_mismatch_obs),
        eval_time_ms: 100_000,
    });

    // 5. Assessed token mismatch
    let mut token_mismatch_obs = base_obs.clone();
    token_mismatch_obs.token = base_intent.token_in.clone();
    cases.push(NegativeCase {
        name: "assessed token mismatch",
        intent: base_intent.clone(),
        observation: Some(token_mismatch_obs),
        eval_time_ms: 100_000,
    });

    // 6. Stale observation
    let mut stale_obs = base_obs.clone();
    stale_obs.observed_at_ms = 85_000; // age = 15_000 > max_staleness 10_000
    stale_obs.expires_at_ms = 150_000;
    cases.push(NegativeCase {
        name: "stale observation",
        intent: base_intent.clone(),
        observation: Some(stale_obs),
        eval_time_ms: 100_000,
    });

    // 7. Excessive future skew
    let mut future_obs = base_obs.clone();
    future_obs.observed_at_ms = 105_000; // skew = 5_000 > max_skew 2_000
    future_obs.expires_at_ms = 160_000;
    cases.push(NegativeCase {
        name: "excessive future skew",
        intent: base_intent.clone(),
        observation: Some(future_obs),
        eval_time_ms: 100_000,
    });

    // 8. buy_succeeds = false
    let mut buy_failed_obs = base_obs.clone();
    buy_failed_obs.buy_succeeds = false;
    cases.push(NegativeCase {
        name: "buy simulation failed",
        intent: base_intent.clone(),
        observation: Some(buy_failed_obs),
        eval_time_ms: 100_000,
    });

    // 9. sellable = false
    let mut unsellable_obs = base_obs.clone();
    unsellable_obs.sellable = false;
    unsellable_obs.sell_succeeds = false;
    cases.push(NegativeCase {
        name: "token not sellable",
        intent: base_intent.clone(),
        observation: Some(unsellable_obs),
        eval_time_ms: 100_000,
    });

    // 10. sell_succeeds = false
    let mut sell_failed_obs = base_obs.clone();
    sell_failed_obs.sell_succeeds = false;
    cases.push(NegativeCase {
        name: "sell simulation failed",
        intent: base_intent.clone(),
        observation: Some(sell_failed_obs),
        eval_time_ms: 100_000,
    });

    // 11. buy_tax exceeds cap
    let mut buy_cap_obs = base_obs.clone();
    buy_cap_obs.buy_tax = Bps::new(501).unwrap();
    cases.push(NegativeCase {
        name: "buy tax exceeds cap",
        intent: base_intent.clone(),
        observation: Some(buy_cap_obs),
        eval_time_ms: 100_000,
    });

    // 12. sell_tax exceeds cap
    let mut sell_cap_obs = base_obs.clone();
    sell_cap_obs.sell_tax = Bps::new(501).unwrap();
    cases.push(NegativeCase {
        name: "sell tax exceeds cap",
        intent: base_intent.clone(),
        observation: Some(sell_cap_obs),
        eval_time_ms: 100_000,
    });

    for case in &cases {
        let intent_before = case.intent.clone();
        let obs_before = case.observation.clone();

        let result = evaluate_tax_safety(
            &case.intent,
            case.observation.as_ref(),
            case.eval_time_ms,
            &policy,
        );

        assert!(
            result.is_err(),
            "case '{}' was expected to fail, but returned Ok",
            case.name
        );

        // Verify pure input immutability: inputs are 100% unchanged
        assert_eq!(
            case.intent, intent_before,
            "case '{}' mutated intent input",
            case.name
        );
        assert_eq!(
            case.observation, obs_before,
            "case '{}' mutated observation input",
            case.name
        );
    }
}

// =========================================================================
// 8. Non-secret error formatting & Serde safety
// =========================================================================

#[test]
fn test_no_secret_leakage_in_error_display_and_debug() {
    let errors = [
        TaxSafetyError::MissingObservation,
        TaxSafetyError::InvalidTradeIntent(DomainError::Expired),
        TaxSafetyError::InvalidTaxObservation(DomainError::ZeroTradeAmount),
        TaxSafetyError::ChainMismatch,
        TaxSafetyError::AssessedAssetMismatch,
        TaxSafetyError::FreshnessEvaluationFailed,
        TaxSafetyError::StaleObservation,
        TaxSafetyError::ResyncRequired,
        TaxSafetyError::BuySimulationFailed,
        TaxSafetyError::SellSimulationFailed,
        TaxSafetyError::TokenNotSellable,
        TaxSafetyError::BuyTaxExceedsCap,
        TaxSafetyError::SellTaxExceedsCap,
        TaxSafetyError::ZeroGrossOutput,
        TaxSafetyError::ZeroNetOutput,
    ];

    for err in &errors {
        let display_str = err.to_string();
        let debug_str = format!("{:?}", err);

        // Verify none of the output contains suspicious strings or secret indicators
        for text in [&display_str, &debug_str] {
            assert!(!text.contains("http://"), "leaked endpoint: {}", text);
            assert!(!text.contains("https://"), "leaked endpoint: {}", text);
            assert!(!text.contains("bearer"), "leaked token: {}", text);
            assert!(!text.contains("secret"), "leaked secret: {}", text);
            assert!(!text.contains("password"), "leaked password: {}", text);
            assert!(!text.contains("private_key"), "leaked key: {}", text);
        }
    }
}

#[test]
fn test_regression_redacted_mismatched_asset_ids() {
    let raw_in = "0x1111111111111111111111111111111111111111";
    let raw_out = "0x2222222222222222222222222222222222222222";
    let raw_observed = "0x9999999999999999999999999999999999999999";

    let mut intent = sample_intent(TradeSide::Buy, 500, 500);
    intent.token_in = sample_asset(raw_in);
    intent.token_out = sample_asset(raw_out);

    let mismatched_obs = sample_observation(
        sample_asset(raw_observed),
        300,
        300,
        true,
        true,
        true,
        100_000,
    );
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&mismatched_obs), 100_000, &policy)
        .expect_err("mismatched asset must fail closed");

    assert_eq!(err, TaxSafetyError::AssessedAssetMismatch);

    let display_str = err.to_string();
    let debug_str = format!("{:?}", err);

    assert_eq!(display_str, "assessed asset mismatch");
    assert_eq!(debug_str, "AssessedAssetMismatch");

    for s in [&display_str, &debug_str] {
        assert!(!s.contains(raw_out), "leaked expected asset id: {}", s);
        assert!(!s.contains(raw_observed), "leaked observed asset id: {}", s);
        assert!(!s.contains("0x2222"), "leaked asset address snippet: {}", s);
        assert!(!s.contains("0x9999"), "leaked asset address snippet: {}", s);
        assert!(!s.contains("22222222"), "leaked address hex: {}", s);
        assert!(!s.contains("99999999"), "leaked address hex: {}", s);
    }
}

#[test]
fn test_regression_redacted_chain_mismatch() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let mut obs = sample_observation(
        AssetId::new(
            ChainId::Solana,
            "So11111111111111111111111111111111111111112",
        )
        .unwrap(),
        300,
        300,
        true,
        true,
        true,
        100_000,
    );
    obs.chain = ChainId::Solana;
    let policy = sample_policy();

    let err = evaluate_tax_safety(&intent, Some(&obs), 100_000, &policy)
        .expect_err("chain mismatch must fail closed");

    assert_eq!(err, TaxSafetyError::ChainMismatch);

    let display_str = err.to_string();
    let debug_str = format!("{:?}", err);

    assert_eq!(display_str, "chain mismatch");
    assert_eq!(debug_str, "ChainMismatch");

    for s in [&display_str, &debug_str] {
        assert!(
            !s.contains("Solana"),
            "leaked chain observation data: {}",
            s
        );
        assert!(!s.contains("Base"), "leaked chain observation data: {}", s);
        assert!(!s.contains("So1111"), "leaked chain address data: {}", s);
    }
}

#[test]
fn test_regression_redacted_non_default_freshness_metadata() {
    let policy = FreshnessPolicy::new(10_000, 2_000).unwrap();
    let mut intent = sample_intent(TradeSide::Buy, 500, 500);
    intent.expiry_ms = None;

    // 1. Stale with distinctive non-default timestamps and sequence
    let distinct_observed_ms = 12345678;
    let distinct_eval_ms = 12399999; // age = 54321 > 10000
    let distinct_slot = 987654321;

    let mut stale_obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        true,
        true,
        distinct_observed_ms,
    );
    stale_obs.block_or_slot = distinct_slot;

    let err_stale = evaluate_tax_safety(&intent, Some(&stale_obs), distinct_eval_ms, &policy)
        .expect_err("stale observation must fail closed");

    assert_eq!(err_stale, TaxSafetyError::StaleObservation);

    let stale_display = err_stale.to_string();
    let stale_debug = format!("{:?}", err_stale);

    assert_eq!(stale_display, "tax observation is stale");
    assert_eq!(stale_debug, "StaleObservation");

    for s in [&stale_display, &stale_debug] {
        assert!(
            !s.contains("12345678"),
            "leaked observed_at timestamp: {}",
            s
        );
        assert!(
            !s.contains("12399999"),
            "leaked evaluation timestamp: {}",
            s
        );
        assert!(!s.contains("987654321"), "leaked slot sequence: {}", s);
        assert!(!s.contains("54321"), "leaked calculated age: {}", s);
    }

    // 2. Future skew with distinctive non-default timestamps and sequence
    let distinct_future_obs_ms = 87654321;
    let distinct_future_eval_ms = 87600000; // future skew = 54321 > 2000
    let distinct_future_slot = 123987456;

    let mut future_obs = sample_observation(
        intent.token_out.clone(),
        300,
        300,
        true,
        true,
        true,
        distinct_future_obs_ms,
    );
    future_obs.block_or_slot = distinct_future_slot;

    let err_resync =
        evaluate_tax_safety(&intent, Some(&future_obs), distinct_future_eval_ms, &policy)
            .expect_err("future skew must fail closed");

    assert_eq!(err_resync, TaxSafetyError::ResyncRequired);

    let resync_display = err_resync.to_string();
    let resync_debug = format!("{:?}", err_resync);

    assert_eq!(
        resync_display,
        "tax observation requires resync or clock skew exceeded policy limit"
    );
    assert_eq!(resync_debug, "ResyncRequired");

    for s in [&resync_display, &resync_debug] {
        assert!(
            !s.contains("87654321"),
            "leaked observed_at timestamp: {}",
            s
        );
        assert!(
            !s.contains("87600000"),
            "leaked evaluation timestamp: {}",
            s
        );
        assert!(!s.contains("123987456"), "leaked slot sequence: {}", s);
        assert!(!s.contains("54321"), "leaked calculated skew: {}", s);
    }

    // 3. FreshnessEvaluationFailed error variant has no wrapped value-bearing payloads
    let err_eval_failed = TaxSafetyError::FreshnessEvaluationFailed;
    assert_eq!(err_eval_failed.to_string(), "freshness evaluation failed");
    assert_eq!(
        format!("{:?}", err_eval_failed),
        "FreshnessEvaluationFailed"
    );
}

#[test]
fn test_regression_redacted_distinct_tax_caps() {
    let policy = sample_policy();

    // Distinct cap numbers: 345 bps max buy, 678 bps max sell
    let intent = sample_intent(TradeSide::Buy, 345, 678);

    // 1. Buy tax cap exceeded: observed 456 bps vs 345 bps cap
    let obs_buy = sample_observation(
        intent.token_out.clone(),
        456,
        100,
        true,
        true,
        true,
        100_000,
    );
    let err_buy = evaluate_tax_safety(&intent, Some(&obs_buy), 100_000, &policy)
        .expect_err("buy tax > max_buy_tax must fail");

    assert_eq!(err_buy, TaxSafetyError::BuyTaxExceedsCap);

    let buy_display = err_buy.to_string();
    let buy_debug = format!("{:?}", err_buy);

    assert_eq!(buy_display, "buy tax exceeds maximum allowed cap");
    assert_eq!(buy_debug, "BuyTaxExceedsCap");

    for s in [&buy_display, &buy_debug] {
        assert!(!s.contains("345"), "leaked max buy tax cap: {}", s);
        assert!(!s.contains("456"), "leaked observed buy tax: {}", s);
    }

    // 2. Sell tax cap exceeded: observed 890 bps vs 678 bps cap
    let obs_sell = sample_observation(
        intent.token_out.clone(),
        100,
        890,
        true,
        true,
        true,
        100_000,
    );
    let err_sell = evaluate_tax_safety(&intent, Some(&obs_sell), 100_000, &policy)
        .expect_err("sell tax > max_sell_tax must fail");

    assert_eq!(err_sell, TaxSafetyError::SellTaxExceedsCap);

    let sell_display = err_sell.to_string();
    let sell_debug = format!("{:?}", err_sell);

    assert_eq!(sell_display, "sell tax exceeds maximum allowed cap");
    assert_eq!(sell_debug, "SellTaxExceedsCap");

    for s in [&sell_display, &sell_debug] {
        assert!(!s.contains("678"), "leaked max sell tax cap: {}", s);
        assert!(!s.contains("890"), "leaked observed sell tax: {}", s);
    }
}

#[test]
fn test_tax_assessment_serde_round_trip() {
    let intent = sample_intent(TradeSide::Buy, 500, 500);
    let obs = sample_observation(
        intent.token_out.clone(),
        250,
        350,
        true,
        true,
        true,
        100_000,
    );
    let policy = sample_policy();

    let assessment = evaluate_tax_safety(&intent, Some(&obs), 105_000, &policy).unwrap();

    let json = serde_json::to_string(&assessment).expect("should serialize to json");
    let deserialized: TaxAssessment =
        serde_json::from_str(&json).expect("should deserialize from json");

    assert_eq!(assessment, deserialized);
}
