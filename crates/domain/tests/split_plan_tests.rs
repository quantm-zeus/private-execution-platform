//! P77 domain split-plan contract tests.
//!
//! Deterministic fixtures only: no clock, RPC, or randomness.

use chain_types::{AssetId, ChainId};
use domain::{
    validate_split_execution_preview, AmountType, DomainError, ExecutionCostComponents,
    ExecutionPreview, IdempotencyKey, IntentId, OrderType, RiskConstraints, RouteLeg, RoutePlan,
    SplitLeg, SplitPlan, TradeIntent, TradeSide, TradeSource, UserId, WalletRef, MAX_SPLIT_LEGS,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, FreshnessStatus, Sequence};

const NOW_MS: i64 = 1_000_000;

fn asset(address: &str) -> AssetId {
    AssetId::new(ChainId::Base, address).expect("valid asset")
}
fn usdc() -> AssetId {
    asset("0xusdc")
}
fn token() -> AssetId {
    asset("0xtoken")
}
fn other() -> AssetId {
    asset("0xother")
}

fn risk() -> RiskConstraints {
    RiskConstraints {
        max_buy_tax: Bps::new(500).expect("bps"),
        max_sell_tax: Bps::new(500).expect("bps"),
        max_price_impact: Bps::new(300).expect("bps"),
        max_slippage: Bps::new(200).expect("bps"),
        max_total_cost: None,
    }
}

fn intent_with(side: TradeSide, amount: u128, allow_partial_fill: bool) -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").expect("id"),
        source: TradeSource::Internal,
        user_id: UserId::new("user-1").expect("user"),
        wallet_ref: WalletRef::new("wallet-1").expect("wallet"),
        chain: ChainId::Base,
        token_in: usdc(),
        token_out: token(),
        side,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(amount),
        order_type: OrderType::Market,
        limit_price: None,
        risk: risk(),
        allow_partial_fill,
        expiry_ms: None,
        nonce: 1,
        idempotency_key: IdempotencyKey::new("idem-1").expect("idem"),
    }
}

fn buy_intent() -> TradeIntent {
    intent_with(TradeSide::Buy, 1_000, true)
}

fn route(
    pool: &str,
    token_out: AssetId,
    amount_in: u128,
    out: u128,
    observed: i64,
    seq: u64,
) -> RoutePlan {
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap".to_string(),
            pool_ref: pool.to_string(),
            token_in: usdc(),
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(amount_in),
            expected_amount_out: AtomicAmount::new(out),
        }],
        expected_net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(out),
        },
        state: Freshness {
            observed_at_ms: observed,
            chain_height: 0,
            sequence: Sequence(seq),
        },
    }
}

fn split_two() -> SplitPlan {
    SplitPlan {
        legs: vec![
            SplitLeg {
                amount_in: AtomicAmount::new(600),
                route: route("0xpoolA", token(), 600, 300, NOW_MS, 1),
            },
            SplitLeg {
                amount_in: AtomicAmount::new(400),
                route: route("0xpoolB", token(), 400, 210, NOW_MS - 100, 2),
            },
        ],
        expected_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(510),
        },
        state: Freshness {
            observed_at_ms: NOW_MS - 100,
            chain_height: 0,
            sequence: Sequence(1),
        },
    }
}

fn aggregate_preview(
    intent: &TradeIntent,
    net_input: u128,
    gross: u128,
    net_out: u128,
) -> ExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: intent.chain.clone(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: intent.side,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(net_input),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(net_out),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(gross),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: FreshnessStatus::Fresh,
    }
}

#[test]
fn split_single_leg_degenerates_to_route() {
    let intent = buy_intent();
    let single = route("0xpoolA", token(), 1_000, 240, NOW_MS, 1);
    let split = SplitPlan {
        legs: vec![SplitLeg {
            amount_in: AtomicAmount::new(1_000),
            route: single.clone(),
        }],
        expected_net_output: single.expected_net_output.clone(),
        state: single.state,
    };
    let preview = aggregate_preview(&intent, 1_000, 250, 240);
    assert!(preview.validate(&intent, &single, NOW_MS).is_ok());
    assert!(validate_split_execution_preview(&intent, &split, &preview, NOW_MS).is_ok());
}

#[test]
fn split_parallel_legs_validate() {
    let intent = buy_intent();
    let split = split_two();
    let preview = aggregate_preview(&intent, 1_000, 520, 510);
    assert!(validate_split_execution_preview(&intent, &split, &preview, NOW_MS).is_ok());
}

#[test]
fn split_zero_and_six_legs_rejected() {
    let intent = buy_intent();
    let empty = SplitPlan {
        legs: vec![],
        expected_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(1),
        },
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    };
    assert_eq!(empty.validate(&intent), Err(DomainError::EmptySplitPlan));

    let base = split_two();
    let mut six = base.clone();
    for index in 0..4 {
        let mut leg = base.legs[index % 2].clone();
        leg.amount_in = AtomicAmount::new(100 + index as u128);
        six.legs.push(leg);
    }
    assert_eq!(six.legs.len(), 6);
    assert_eq!(
        six.validate(&intent),
        Err(DomainError::SplitLegCountExceeded)
    );
    assert_eq!(MAX_SPLIT_LEGS, 5);
}

#[test]
fn split_output_sum_mismatch_rejected() {
    let intent = buy_intent();
    let mut split = split_two();
    split.expected_net_output.amount = AtomicAmount::new(511);
    assert_eq!(
        split.validate(&intent),
        Err(DomainError::SplitOutputConservationViolated)
    );
}

#[test]
fn split_pair_mismatch_rejected() {
    let intent = buy_intent();
    let mut split = split_two();
    split.legs[1].route = route("0xpoolB", other(), 400, 210, NOW_MS - 100, 2);
    assert_eq!(
        split.validate(&intent),
        Err(DomainError::SplitLegTokenMismatch)
    );
}

#[test]
fn split_state_mismatch_rejected() {
    let intent = buy_intent();
    let mut split = split_two();
    split.state.observed_at_ms = NOW_MS;
    assert_eq!(
        split.validate(&intent),
        Err(DomainError::SplitStateMismatch)
    );
}

#[test]
fn split_leg_funding_over_budget_rejected() {
    let intent = buy_intent();
    let mut split = split_two();
    split.legs[0].route.legs[0].amount_in = AtomicAmount::new(700);
    assert_eq!(
        split.validate(&intent),
        Err(DomainError::SplitLegUnmodeledFunding)
    );
}

#[test]
fn split_input_conservation_is_bound_to_preview() {
    let intent = buy_intent();
    let split = split_two();
    let preview = aggregate_preview(&intent, 999, 520, 510);
    assert_eq!(
        validate_split_execution_preview(&intent, &split, &preview, NOW_MS),
        Err(DomainError::SplitInputConservationViolated)
    );
}

#[test]
fn split_output_conservation_is_bound_to_preview() {
    let intent = buy_intent();
    let split = split_two();
    let preview = aggregate_preview(&intent, 1_000, 520, 509);
    assert_eq!(
        validate_split_execution_preview(&intent, &split, &preview, NOW_MS),
        Err(DomainError::SplitOutputConservationViolated)
    );
}

#[test]
fn validate_split_reuses_intent_risk_and_amount() {
    // max_total_cost parity with the locked single-route validator.
    let mut intent = buy_intent();
    intent.risk.max_total_cost = Some(AssetAmount {
        asset: usdc(),
        amount: AtomicAmount::new(500),
    });
    let split = split_two();
    let preview = aggregate_preview(&intent, 1_000, 520, 510);
    let single = route("0xpoolA", token(), 1_000, 240, NOW_MS, 1);
    let single_preview = aggregate_preview(&intent, 1_000, 250, 240);
    let single_err = single_preview.validate(&intent, &single, NOW_MS);
    let split_err = validate_split_execution_preview(&intent, &split, &preview, NOW_MS);
    assert_eq!(single_err, split_err);
    assert!(matches!(
        split_err,
        Err(DomainError::InconsistentNetEconomics(_))
    ));

    // all-or-nothing partial-input parity.
    let intent = intent_with(TradeSide::Buy, 1_000, false);
    let partial = SplitPlan {
        legs: vec![
            SplitLeg {
                amount_in: AtomicAmount::new(500),
                route: route("0xpoolA", token(), 500, 260, NOW_MS, 1),
            },
            SplitLeg {
                amount_in: AtomicAmount::new(400),
                route: route("0xpoolB", token(), 400, 200, NOW_MS, 1),
            },
        ],
        expected_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(460),
        },
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    };
    let preview = aggregate_preview(&intent, 900, 460, 460);
    assert_eq!(
        validate_split_execution_preview(&intent, &partial, &preview, NOW_MS),
        Err(DomainError::InconsistentNetEconomics(
            "all-or-nothing intent cannot accept partial simulated input"
        ))
    );
}

#[test]
fn split_multihop_funding_rejected() {
    let intent = buy_intent();
    let branch = SplitLeg {
        amount_in: AtomicAmount::new(600),
        route: RoutePlan {
            legs: vec![
                RouteLeg {
                    venue: "uniswap".to_string(),
                    pool_ref: "0xhop1".to_string(),
                    token_in: usdc(),
                    token_out: other(),
                    amount_in: AtomicAmount::new(600),
                    expected_amount_out: AtomicAmount::new(100),
                },
                RouteLeg {
                    venue: "uniswap".to_string(),
                    pool_ref: "0xhop2".to_string(),
                    token_in: other(),
                    token_out: token(),
                    amount_in: AtomicAmount::new(200),
                    expected_amount_out: AtomicAmount::new(50),
                },
            ],
            expected_net_output: AssetAmount {
                asset: token(),
                amount: AtomicAmount::new(50),
            },
            state: Freshness {
                observed_at_ms: NOW_MS,
                chain_height: 0,
                sequence: Sequence(1),
            },
        },
    };
    let split = SplitPlan {
        legs: vec![branch],
        expected_net_output: AssetAmount {
            asset: token(),
            amount: AtomicAmount::new(50),
        },
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 0,
            sequence: Sequence(1),
        },
    };
    // The second hop needs 200 but the first hop only yields 100.
    assert_eq!(
        split.validate(&intent),
        Err(DomainError::SplitLegUnmodeledFunding)
    );
}

#[test]
fn split_pool_reuse_rejected() {
    let intent = buy_intent();
    let mut split = split_two();
    // Both branches would independently quote the same pool state.
    split.legs[1].route.legs[0].pool_ref = "0xpoolA".to_string();
    assert_eq!(split.validate(&intent), Err(DomainError::SplitPoolReused));
}
