//! P40 signing-request boundary tests.
//!
//! The pinned digest hexes below were derived from an independent Python
//! `hashlib` reference implementing the byte layout documented in
//! `privy::signing` (tag bytes, u32/u64/u128/i64 big-endian fields,
//! length-prefixed UTF-8, and the chain-tag / asset encoding).

use std::collections::HashSet;

use chain_types::{AssetId, ChainId};
use domain::{
    AmountType, ExecutionCostComponents, ExecutionPreview, IdempotencyKey, IntentId, LimitPrice,
    OrderType, RiskConstraints, RouteLeg, RoutePlan, TradeIntent, TradeSide, TradeSource, UserId,
    ValidatedExecutionPreview, WalletRef,
};
use market_types::{AssetAmount, AtomicAmount, Bps, Freshness, PriceRatio, Sequence};
use policy::{
    ApprovedExecution, PolicyContext, PolicyEngine, PolicyLimits, TradingGate, TurnoverSnapshot,
    UsdMicros,
};
use privy::{
    PayloadDigest, PreparedExecutionRef, PrivyError, PrivySigningBoundary, SigningRequest,
};

const NOW_MS: i64 = 1_000;

// --- Pinned canonical request digests (from the Python hashlib reference) ---
const HAPPY: &str = "24e63ee2d5ef7e29c141239e5290da72af0ae146bb8437948c481a2aacd8a297";
const S_NONCE: &str = "e228711463fd11a77e555f674f7ead7cfaf598d1d374adb804fa902acef73390";
const S_PAYLOAD: &str = "f82c53f305b9a1a55839559a5039c31cb671153cb0385adad3603247b2c5120f";
const S_POOL: &str = "5b74cc18ab1c26403d841c83724b67c5c011c1761329fb5a6f3c940114ee4091";
const S_ROUTE_OUT: &str = "d34cbf74ce3e2dc618bf91e0b870b6054384429b88752a81e766497f6d1d1a45";
const S_NO_EXPIRES: &str = "e43008dfd2bd25d2acd4bb7daad4138964dc2c354a67655e2f5f9bc74bc4636e";
const S_TOKEN: &str = "afc4000f4b529a8078371ddfcfe9dc73a5cfa34d8716ad8f2f3d169b1bea599c";
const S_AMOUNT: &str = "783726a0f667735be0ce49976f34497a80436265c93b09c8ad9bb35ab464768c";

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn limits() -> PolicyLimits {
    PolicyLimits {
        max_trade_usd: UsdMicros::new(1_000_000),
        max_hourly_turnover_usd: UsdMicros::new(10_000_000),
        max_daily_turnover_usd: UsdMicros::new(50_000_000),
        max_buy_tax: Bps::new(500).unwrap(),
        max_sell_tax: Bps::new(500).unwrap(),
        max_price_impact: Bps::new(300).unwrap(),
        max_slippage: Bps::new(200).unwrap(),
        allowed_chains: HashSet::from([ChainId::Base]),
        allowed_venues: HashSet::from(["uniswap".to_string()]),
    }
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(
        TradingGate::from_trusted_startup(Some("true")).unwrap(),
        limits(),
    )
    .unwrap()
}

fn context() -> PolicyContext {
    PolicyContext::from_trusted_backend_state(
        NOW_MS,
        UsdMicros::new(500_000),
        TurnoverSnapshot::from_trusted_backend_state(UsdMicros::new(0), UsdMicros::new(0)),
        Some("uniswap".to_string()),
    )
    .unwrap()
}

fn intent() -> TradeIntent {
    TradeIntent {
        id: IntentId::new("intent-1").unwrap(),
        source: TradeSource::Web,
        user_id: UserId::new("user-1").unwrap(),
        wallet_ref: WalletRef::new("wallet-1").unwrap(),
        chain: ChainId::Base,
        token_in: AssetId::new(ChainId::Base, "USDC").unwrap(),
        token_out: AssetId::new(ChainId::Base, "TOKEN").unwrap(),
        side: TradeSide::Buy,
        amount_type: AmountType::InputAssetAtomic,
        amount: AtomicAmount::new(1_000),
        order_type: OrderType::Market,
        limit_price: None,
        risk: RiskConstraints {
            max_buy_tax: Bps::new(100).unwrap(),
            max_sell_tax: Bps::new(100).unwrap(),
            max_price_impact: Bps::new(100).unwrap(),
            max_slippage: Bps::new(100).unwrap(),
            max_total_cost: None,
        },
        allow_partial_fill: true,
        expiry_ms: Some(10_000),
        nonce: 7,
        idempotency_key: IdempotencyKey::new("idem-1").unwrap(),
    }
}

fn route() -> RoutePlan {
    let token_in = AssetId::new(ChainId::Base, "USDC").unwrap();
    let token_out = AssetId::new(ChainId::Base, "TOKEN").unwrap();
    RoutePlan {
        legs: vec![RouteLeg {
            venue: "uniswap_v3".to_string(),
            pool_ref: "0xpool1".to_string(),
            token_in,
            token_out: token_out.clone(),
            amount_in: AtomicAmount::new(1_000),
            expected_amount_out: AtomicAmount::new(250),
        }],
        expected_net_output: AssetAmount {
            asset: token_out,
            amount: AtomicAmount::new(240),
        },
        state: Freshness {
            observed_at_ms: NOW_MS,
            chain_height: 100,
            sequence: Sequence(1),
        },
    }
}

fn approved(engine: &PolicyEngine, intent: &TradeIntent) -> ApprovedExecution {
    engine.authorize_trade(intent, &context()).unwrap()
}

fn prepared(intent: &TradeIntent) -> PreparedExecutionRef {
    PreparedExecutionRef::new(
        "prepared-1",
        intent.id.clone(),
        intent.idempotency_key.clone(),
    )
    .unwrap()
}

fn payload() -> PayloadDigest {
    PayloadDigest::from_bytes(std::array::from_fn(|i| i as u8))
}

fn build_preview(
    intent: &TradeIntent,
    route: &RoutePlan,
    net_in: u128,
    gross: u128,
    net: u128,
) -> ValidatedExecutionPreview {
    ExecutionPreview {
        intent_id: intent.id.clone(),
        chain: intent.chain.clone(),
        token_in: intent.token_in.clone(),
        token_out: intent.token_out.clone(),
        side: intent.side,
        simulated_net_input: AssetAmount {
            asset: intent.token_in.clone(),
            amount: AtomicAmount::new(net_in),
        },
        simulated_net_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(net),
        },
        gross_output: AssetAmount {
            asset: intent.token_out.clone(),
            amount: AtomicAmount::new(gross),
        },
        cost_components: ExecutionCostComponents::default(),
        local_state_freshness: market_types::FreshnessStatus::Fresh,
    }
    .validate(intent, route, NOW_MS)
    .unwrap()
}

fn bind_with(
    intent: &TradeIntent,
    route: &RoutePlan,
    preview: &ValidatedExecutionPreview,
    approved: &ApprovedExecution,
    prepared: &PreparedExecutionRef,
    payload: PayloadDigest,
    now_ms: i64,
) -> Result<SigningRequest, PrivyError> {
    let engine = engine();
    SigningRequest::bind(
        &engine, approved, prepared, intent, route, preview, payload, now_ms,
    )
}

fn bind_request(
    intent: &TradeIntent,
    route: &RoutePlan,
    payload: PayloadDigest,
    now_ms: i64,
) -> Result<SigningRequest, PrivyError> {
    let engine = engine();
    let approved = approved(&engine, intent);
    let prepared = prepared(intent);
    let preview = build_preview(intent, route, 1_000, 250, 240);
    SigningRequest::bind(
        &engine, &approved, &prepared, intent, route, &preview, payload, now_ms,
    )
}

fn digest_of(intent: &TradeIntent, route: &RoutePlan) -> String {
    let request = bind_request(intent, route, payload(), NOW_MS).unwrap();
    hex(request.request_digest().as_bytes())
}

#[test]
fn happy_path_binds_and_pins_request_digest() {
    let intent = intent();
    let route = route();
    let request = bind_request(&intent, &route, payload(), NOW_MS).unwrap();

    assert_eq!(hex(request.request_digest().as_bytes()), HAPPY);
    assert_eq!(digest_of(&intent, &route), HAPPY);
    assert_eq!(request.intent_id(), &intent.id);
    assert_eq!(request.idempotency_key(), &intent.idempotency_key);
    assert_eq!(request.wallet_ref(), &intent.wallet_ref);
    assert_eq!(request.chain(), &ChainId::Base);
    assert_eq!(request.nonce(), 7);
    assert_eq!(request.payload_digest(), &payload());
}

#[test]
fn sensitivity_vectors_change_request_digest_with_pinned_hexes() {
    let base_route = route();
    assert_eq!(digest_of(&intent(), &base_route), HAPPY);

    // nonce
    let mut nonce_intent = intent();
    nonce_intent.nonce = 8;
    assert_eq!(digest_of(&nonce_intent, &base_route), S_NONCE);

    // a single payload byte
    let mut payload_bytes = [0u8; 32];
    for (i, byte) in payload_bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    payload_bytes[31] = 0x20;
    let preview = build_preview(&intent(), &base_route, 1_000, 250, 240);
    let engine = engine();
    let base_intent = intent();
    let request = bind_with(
        &base_intent,
        &base_route,
        &preview,
        &approved(&engine, &base_intent),
        &prepared(&base_intent),
        PayloadDigest::from_bytes(payload_bytes),
        NOW_MS,
    )
    .unwrap();
    assert_eq!(hex(request.request_digest().as_bytes()), S_PAYLOAD);

    // route pool reference
    let mut pool_route = base_route.clone();
    pool_route.legs[0].pool_ref = "0xpool2".to_string();
    assert_eq!(digest_of(&intent(), &pool_route), S_POOL);

    // route expected leg output
    let mut out_route = base_route.clone();
    out_route.legs[0].expected_amount_out = AtomicAmount::new(251);
    assert_eq!(digest_of(&intent(), &out_route), S_ROUTE_OUT);

    // approval expiry presence
    let mut no_expiry = intent();
    no_expiry.expiry_ms = None;
    assert_eq!(digest_of(&no_expiry, &base_route), S_NO_EXPIRES);

    // a token address
    let mut token_intent = intent();
    token_intent.token_in = AssetId::new(ChainId::Base, "USDCX").unwrap();
    let mut token_route = base_route.clone();
    token_route.legs[0].token_in = token_intent.token_in.clone();
    assert_eq!(digest_of(&token_intent, &token_route), S_TOKEN);

    // an amount (gross output)
    let amount_intent = intent();
    let amount_preview = build_preview(&amount_intent, &base_route, 1_000, 251, 240);
    let request = bind_with(
        &amount_intent,
        &base_route,
        &amount_preview,
        &approved(&engine, &amount_intent),
        &prepared(&amount_intent),
        payload(),
        NOW_MS,
    )
    .unwrap();
    assert_eq!(hex(request.request_digest().as_bytes()), S_AMOUNT);
}

#[test]
fn disabled_gate_is_rejected() {
    let engine = engine();
    let intent = intent();
    let route = route();
    let approved = approved(&engine, &intent);
    let prepared = prepared(&intent);
    let preview = build_preview(&intent, &route, 1_000, 250, 240);
    engine.disable_trading();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &intent,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::TradingDisabled)
    );
}

#[test]
fn expired_approval_is_rejected() {
    let engine = engine();
    let original = intent();
    let route = route();
    let approved = approved(&engine, &original);
    let prepared = prepared(&original);
    let preview = build_preview(&original, &route, 1_000, 250, 240);
    // The domain validator would pre-empt with `Expired` if the intent itself had
    // expired, so use an expiry-neutral intent to exercise the approval check.
    let mut without_expiry = original.clone();
    without_expiry.expiry_ms = None;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &without_expiry,
            &route,
            &preview,
            payload(),
            10_000,
        ),
        Err(PrivyError::ApprovalExpired)
    );
}

#[test]
fn approval_binding_mismatches_are_rejected() {
    let engine = engine();
    let base = intent();
    let route = route();
    let approved = approved(&engine, &base);
    let prepared = prepared(&base);
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    let mut wrong_id = base.clone();
    wrong_id.id = IntentId::new("other-intent").unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &wrong_id,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );

    let mut wrong_wallet = base.clone();
    wrong_wallet.wallet_ref = WalletRef::new("other-wallet").unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &wrong_wallet,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );

    let wrong_prepared = PreparedExecutionRef::new(
        "prepared-other",
        IntentId::new("other-intent").unwrap(),
        base.idempotency_key.clone(),
    )
    .unwrap();
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &wrong_prepared,
            &base,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::ApprovalBindingMismatch)
    );
}

#[test]
fn preview_revalidation_failures_are_rejected() {
    let engine = engine();
    let base = intent();
    let route = route();
    let approved = approved(&engine, &base);
    let prepared = prepared(&base);
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    // Preview side disagrees with the intent.
    let mut opposite_side = base.clone();
    opposite_side.side = TradeSide::Sell;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &opposite_side,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // Route economics no longer match the validated preview net output.
    let mut net_mismatch = route.clone();
    net_mismatch.expected_net_output.amount = AtomicAmount::new(241);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &base,
            &net_mismatch,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // Stale route state.
    let mut stale_route = route.clone();
    stale_route.state.observed_at_ms = 0;
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &base,
            &stale_route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // Expired intent (the approval expiry equals the intent expiry; the domain
    // validator is the first fail-closed check to fire).
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &approved,
            &prepared,
            &base,
            &route,
            &preview,
            payload(),
            10_000,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );
}

#[test]
fn limit_violation_and_all_or_nothing_mismatch_are_revalidation_failures() {
    let engine = engine();
    let base = intent();
    let route = route();
    let preview = build_preview(&base, &route, 1_000, 250, 240);

    // A limit the exact net economics violate (1000/240 > 4.0).
    let mut limited = base.clone();
    limited.order_type = OrderType::Limit;
    limited.limit_price = Some(LimitPrice {
        numerator_asset: base.token_in.clone(),
        denominator_asset: base.token_out.clone(),
        ratio: PriceRatio::new(400, 100).unwrap(),
    });
    let limited_approved = approved(&engine, &limited);
    let limited_prepared = prepared(&limited);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &limited_approved,
            &limited_prepared,
            &limited,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );

    // All-or-nothing intent whose amount does not match the simulated net input.
    let mut all_or_nothing = base.clone();
    all_or_nothing.allow_partial_fill = false;
    all_or_nothing.amount = AtomicAmount::new(2_000);
    let aon_approved = approved(&engine, &all_or_nothing);
    let aon_prepared = prepared(&all_or_nothing);
    assert_eq!(
        SigningRequest::bind(
            &engine,
            &aon_approved,
            &aon_prepared,
            &all_or_nothing,
            &route,
            &preview,
            payload(),
            NOW_MS,
        ),
        Err(PrivyError::PreviewRevalidationFailed)
    );
}

#[test]
fn zero_payload_digest_is_rejected() {
    assert_eq!(
        bind_request(
            &intent(),
            &route(),
            PayloadDigest::from_bytes([0u8; 32]),
            NOW_MS
        ),
        Err(PrivyError::MissingPayloadDigest)
    );
}

#[tokio::test]
async fn default_boundary_fails_closed() {
    let boundary = PrivySigningBoundary::default();
    let request = bind_request(&intent(), &route(), payload(), NOW_MS).unwrap();
    assert_eq!(
        boundary.submit_signing_request(&request).await,
        Err(PrivyError::SigningUnavailable)
    );
}

#[test]
fn errors_and_digests_reveal_no_digits() {
    let errors = [
        PrivyError::SigningUnavailable,
        PrivyError::InvalidExecutionReference,
        PrivyError::ApprovalBindingMismatch,
        PrivyError::ApprovalExpired,
        PrivyError::TradingDisabled,
        PrivyError::PreviewRevalidationFailed,
        PrivyError::MissingPayloadDigest,
        PrivyError::DuplicateSigningRequest,
        PrivyError::IdempotencyConflict,
        PrivyError::SignerRejected,
    ];
    for error in errors {
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(
                !rendered.chars().any(|c| c.is_ascii_digit()),
                "redaction leak in `{rendered}`"
            );
        }
    }

    let payload = payload();
    assert!(!format!("{payload:?}").chars().any(|c| c.is_ascii_digit()));

    let request = bind_request(&intent(), &route(), payload, NOW_MS).unwrap();
    assert!(!format!("{:?}", request.request_digest())
        .chars()
        .any(|c| c.is_ascii_digit()));
    assert!(!format!("{request:?}").chars().any(|c| c.is_ascii_digit()));
}
